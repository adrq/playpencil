use serde::{Deserialize, Serialize};

/// Committed lifecycle state. The persisted field is `Option<State>`, where
/// `None` is genesis (the sandbox exists but has not yet settled).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum State {
    Stopped,
    Running,
    Failed,
    Destroyed,
}

/// Caller intent. Always `Some` in the persisted record.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DesiredState {
    Stopped,
    Running,
    Destroyed,
}

/// Why a sandbox entered `Failed`.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureReason {
    ProvisionFailed,
    StartFailed,
    Crashed,
    DestroyFailed,
}

/// A caller-issued lifecycle verb.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Verb {
    Start,
    Stop,
    Destroy,
}

/// The single driver action the reconciler should take this tick. `Settled`
/// means no driver work is needed (the sandbox already satisfies its intent;
/// the loop only needs to mark convergence).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ReconcileAction {
    Provision,
    Start,
    Stop,
    Teardown,
    Settled,
}

/// Pure transition function. A latched failure (`Failed` with
/// `observed_generation == generation`) never auto-retries — only a fresh verb,
/// which bumps `generation`, reopens it. `rootfs_present` selects the right
/// failure-retry action without a driver round-trip.
pub fn next_action(
    state: Option<State>,
    desired: DesiredState,
    reason: Option<FailureReason>,
    rootfs_present: bool,
    generation: u64,
    observed_generation: u64,
) -> ReconcileAction {
    use DesiredState as D;
    use FailureReason as F;
    use ReconcileAction as A;
    use State as S;

    if state == Some(S::Failed) && observed_generation == generation {
        return A::Settled;
    }

    match (state, desired) {
        // Genesis.
        (None, D::Destroyed) => A::Teardown,
        (None, _) => A::Provision,

        // Failed, reopened by a fresh verb.
        (Some(S::Failed), D::Destroyed) => A::Teardown,
        (Some(S::Failed), D::Running) => match reason {
            Some(F::ProvisionFailed) if !rootfs_present => A::Provision,
            Some(F::StartFailed | F::Crashed) if !rootfs_present => A::Provision,
            Some(F::ProvisionFailed | F::StartFailed | F::Crashed) => A::Start,
            _ => A::Settled,
        },
        (Some(S::Failed), D::Stopped) => A::Settled,

        // Stopped.
        (Some(S::Stopped), D::Stopped) => A::Settled,
        (Some(S::Stopped), D::Running) => A::Start,
        (Some(S::Stopped), D::Destroyed) => A::Teardown,

        // Running.
        (Some(S::Running), D::Running) => A::Settled,
        (Some(S::Running), D::Stopped) => A::Stop,
        (Some(S::Running), D::Destroyed) => A::Teardown,

        // Destroyed (terminal).
        (Some(S::Destroyed), _) => A::Settled,
    }
}

/// Pure verb precondition.
/// - `destroy`: any non-terminal state.
/// - `start`: any non-terminal state except one already being destroyed.
/// - `stop`: any non-terminal state except `Failed` and except being destroyed.
pub fn precondition_ok(
    state: Option<State>,
    desired: DesiredState,
    _reason: Option<FailureReason>,
    verb: Verb,
) -> bool {
    let terminal = state == Some(State::Destroyed);
    let being_destroyed = desired == DesiredState::Destroyed;
    match verb {
        Verb::Destroy => !terminal,
        Verb::Start => !terminal && !being_destroyed,
        Verb::Stop => !terminal && !being_destroyed && state != Some(State::Failed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use DesiredState as D;
    use FailureReason as F;
    use ReconcileAction as A;
    use State as S;

    #[test]
    fn latched_failure_is_settled_for_every_reason() {
        for reason in [
            F::ProvisionFailed,
            F::StartFailed,
            F::Crashed,
            F::DestroyFailed,
        ] {
            for desired in [D::Stopped, D::Running, D::Destroyed] {
                assert_eq!(
                    next_action(Some(S::Failed), desired, Some(reason), true, 2, 2),
                    A::Settled,
                    "latched {reason:?} with desired {desired:?} must settle"
                );
            }
        }
    }

    #[test]
    fn genesis_walks_through_provision() {
        assert_eq!(
            next_action(None, D::Stopped, None, false, 1, 0),
            A::Provision
        );
        assert_eq!(
            next_action(None, D::Running, None, false, 1, 0),
            A::Provision
        );
        assert_eq!(
            next_action(None, D::Destroyed, None, false, 1, 0),
            A::Teardown
        );
    }

    #[test]
    fn stopped_and_running_dispatch() {
        assert_eq!(
            next_action(Some(S::Stopped), D::Stopped, None, true, 1, 0),
            A::Settled
        );
        assert_eq!(
            next_action(Some(S::Stopped), D::Running, None, true, 2, 1),
            A::Start
        );
        assert_eq!(
            next_action(Some(S::Stopped), D::Destroyed, None, true, 2, 1),
            A::Teardown
        );
        assert_eq!(
            next_action(Some(S::Running), D::Running, None, true, 1, 0),
            A::Settled
        );
        assert_eq!(
            next_action(Some(S::Running), D::Stopped, None, true, 2, 1),
            A::Stop
        );
        assert_eq!(
            next_action(Some(S::Running), D::Destroyed, None, true, 2, 1),
            A::Teardown
        );
        assert_eq!(
            next_action(Some(S::Destroyed), D::Destroyed, None, false, 1, 1),
            A::Settled
        );
    }

    #[test]
    fn failed_retry_subtable() {
        // reopened: observed < generation
        assert_eq!(
            next_action(
                Some(S::Failed),
                D::Running,
                Some(F::ProvisionFailed),
                false,
                2,
                1
            ),
            A::Provision
        );
        assert_eq!(
            next_action(
                Some(S::Failed),
                D::Running,
                Some(F::ProvisionFailed),
                true,
                2,
                1
            ),
            A::Start
        );
        assert_eq!(
            next_action(
                Some(S::Failed),
                D::Running,
                Some(F::StartFailed),
                true,
                2,
                1
            ),
            A::Start
        );
        assert_eq!(
            next_action(Some(S::Failed), D::Running, Some(F::Crashed), false, 2, 1),
            A::Provision
        );
        assert_eq!(
            next_action(
                Some(S::Failed),
                D::Destroyed,
                Some(F::DestroyFailed),
                true,
                2,
                1
            ),
            A::Teardown
        );
    }

    #[test]
    fn preconditions() {
        // destroy: any non-terminal
        assert!(precondition_ok(None, D::Stopped, None, Verb::Destroy));
        assert!(precondition_ok(
            Some(S::Running),
            D::Running,
            None,
            Verb::Destroy
        ));
        assert!(precondition_ok(
            Some(S::Failed),
            D::Destroyed,
            Some(F::DestroyFailed),
            Verb::Destroy
        ));
        assert!(!precondition_ok(
            Some(S::Destroyed),
            D::Destroyed,
            None,
            Verb::Destroy
        ));

        // start: rejected when terminal or being destroyed
        assert!(precondition_ok(
            Some(S::Stopped),
            D::Stopped,
            None,
            Verb::Start
        ));
        assert!(!precondition_ok(
            Some(S::Stopped),
            D::Destroyed,
            None,
            Verb::Start
        ));
        assert!(!precondition_ok(
            Some(S::Destroyed),
            D::Destroyed,
            None,
            Verb::Start
        ));

        // stop: rejected when Failed, terminal, or being destroyed
        assert!(precondition_ok(
            Some(S::Running),
            D::Running,
            None,
            Verb::Stop
        ));
        assert!(!precondition_ok(
            Some(S::Failed),
            D::Running,
            Some(F::Crashed),
            Verb::Stop
        ));
        assert!(!precondition_ok(
            Some(S::Running),
            D::Destroyed,
            None,
            Verb::Stop
        ));
        assert!(!precondition_ok(
            Some(S::Destroyed),
            D::Destroyed,
            None,
            Verb::Stop
        ));
    }
}
