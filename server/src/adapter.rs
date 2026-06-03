//! Translation between the wire protocol and the native backend types.

use serde::{Deserialize, Serialize};

use playpencil_core::lifecycle::{DesiredState, FailureReason, State};
use playpencil_core::types::{NetworkPolicy, SandboxView};

use crate::api_types::{SandboxResponse, StatusWire};

/// Project the native lifecycle fields onto the wire state string. Ordered
/// precedence — first match wins.
pub(crate) fn project_wire_state(
    state: Option<State>,
    desired: DesiredState,
    generation: u64,
    observed_generation: u64,
) -> &'static str {
    use DesiredState as D;
    use State as S;
    // Ordered precedence, first match wins. The in-flight rules (4, 5) are
    // STATE-BASED: they require the committed state to still differ from the
    // target. This is deliberate — the reconciler broadcasts state=Running before
    // do_start's converge() and state=Stopped before do_stop's converge(), so a
    // state-based projection reads those broadcasts as the terminal "Running" /
    // "Stopped" and the SSE stream observes convergence WITHOUT needing a
    // converge() broadcast. (A cursor-only in-flight rule would project "Pending"
    // on that terminal broadcast and the client would hang.)
    // The Failed-latch (observed == generation) is checked before the in-flight
    // rules so it is never masked; the desired=Destroyed rule wins over a stop or
    // a latched Failed.
    if state == Some(S::Destroyed) {
        return "Terminated";
    }
    if desired == D::Destroyed && observed_generation < generation {
        return "Stopping";
    }
    if state == Some(S::Failed) && observed_generation == generation {
        return "Failed";
    }
    if desired == D::Running && state != Some(S::Running) && observed_generation < generation {
        return "Pending";
    }
    // Native stop-in-flight: a stop was accepted (desired=Stopped) while the VM is
    // still Running and the reconciler has not yet converged. Lets a /v1x stop be
    // positively observable instead of reading steady Running until it flips.
    if desired == D::Stopped && state == Some(S::Running) && observed_generation < generation {
        return "Stopping";
    }
    match state {
        None => "Pending",
        Some(S::Stopped) => "Stopped",
        Some(S::Running) => "Running",
        Some(S::Failed) => "Failed",
        Some(S::Destroyed) => "Terminated",
    }
}

fn reason_str(reason: FailureReason) -> String {
    match reason {
        FailureReason::ProvisionFailed => "provision_failed",
        FailureReason::StartFailed => "start_failed",
        FailureReason::Crashed => "crashed",
        FailureReason::DestroyFailed => "destroy_failed",
    }
    .to_string()
}

/// Build the wire response from a status snapshot and its persisted config.
pub(crate) fn build_response(view: &SandboxView) -> SandboxResponse {
    let s = &view.status;
    let wire = project_wire_state(s.state, s.desired, s.generation, s.observed_generation);
    SandboxResponse {
        id: s.sandbox_id.0.clone(),
        status: StatusWire {
            state: wire.to_string(),
            reason: s.reason.map(reason_str),
            message: s.message.clone(),
            last_transition_at: s.last_transition_at.clone(),
        },
        created_at: s.created_at.clone(),
        image: Some(view.config.image.clone()),
        name: view.config.name.clone(),
        network: Some((&view.config.network).into()),
    }
}

// ---------------------------------------------------------------------------
// Network policy wire form
// ---------------------------------------------------------------------------

#[derive(Deserialize, Serialize, Clone)]
#[serde(untagged)]
pub(crate) enum NetworkPolicyWire {
    Allowlist { allowlist: AllowlistConfig },
    Simple(String),
}

#[derive(Deserialize, Serialize, Clone)]
pub(crate) struct AllowlistConfig {
    pub allowed_domains: Vec<String>,
}

impl TryFrom<NetworkPolicyWire> for NetworkPolicy {
    type Error = String;

    fn try_from(wire: NetworkPolicyWire) -> Result<Self, Self::Error> {
        match wire {
            NetworkPolicyWire::Simple(s) if s == "isolated" => Ok(NetworkPolicy::Isolated),
            NetworkPolicyWire::Simple(s) if s == "unrestricted" => Ok(NetworkPolicy::Unrestricted),
            NetworkPolicyWire::Simple(s) => Err(format!("unknown network policy: {s}")),
            NetworkPolicyWire::Allowlist { allowlist } => Ok(NetworkPolicy::Allowlist {
                allowed_domains: allowlist.allowed_domains,
            }),
        }
    }
}

impl From<&NetworkPolicy> for NetworkPolicyWire {
    fn from(np: &NetworkPolicy) -> Self {
        match np {
            NetworkPolicy::Isolated => NetworkPolicyWire::Simple("isolated".into()),
            NetworkPolicy::Unrestricted => NetworkPolicyWire::Simple("unrestricted".into()),
            NetworkPolicy::Allowlist { allowed_domains } => NetworkPolicyWire::Allowlist {
                allowlist: AllowlistConfig {
                    allowed_domains: allowed_domains.clone(),
                },
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_state_precedence() {
        // Terminated wins.
        assert_eq!(
            project_wire_state(Some(State::Destroyed), DesiredState::Destroyed, 2, 2),
            "Terminated"
        );
        // Being destroyed (in flight) -> Stopping, even from Failed.
        assert_eq!(
            project_wire_state(Some(State::Failed), DesiredState::Destroyed, 3, 2),
            "Stopping"
        );
        // Latched failure -> Failed.
        assert_eq!(
            project_wire_state(Some(State::Failed), DesiredState::Running, 2, 2),
            "Failed"
        );
        // Bring-up in progress -> Pending.
        assert_eq!(
            project_wire_state(Some(State::Stopped), DesiredState::Running, 2, 1),
            "Pending"
        );
        assert_eq!(
            project_wire_state(None, DesiredState::Running, 1, 0),
            "Pending"
        );
        // Settled states.
        assert_eq!(
            project_wire_state(Some(State::Stopped), DesiredState::Stopped, 1, 1),
            "Stopped"
        );
        assert_eq!(
            project_wire_state(Some(State::Running), DesiredState::Running, 1, 1),
            "Running"
        );
        // Native stop-in-flight (desired=Stopped, still Running, not yet
        // converged) now projects Stopping so the /v1x stop is observable.
        assert_eq!(
            project_wire_state(Some(State::Running), DesiredState::Stopped, 2, 1),
            "Stopping"
        );
        // Guard: the stop-in-flight rule requires observed < generation. A
        // converged (observed == generation) Running with desired=Stopped reads
        // Running, not Stopping (the stop rule must not shadow steady Running).
        assert_eq!(
            project_wire_state(Some(State::Running), DesiredState::Stopped, 1, 1),
            "Running"
        );
        // Guard: destroy-in-flight from Running still wins as Stopping via the
        // desired=Destroyed rule, unaffected by the stop rule.
        assert_eq!(
            project_wire_state(Some(State::Running), DesiredState::Destroyed, 2, 1),
            "Stopping"
        );
    }
}
