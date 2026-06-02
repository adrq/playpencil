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
        // Native stop-in-flight still projects Running.
        assert_eq!(
            project_wire_state(Some(State::Running), DesiredState::Stopped, 2, 1),
            "Running"
        );
    }
}
