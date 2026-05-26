use serde::{Deserialize, Serialize};
use std::fmt;

/// Sandbox lifecycle states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SandboxState {
    Creating,
    Ready,
    Running,
    Stopped,
    Destroyed,
}

impl SandboxState {
    /// Returns true if transitioning from self to target is valid.
    pub fn can_transition_to(&self, target: SandboxState) -> bool {
        matches!(
            (self, target),
            (Self::Creating, Self::Ready)
                | (Self::Creating, Self::Destroyed)
                | (Self::Ready, Self::Running)
                | (Self::Ready, Self::Destroyed)
                | (Self::Running, Self::Stopped)
                | (Self::Running, Self::Destroyed)
                | (Self::Stopped, Self::Running)
                | (Self::Stopped, Self::Destroyed)
        )
    }

    /// Attempt the transition. Returns Ok(target) on success,
    /// Err(self) if the transition is invalid.
    pub fn transition_to(self, target: SandboxState) -> Result<SandboxState, SandboxState> {
        if self.can_transition_to(target) {
            Ok(target)
        } else {
            Err(self)
        }
    }
}

impl fmt::Display for SandboxState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Creating => "creating",
            Self::Ready => "ready",
            Self::Running => "running",
            Self::Stopped => "stopped",
            Self::Destroyed => "destroyed",
        };
        f.write_str(s)
    }
}
