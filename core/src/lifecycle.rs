use serde::{Deserialize, Serialize};
use std::fmt;

/// Sandbox lifecycle states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SandboxState {
    Creating,
    Ready,
    /// Transient: start() has claimed the entry but has not yet forked the VM.
    /// Prevents a second concurrent start() from racing through the Ready/Stopped check.
    Starting,
    Running,
    /// Transient: stop() has started but kill_and_wait has not completed.
    /// Prevents a concurrent start() from seeing Stopped and launching a new VM
    /// while the old one is still alive.
    Stopping,
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
                | (Self::Ready, Self::Starting)
                | (Self::Ready, Self::Running) // kept for MockBackend
                | (Self::Ready, Self::Destroyed)
                | (Self::Starting, Self::Running)
                | (Self::Starting, Self::Ready) // rollback on start() failure from Ready
                | (Self::Starting, Self::Stopped) // rollback on start() failure from Stopped
                | (Self::Starting, Self::Destroyed)
                | (Self::Running, Self::Stopping)
                | (Self::Running, Self::Stopped) // kept for MockBackend
                | (Self::Running, Self::Destroyed)
                | (Self::Stopping, Self::Stopped)
                // Stopping → Destroyed is intentionally absent: destroy() must wait for
                // stop() to complete (rootfs may still be in use by the running VM).
                | (Self::Stopped, Self::Starting)
                | (Self::Stopped, Self::Running) // kept for MockBackend
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
            Self::Starting => "starting",
            Self::Running => "running",
            Self::Stopping => "stopping",
            Self::Stopped => "stopped",
            Self::Destroyed => "destroyed",
        };
        f.write_str(s)
    }
}
