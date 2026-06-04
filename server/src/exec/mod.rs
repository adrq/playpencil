pub(crate) mod command;
pub(crate) mod decode;
pub(crate) mod duplex;

use std::time::Duration;

use playpencil_core::types::ExecCanceller;

// POSIX signal numbers (the server has no libc dependency).
pub(crate) const SIGTERM: i32 = 15;
pub(crate) const SIGKILL: i32 = 9;
/// Grace between TERM and KILL when escalating a cancellation.
pub(crate) const TERM_GRACE: Duration = Duration::from_secs(10);

/// Spawn the single TERM→grace→KILL escalation owner for one exec. Backend
/// cancellation is latched (the `cancel_phase` latch), so even if this races a
/// concurrent caller the process still receives at most one resume + one TERM +
/// one KILL. Callers must still coalesce to ONE escalation task per exec (via a
/// `cleanup_started`/`take_for_cleanup` win) so a stray grace timer is not left
/// running per disconnect.
pub(crate) fn spawn_escalation(canceller: ExecCanceller) {
    tokio::spawn(async move {
        canceller.cancel(SIGTERM);
        tokio::time::sleep(TERM_GRACE).await;
        canceller.cancel(SIGKILL);
    });
}
