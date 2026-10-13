//! Daemon-wide health: whether the daemon can serve requests.

use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::watch;

use crate::store::Store;

/// How long a health check waits for the store probe.
pub const STORE_PROBE_DEADLINE: Duration = Duration::from_secs(2);

/// Why the daemon cannot serve.
#[derive(Debug, Clone, thiserror::Error)]
pub enum Unhealthy {
    #[error("store probe failed: {0}")]
    Store(Arc<io::Error>),
    #[error("store probe did not complete in time")]
    StoreTimeout,
    #[error("sandbox runtime has not completed recovery")]
    NotReady,
    #[error("sandbox runtime is shut down")]
    Shutdown,
    #[error("VM fork supervisor has exited")]
    ForkSupervisorDown,
}

type ProbeResult = Result<(), Arc<io::Error>>;
type Slot = Arc<Mutex<Option<watch::Receiver<Option<ProbeResult>>>>>;

/// Runs [`Store::probe`] on a dedicated thread, at most one at a time.
/// Concurrent callers share the probe in flight; each waits up to its own
/// deadline. A probe that outlives the deadline keeps running and is joined by
/// later callers until it finishes.
pub struct StoreProbe {
    slot: Slot,
    deadline: Duration,
    #[cfg(test)]
    started: std::sync::atomic::AtomicUsize,
    #[cfg(test)]
    joined: std::sync::atomic::AtomicUsize,
}

/// Owns a running probe's result channel. Dropping it empties the slot and
/// publishes the result in one critical section; a probe that never produced
/// a result (it panicked or never ran) publishes an error.
struct ProbeJob {
    slot: Slot,
    tx: watch::Sender<Option<ProbeResult>>,
    result: Option<ProbeResult>,
}

impl Drop for ProbeJob {
    fn drop(&mut self) {
        let result = self
            .result
            .take()
            .unwrap_or_else(|| Err(Arc::new(io::Error::other("store probe did not run"))));
        let mut slot = self.slot.lock().unwrap_or_else(|e| e.into_inner());
        *slot = None;
        self.tx.send_replace(Some(result));
    }
}

impl StoreProbe {
    pub fn new(deadline: Duration) -> Self {
        Self {
            slot: Arc::new(Mutex::new(None)),
            deadline,
            #[cfg(test)]
            started: Default::default(),
            #[cfg(test)]
            joined: Default::default(),
        }
    }

    /// Probes `store`, joining the probe in flight if there is one.
    pub async fn check(&self, store: &Arc<dyn Store>) -> Result<(), Unhealthy> {
        let (mut rx, job) = {
            let mut slot = self.slot.lock().unwrap_or_else(|e| e.into_inner());
            match slot.as_ref() {
                Some(rx) => (rx.clone(), None),
                None => {
                    let (tx, rx) = watch::channel(None);
                    *slot = Some(rx.clone());
                    let job = ProbeJob {
                        slot: self.slot.clone(),
                        tx,
                        result: None,
                    };
                    (rx, Some(job))
                }
            }
        };
        #[cfg(test)]
        {
            use std::sync::atomic::Ordering;
            if job.is_some() {
                self.started.fetch_add(1, Ordering::SeqCst);
            }
            self.joined.fetch_add(1, Ordering::SeqCst);
        }
        if let Some(job) = job {
            let store = store.clone();
            // On spawn failure the closure, and with it the job, is dropped,
            // which publishes an error.
            let _ = std::thread::Builder::new()
                .name("pp-store-probe".into())
                .spawn(move || {
                    let mut job = job;
                    job.result = Some(store.probe().map_err(Arc::new));
                });
        }

        match tokio::time::timeout(self.deadline, rx.wait_for(Option::is_some)).await {
            Err(_) => Err(Unhealthy::StoreTimeout),
            Ok(Err(_)) => Err(Unhealthy::Store(Arc::new(io::Error::other(
                "store probe did not run",
            )))),
            Ok(Ok(result)) => match result.as_ref() {
                Some(Ok(())) => Ok(()),
                Some(Err(e)) => Err(Unhealthy::Store(e.clone())),
                None => unreachable!("wait_for returned before a result was published"),
            },
        }
    }

    /// Number of probes started so far.
    #[cfg(test)]
    pub(crate) fn started(&self) -> usize {
        self.started.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Number of callers that have started or joined a probe so far.
    #[cfg(test)]
    pub(crate) fn joined(&self) -> usize {
        self.joined.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Blocks until no probe is in flight.
    #[cfg(test)]
    pub(crate) fn wait_idle(&self) {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while self.slot.lock().unwrap().is_some() {
            assert!(
                std::time::Instant::now() < deadline,
                "probe still in flight"
            );
            std::thread::sleep(Duration::from_millis(2));
        }
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use std::collections::VecDeque;
    use std::io;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Condvar, Mutex};

    use crate::store::{InMemoryStore, PersistedRecord, Store};
    use crate::types::SandboxId;

    /// A store whose `probe` blocks until opened and returns queued results
    /// (Ok once the queue is empty).
    #[derive(Default)]
    pub(crate) struct GateStore {
        inner: InMemoryStore,
        open: Mutex<bool>,
        opened: Condvar,
        runs: AtomicUsize,
        results: Mutex<VecDeque<io::Result<()>>>,
    }

    impl GateStore {
        pub(crate) fn open(&self) {
            *self.open.lock().unwrap() = true;
            self.opened.notify_all();
        }

        pub(crate) fn push_result(&self, result: io::Result<()>) {
            self.results.lock().unwrap().push_back(result);
        }

        /// Number of `probe` calls entered so far.
        pub(crate) fn runs(&self) -> usize {
            self.runs.load(Ordering::SeqCst)
        }

        /// Blocks until `probe` has been entered `n` times.
        pub(crate) fn wait_runs(&self, n: usize) {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            while self.runs() < n {
                assert!(std::time::Instant::now() < deadline, "probe not entered");
                std::thread::sleep(std::time::Duration::from_millis(2));
            }
        }
    }

    impl Store for GateStore {
        fn upsert(&self, record: &PersistedRecord) -> io::Result<()> {
            self.inner.upsert(record)
        }
        fn delete(&self, id: &SandboxId) -> io::Result<()> {
            self.inner.delete(id)
        }
        fn load_all(&self) -> io::Result<Vec<PersistedRecord>> {
            self.inner.load_all()
        }
        fn replace_all(&self, records: &[PersistedRecord]) -> io::Result<()> {
            self.inner.replace_all(records)
        }
        fn probe(&self) -> io::Result<()> {
            self.runs.fetch_add(1, Ordering::SeqCst);
            let mut open = self.open.lock().unwrap();
            while !*open {
                open = self.opened.wait(open).unwrap();
            }
            drop(open);
            self.results.lock().unwrap().pop_front().unwrap_or(Ok(()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::GateStore;
    use super::*;
    use std::time::Instant;

    const SHORT: Duration = Duration::from_millis(150);

    fn gated() -> (Arc<GateStore>, Arc<dyn Store>) {
        let gate = Arc::new(GateStore::default());
        let store: Arc<dyn Store> = gate.clone();
        (gate, store)
    }

    async fn wait_joined(probe: &StoreProbe, n: usize) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while probe.joined() < n {
            assert!(Instant::now() < deadline, "callers did not join");
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn overlapping_healthy_calls_share_one_probe() {
        let (gate, store) = gated();
        let probe = Arc::new(StoreProbe::new(Duration::from_secs(5)));
        let calls: Vec<_> = (0..5)
            .map(|_| {
                let probe = probe.clone();
                let store = store.clone();
                tokio::spawn(async move { probe.check(&store).await })
            })
            .collect();
        wait_joined(&probe, 5).await;
        gate.open();
        for call in calls {
            call.await.unwrap().unwrap();
        }
        assert_eq!(gate.runs(), 1);
        assert_eq!(probe.started(), 1);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn hung_probe_is_joined_not_resubmitted() {
        let (gate, store) = gated();
        let probe = StoreProbe::new(SHORT);
        let (a, b) = tokio::join!(probe.check(&store), probe.check(&store));
        assert!(matches!(a, Err(Unhealthy::StoreTimeout)), "{a:?}");
        assert!(matches!(b, Err(Unhealthy::StoreTimeout)), "{b:?}");

        let late = probe.check(&store).await;
        assert!(matches!(late, Err(Unhealthy::StoreTimeout)), "{late:?}");
        assert_eq!(probe.started(), 1);

        gate.open();
        probe.wait_idle();
        assert_eq!(gate.runs(), 1);
        assert_eq!(probe.started(), 1);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn completed_probe_is_not_reused() {
        let (gate, store) = gated();
        gate.push_result(Err(io::Error::other("first probe fails")));
        let probe = StoreProbe::new(SHORT);
        let first = probe.check(&store).await;
        assert!(matches!(first, Err(Unhealthy::StoreTimeout)), "{first:?}");

        gate.open();
        probe.wait_idle();
        assert_eq!(gate.runs(), 1);

        probe.check(&store).await.unwrap();
        assert_eq!(gate.runs(), 2);
        assert_eq!(probe.started(), 2);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn probe_failure_is_reported() {
        let (gate, store) = gated();
        gate.push_result(Err(io::Error::other("disk on fire")));
        gate.open();
        let probe = StoreProbe::new(Duration::from_secs(5));
        let err = probe.check(&store).await.unwrap_err();
        assert_eq!(err.to_string(), "store probe failed: disk on fire");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn panicking_probe_reports_failure_and_frees_slot() {
        struct PanicStore;
        impl Store for PanicStore {
            fn upsert(&self, _: &crate::store::PersistedRecord) -> io::Result<()> {
                unreachable!()
            }
            fn delete(&self, _: &crate::types::SandboxId) -> io::Result<()> {
                unreachable!()
            }
            fn load_all(&self) -> io::Result<Vec<crate::store::PersistedRecord>> {
                unreachable!()
            }
            fn replace_all(&self, _: &[crate::store::PersistedRecord]) -> io::Result<()> {
                unreachable!()
            }
            fn probe(&self) -> io::Result<()> {
                panic!("probe panicked");
            }
        }
        let store: Arc<dyn Store> = Arc::new(PanicStore);
        let probe = StoreProbe::new(Duration::from_secs(5));
        let err = probe.check(&store).await.unwrap_err();
        assert_eq!(
            err.to_string(),
            "store probe failed: store probe did not run"
        );
        probe.wait_idle();
        assert_eq!(probe.started(), 1);
    }

    #[test]
    fn hung_probe_does_not_block_teardown() {
        let (gate, store) = gated();
        let probe = StoreProbe::new(SHORT);
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        let result = rt.block_on(probe.check(&store));
        assert!(matches!(result, Err(Unhealthy::StoreTimeout)), "{result:?}");

        let start = Instant::now();
        drop(rt);
        assert!(
            start.elapsed() < Duration::from_secs(1),
            "runtime teardown waited {:?}",
            start.elapsed()
        );
        assert_eq!(gate.runs(), 1);
        gate.open();
        probe.wait_idle();
    }
}
