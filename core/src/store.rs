//! Durable, atomic, PID-reuse-safe persistence for sandbox records.

use std::collections::BTreeMap;
use std::collections::HashMap;
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use crate::lifecycle::{DesiredState, FailureReason, State};
use crate::types::{EntrypointExit, SandboxConfig, SandboxId, validate_entrypoint};

/// A single sandbox's durable record.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PersistedRecord {
    pub id: SandboxId,
    pub config: SandboxConfig,
    pub desired: DesiredState,
    pub generation: u64,
    /// `None` is genesis (the sandbox exists but has not yet settled).
    pub state: Option<State>,
    pub observed_generation: u64,
    pub pid: Option<i32>,
    /// `/proc/<pid>/stat` field 22 (clock ticks), captured at fork.
    pub pid_start_time: Option<u64>,
    /// Prepared rootfs root; its parent is the per-sandbox session dir.
    pub rootfs_path: Option<PathBuf>,
    pub reason: Option<FailureReason>,
    pub message: Option<String>,
    /// How the main process finished. Backend-internal; never reaches the status
    /// wire. Valid only on a crashed-failed record (see `validate_record`).
    #[serde(default)]
    pub entrypoint_exit: Option<EntrypointExit>,
    pub created_at: String,
    pub last_transition_at: String,
}

/// Persistence primitive. Implementations serialize sandbox records durably.
pub trait Store: Send + Sync {
    fn upsert(&self, record: &PersistedRecord) -> io::Result<()>;
    fn delete(&self, id: &SandboxId) -> io::Result<()>;
    /// Returns every persisted record. Missing backing store yields an empty
    /// list; a corrupt or invalid store is a hard error (fail loud).
    fn load_all(&self) -> io::Result<Vec<PersistedRecord>>;

    /// Atomically replace the ENTIRE set of persisted records in one durable
    /// commit. Validates every record first; on any invalid record nothing is
    /// written. Used by recovery to commit the whole normalized map at once so
    /// a mid-recovery failure leaves no partial durable write.
    fn replace_all(&self, records: &[PersistedRecord]) -> io::Result<()>;

    /// Checks that the store can be read and written now, without changing
    /// any record.
    fn probe(&self) -> io::Result<()>;
}

/// A single JSON file holding `id -> PersistedRecord`. Every write is a
/// whole-map atomic rewrite (temp -> fsync -> rename -> fsync dir). The internal
/// mutex serializes the rewrite across sandboxes so concurrent writers can't
/// clobber the shared file.
pub struct JsonStore {
    path: PathBuf,
    lock: Mutex<()>,
}

impl JsonStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            lock: Mutex::new(()),
        }
    }

    fn read_map(&self) -> io::Result<BTreeMap<String, PersistedRecord>> {
        match std::fs::read(&self.path) {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(io::Error::other),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(BTreeMap::new()),
            Err(e) => Err(e),
        }
    }

    /// A unique, per-write temp path in the state dir. A fresh name each write
    /// means an `O_EXCL` create can never reuse a stale or attacker-planted
    /// file (or follow a symlink) at a predictable temp path.
    fn unique_tmp_path(&self) -> PathBuf {
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let mut name = self
            .path
            .file_name()
            .map(|s| s.to_os_string())
            .unwrap_or_default();
        name.push(format!(".tmp.{}.{nanos}.{seq}", std::process::id()));
        self.path.with_file_name(name)
    }

    fn write_map(&self, map: &BTreeMap<String, PersistedRecord>) -> io::Result<()> {
        let json = serde_json::to_vec_pretty(map).map_err(io::Error::other)?;
        // Records embed SandboxConfig.env, which commonly holds credentials, so
        // the state file must never be readable by other local users. Ensure the
        // data dir exists as 0700 and is crash-durable before writing into it.
        if let Some(dir) = self.path.parent() {
            ensure_secure_dir(dir)?;
        }

        // Write to a fresh O_EXCL temp (never reuse/follow a stale temp or
        // symlink), fsync it, then atomically rename onto the state file. The
        // fresh create guarantees the 0600 mode actually applies.
        let tmp = self.unique_tmp_path();
        if let Err(e) = write_secret_file(&tmp, &json) {
            let _ = std::fs::remove_file(&tmp);
            return Err(e);
        }
        if let Err(e) = std::fs::rename(&tmp, &self.path) {
            let _ = std::fs::remove_file(&tmp);
            return Err(e);
        }
        // The rename is the commit point: state.json now holds the new bytes.
        // Fsync the parent directory to make that rename crash-durable. A
        // failure here is PAST the commit point (the new record is already the
        // on-disk state), so it must be reported as a committed-but-unsynced
        // durability degradation, never as a rollback-safe "the write did not
        // happen" error — otherwise a caller would roll back in memory while
        // disk holds the new record.
        self.sync_dir().map_err(committed_unsynced_error)
    }

    /// Fsyncs the directory holding the state file.
    fn sync_dir(&self) -> io::Result<()> {
        let Some(dir) = self.path.parent() else {
            return Ok(());
        };
        let dir = if dir.as_os_str().is_empty() {
            std::path::Path::new(".")
        } else {
            dir
        };
        std::fs::File::open(dir).and_then(|f| f.sync_all())
    }
}

/// The store COMMITTED a write (the atomic rename succeeded, so the new bytes
/// are already the on-disk state) but the follow-up directory fsync that makes
/// the rename crash-durable failed. Callers must treat the write as committed
/// and MUST NOT roll back in-memory state.
#[derive(Debug)]
struct CommittedUnsynced(io::Error);

impl std::fmt::Display for CommittedUnsynced {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "record committed but directory fsync failed: {}", self.0)
    }
}

impl std::error::Error for CommittedUnsynced {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}

/// Build the error a `Store` returns when a write COMMITTED (its atomic rename
/// completed) but the follow-up durability fsync failed. Pairs with
/// `is_committed_unsynced_error` so callers treat the write as committed.
pub fn committed_unsynced_error(source: io::Error) -> io::Error {
    io::Error::other(CommittedUnsynced(source))
}

/// True if `e` reports a write that COMMITTED (the atomic rename completed) but
/// whose directory fsync failed afterwards. The record is already on disk, so a
/// caller seeing this must treat the operation as committed and NOT roll back
/// (rolling back would diverge in-memory state from disk and could resurrect a
/// rejected intent on restart).
pub fn is_committed_unsynced_error(e: &io::Error) -> bool {
    e.get_ref()
        .is_some_and(|inner| inner.is::<CommittedUnsynced>())
}

/// Ensure `dir` exists as an owner-only (0700) directory whose creation is
/// crash-durable. If `dir` is missing it (and any missing ancestors) are
/// created 0700 and its parent is fsync'd so the new directory entry survives a
/// crash; if `dir` already exists this is a no-op and its mode is left
/// untouched. Centralizing this here makes the durability guarantee hold no
/// matter who creates the data dir (the store on first write, or the daemon at
/// startup).
pub fn ensure_secure_dir(dir: &std::path::Path) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    if dir.as_os_str().is_empty() || dir.exists() {
        return Ok(());
    }
    // Collect the missing components from `dir` up to the deepest existing
    // ancestor (deepest-first).
    let mut missing: Vec<&std::path::Path> = Vec::new();
    let mut cur = dir;
    while !cur.exists() {
        missing.push(cur);
        match cur.parent() {
            Some(p) if !p.as_os_str().is_empty() => cur = p,
            _ => break,
        }
    }
    // Create shallowest-first, fsyncing each new directory's parent so EVERY
    // new entry along the chain is crash-durable — a single final-parent fsync
    // would leave earlier new ancestors unsynced and losable after a crash.
    for comp in missing.iter().rev() {
        match std::fs::DirBuilder::new().mode(0o700).create(comp) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
        let parent = match comp.parent() {
            Some(p) if !p.as_os_str().is_empty() => p,
            _ => std::path::Path::new("."),
        };
        std::fs::File::open(parent)?.sync_all()?;
    }
    Ok(())
}

/// Create `path` exclusively (`O_EXCL`) at mode 0600, write `bytes`, and fsync.
/// `create_new` fails if anything already exists at `path` (including a
/// symlink), so a fresh file is guaranteed and the 0600 mode is never ignored.
fn write_secret_file(path: &std::path::Path, bytes: &[u8]) -> io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(bytes)?;
    f.sync_all()
}

impl Store for JsonStore {
    fn upsert(&self, record: &PersistedRecord) -> io::Result<()> {
        validate_record(&record.id.0, record).map_err(io::Error::other)?;
        let _guard = self.lock.lock().unwrap();
        let mut map = self.read_map()?;
        map.insert(record.id.0.clone(), record.clone());
        // Fail loud rather than rewriting a file that already holds a
        // structurally-invalid record (e.g. external corruption).
        validate_map(&map)?;
        self.write_map(&map)
    }

    fn delete(&self, id: &SandboxId) -> io::Result<()> {
        let _guard = self.lock.lock().unwrap();
        let mut map = self.read_map()?;
        map.remove(&id.0);
        validate_map(&map)?;
        self.write_map(&map)
    }

    fn load_all(&self) -> io::Result<Vec<PersistedRecord>> {
        let _guard = self.lock.lock().unwrap();
        let map = self.read_map()?;
        let mut out = Vec::with_capacity(map.len());
        for (key, record) in map {
            validate_record(&key, &record).map_err(io::Error::other)?;
            out.push(record);
        }
        Ok(out)
    }

    fn replace_all(&self, records: &[PersistedRecord]) -> io::Result<()> {
        let mut map = BTreeMap::new();
        for r in records {
            map.insert(r.id.0.clone(), r.clone());
        }
        let _guard = self.lock.lock().unwrap();
        validate_map(&map)?;
        self.write_map(&map)
    }

    /// Reads and validates the state file, creates, writes and removes a
    /// temp file beside it with a directory fsync, then takes and releases
    /// the store lock. The lock is never held across I/O.
    fn probe(&self) -> io::Result<()> {
        use std::os::unix::fs::OpenOptionsExt;

        validate_map(&self.read_map()?)?;

        let tmp = self.unique_tmp_path();
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)?;
        let written = file.write_all(b"probe\n").and_then(|()| self.sync_dir());
        drop(file);
        let removed = std::fs::remove_file(&tmp);
        written?;
        removed?;

        drop(
            self.lock
                .lock()
                .map_err(|_| io::Error::other("store lock poisoned"))?,
        );
        Ok(())
    }
}

/// Disk-free `Store` for the mock backend and reconciler unit tests.
pub struct InMemoryStore {
    map: Mutex<HashMap<SandboxId, PersistedRecord>>,
}

impl InMemoryStore {
    pub fn new() -> Self {
        Self {
            map: Mutex::new(HashMap::new()),
        }
    }
}

impl Default for InMemoryStore {
    fn default() -> Self {
        Self::new()
    }
}

impl Store for InMemoryStore {
    fn upsert(&self, record: &PersistedRecord) -> io::Result<()> {
        validate_record(&record.id.0, record).map_err(io::Error::other)?;
        self.map
            .lock()
            .unwrap()
            .insert(record.id.clone(), record.clone());
        Ok(())
    }

    fn delete(&self, id: &SandboxId) -> io::Result<()> {
        self.map.lock().unwrap().remove(id);
        Ok(())
    }

    fn load_all(&self) -> io::Result<Vec<PersistedRecord>> {
        let map = self.map.lock().unwrap();
        for (key, record) in map.iter() {
            validate_record(&key.0, record).map_err(io::Error::other)?;
        }
        Ok(map.values().cloned().collect())
    }

    fn replace_all(&self, records: &[PersistedRecord]) -> io::Result<()> {
        let mut new_map = HashMap::with_capacity(records.len());
        for r in records {
            validate_record(&r.id.0, r).map_err(io::Error::other)?;
            new_map.insert(r.id.clone(), r.clone());
        }
        *self.map.lock().unwrap() = new_map;
        Ok(())
    }

    fn probe(&self) -> io::Result<()> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// PID-reuse-safe verification
// ---------------------------------------------------------------------------

/// Read `/proc/<pid>/stat` field 22 (process start time, in clock ticks).
///
/// The `comm` field (field 2) is parenthesized and may contain spaces and
/// parentheses, so the parse splits on the LAST `)` before tokenizing.
#[cfg(target_os = "linux")]
pub fn pid_start_time(pid: i32) -> Option<u64> {
    if pid <= 0 {
        return None;
    }
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    parse_starttime(&stat)
}

/// PID start-time verification is implemented via `/proc`; on platforms without
/// it there is no start-time source, so callers (e.g. start()) must surface a
/// clear unsupported error rather than treat a process as verified.
#[cfg(not(target_os = "linux"))]
pub fn pid_start_time(_pid: i32) -> Option<u64> {
    None
}

/// Extract field 22 (starttime) from a `/proc/<pid>/stat` line.
#[cfg(target_os = "linux")]
fn parse_starttime(stat: &str) -> Option<u64> {
    let after_comm = &stat[stat.rfind(')')? + 1..];
    // After the closing `)`, the next field is `state` (overall field 3), so
    // `starttime` (field 22) is at index 22 - 3 = 19.
    after_comm.split_whitespace().nth(19)?.parse().ok()
}

/// True iff `pid` currently exists AND its start time matches `expected`
/// (defeats PID reuse).
pub fn verify_pid(pid: i32, expected: u64) -> bool {
    pid_start_time(pid) == Some(expected)
}

/// Capture a process's start time for PID-reuse verification, or a clear
/// platform error. On Linux a `None` means the process already exited (the
/// caller raced its exit); off Linux there is no start-time source, so the
/// operation is explicitly unsupported rather than a spurious capture failure.
#[cfg(target_os = "linux")]
pub fn require_pid_start_time(pid: i32) -> Result<u64, String> {
    pid_start_time(pid).ok_or_else(|| "could not capture VM start time".into())
}

#[cfg(not(target_os = "linux"))]
pub fn require_pid_start_time(_pid: i32) -> Result<u64, String> {
    Err("unsupported on this platform: pid start-time verification".into())
}

// ---------------------------------------------------------------------------
// Record validation
// ---------------------------------------------------------------------------

/// Accept ONLY the `(state, desired, observed-vs-generation, reason, resources)`
/// tuples reachable per the lifecycle transition table; reject everything else
/// as corrupt so the reconciler provably never sees an invalid record.
/// Validate every entry of a whole map before it is written, so a single
/// invalid record fails the write loud instead of being silently rewritten.
fn validate_map(map: &BTreeMap<String, PersistedRecord>) -> io::Result<()> {
    for (key, record) in map {
        validate_record(key, record).map_err(io::Error::other)?;
    }
    Ok(())
}

fn validate_record(map_key: &str, r: &PersistedRecord) -> Result<(), String> {
    if map_key != r.id.0 {
        return Err(format!("map key {:?} != record id {:?}", map_key, r.id.0));
    }
    if r.generation < 1 {
        return Err("generation must be >= 1".into());
    }
    if r.observed_generation > r.generation {
        return Err("observed_generation must be <= generation".into());
    }
    if r.pid.is_some() != r.pid_start_time.is_some() {
        return Err("pid and pid_start_time must be set together".into());
    }
    let is_failed = r.state == Some(State::Failed);
    if r.reason.is_some() != is_failed {
        return Err("reason present iff state is Failed".into());
    }
    if r.message.is_some() != is_failed {
        return Err("message present iff state is Failed".into());
    }
    // A live pid exists only while Running.
    if r.pid.is_some() != (r.state == Some(State::Running)) {
        return Err("pid present iff state is Running".into());
    }
    // The main-process exit carrier is valid only on a crashed-failed record;
    // any other state carrying it is a missed clear and corrupt. This is the
    // loud structural backstop for the carrier invariant.
    if r.entrypoint_exit.is_some()
        && !(r.state == Some(State::Failed) && r.reason == Some(FailureReason::Crashed))
    {
        return Err("entrypoint_exit present only on failed+crashed records".into());
    }
    // A corrupt persisted main-process command must fail loud at load/write.
    validate_entrypoint(r.config.entrypoint.as_deref())?;

    let obs = r.observed_generation;
    let cur_gen = r.generation;
    let has_rootfs = r.rootfs_path.is_some();

    use DesiredState as D;
    use FailureReason as F;
    use State as S;
    match (r.state, r.desired) {
        (None, _) => {
            if obs >= cur_gen {
                return Err("genesis requires observed_generation < generation".into());
            }
            if has_rootfs {
                return Err("genesis must not carry a rootfs".into());
            }
            Ok(())
        }
        (Some(S::Stopped), D::Stopped) => {
            if !has_rootfs {
                return Err("stopped sandbox requires a rootfs".into());
            }
            Ok(())
        }
        (Some(S::Stopped), D::Running | D::Destroyed) => {
            if obs >= cur_gen {
                return Err("pending transition requires observed_generation < generation".into());
            }
            if !has_rootfs {
                return Err("stopped sandbox requires a rootfs".into());
            }
            Ok(())
        }
        (Some(S::Running), D::Running) => {
            if !has_rootfs {
                return Err("running sandbox requires a rootfs".into());
            }
            Ok(())
        }
        (Some(S::Running), D::Stopped | D::Destroyed) => {
            if obs >= cur_gen {
                return Err(
                    "in-flight transition requires observed_generation < generation".into(),
                );
            }
            if !has_rootfs {
                return Err("running sandbox requires a rootfs".into());
            }
            Ok(())
        }
        (Some(S::Failed), D::Running) => {
            let reason = r.reason.expect("failed implies reason");
            if reason == F::DestroyFailed {
                return Err("destroy_failed is invalid with desired=running".into());
            }
            check_failed_rootfs(reason, has_rootfs)
        }
        (Some(S::Failed), D::Stopped) => {
            if obs != cur_gen {
                return Err("failed+stopped must be latched (observed == generation)".into());
            }
            if r.reason != Some(F::ProvisionFailed) {
                return Err("failed+stopped requires provision_failed".into());
            }
            check_failed_rootfs(F::ProvisionFailed, has_rootfs)
        }
        (Some(S::Failed), D::Destroyed) => {
            let reason = r.reason.expect("failed implies reason");
            if obs == cur_gen && reason != F::DestroyFailed {
                return Err("latched failed+destroyed must be destroy_failed".into());
            }
            check_failed_rootfs(reason, has_rootfs)
        }
        (Some(S::Destroyed), D::Destroyed) => {
            if obs != cur_gen {
                return Err("destroyed must be fully converged (observed == generation)".into());
            }
            if has_rootfs {
                return Err("destroyed must not carry a rootfs".into());
            }
            Ok(())
        }
        (Some(S::Destroyed), _) => Err("destroyed requires desired=destroyed".into()),
    }
}

/// Rootfs presence required for a `Failed` record, by reason:
/// - `provision_failed`: no rootfs was ever built/retained, so it must be absent.
/// - `start_failed` / `crashed`: the sandbox had provisioned, so a rootfs is present.
/// - `destroy_failed`: a teardown failed; the rootfs may or may not have been
///   recorded (destroying a never-provisioned sandbox still fails on session-dir
///   cleanup), so either is valid.
fn check_failed_rootfs(reason: FailureReason, has_rootfs: bool) -> Result<(), String> {
    match reason {
        FailureReason::ProvisionFailed => {
            if has_rootfs {
                return Err("provision_failed must not carry a rootfs".into());
            }
        }
        FailureReason::StartFailed | FailureReason::Crashed => {
            if !has_rootfs {
                return Err("start_failed/crashed requires a rootfs".into());
            }
        }
        FailureReason::DestroyFailed => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::NetworkPolicy;

    fn cfg() -> SandboxConfig {
        SandboxConfig {
            name: Some("t".into()),
            image: "alpine".into(),
            mounts: vec![],
            network: NetworkPolicy::Isolated,
            env: vec![],
            entrypoint: None,
        }
    }

    /// A valid `Stopped` at-rest record; mutate fields to build other shapes.
    fn base(id: &str) -> PersistedRecord {
        PersistedRecord {
            id: SandboxId(id.into()),
            config: cfg(),
            desired: DesiredState::Stopped,
            generation: 1,
            state: Some(State::Stopped),
            observed_generation: 1,
            pid: None,
            pid_start_time: None,
            rootfs_path: Some(PathBuf::from("/tmp/rootfs")),
            reason: None,
            message: None,
            entrypoint_exit: None,
            created_at: "t0".into(),
            last_transition_at: "t0".into(),
        }
    }

    fn running(id: &str) -> PersistedRecord {
        PersistedRecord {
            state: Some(State::Running),
            desired: DesiredState::Running,
            pid: Some(1),
            pid_start_time: Some(42),
            ..base(id)
        }
    }

    fn failed(id: &str, reason: FailureReason) -> PersistedRecord {
        PersistedRecord {
            state: Some(State::Failed),
            reason: Some(reason),
            message: Some("boom".into()),
            rootfs_path: if reason == FailureReason::ProvisionFailed {
                None
            } else {
                Some(PathBuf::from("/tmp/rootfs"))
            },
            ..base(id)
        }
    }

    // --- Store round-trip -------------------------------------------------

    #[test]
    fn json_store_roundtrip_overwrite_delete() {
        let dir = tempdir();
        let store = JsonStore::new(dir.join("state.json"));
        store.upsert(&base("sb-1")).unwrap();
        store.upsert(&running("sb-2")).unwrap();
        let mut ids: Vec<_> = store
            .load_all()
            .unwrap()
            .into_iter()
            .map(|r| r.id.0)
            .collect();
        ids.sort();
        assert_eq!(ids, vec!["sb-1", "sb-2"]);

        // Overwrite same id.
        let updated = PersistedRecord {
            generation: 2,
            observed_generation: 1,
            desired: DesiredState::Running,
            ..base("sb-1")
        };
        store.upsert(&updated).unwrap();
        let loaded: Vec<_> = store.load_all().unwrap();
        assert_eq!(loaded.len(), 2);
        let sb1 = loaded.iter().find(|r| r.id.0 == "sb-1").unwrap();
        assert_eq!(sb1.generation, 2);

        store.delete(&SandboxId("sb-1".into())).unwrap();
        let after: Vec<_> = store.load_all().unwrap();
        assert_eq!(after.len(), 1);
        assert_eq!(after[0].id.0, "sb-2");
    }

    #[test]
    fn json_store_writes_secret_safe_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let parent = tempdir();
        // A data dir the store must create itself (so we observe its mode).
        let data_dir = parent.join("data");
        let path = data_dir.join("state.json");
        let store = JsonStore::new(&path);
        store.upsert(&base("sb-1")).unwrap();

        // The freshly created data dir is 0700 (no group/other access).
        let dir_mode = std::fs::metadata(&data_dir).unwrap().permissions().mode();
        assert_eq!(dir_mode & 0o777, 0o700, "data dir must be 0700");

        // state.json is the renamed temp file, so this also proves the temp
        // file was created 0600 (never briefly world-readable).
        let file_mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(file_mode & 0o777, 0o600, "state file must be 0600");
    }

    #[test]
    fn json_store_temp_is_fresh_not_stale_or_symlink() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir();
        let path = dir.join("state.json");

        // A world-readable stale file at a predictable temp path an attacker
        // might pre-plant (the old fixed `state.tmp`).
        let legacy_tmp = path.with_extension("tmp");
        std::fs::write(&legacy_tmp, b"stale").unwrap();
        std::fs::set_permissions(&legacy_tmp, std::fs::Permissions::from_mode(0o644)).unwrap();

        // A symlink at another predictable temp path pointing at a victim file.
        let victim = dir.join("victim");
        std::fs::write(&victim, b"orig").unwrap();
        let symlink_tmp = path.with_file_name("state.json.tmp");
        std::os::unix::fs::symlink(&victim, &symlink_tmp).unwrap();

        let store = JsonStore::new(&path);
        store.upsert(&base("sb-1")).unwrap();

        // state.json is 0600 — not the 0644 inherited from a reused stale temp.
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "state file must be 0600");
        // The symlink's target was never written through.
        assert_eq!(std::fs::read(&victim).unwrap(), b"orig");
        // The store still round-trips despite the planted files.
        assert_eq!(store.load_all().unwrap().len(), 1);
    }

    #[test]
    fn ensure_secure_dir_creates_0700_and_is_idempotent() {
        use std::os::unix::fs::PermissionsExt;
        let parent = tempdir();
        // Several missing ancestors: EVERY newly created component is 0700
        // (each one's parent is fsynced individually for crash durability).
        let a = parent.join("a");
        let b = a.join("b");
        let dir = b.join("data");
        ensure_secure_dir(&dir).unwrap();
        for d in [&a, &b, &dir] {
            assert!(d.is_dir(), "{} should exist", d.display());
            let mode = std::fs::metadata(d).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o700, "{} must be 0700", d.display());
        }
        // Idempotent on an existing dir (no error, mode untouched).
        ensure_secure_dir(&dir).unwrap();
        let mode = std::fs::metadata(&dir).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700);
    }

    #[test]
    fn json_store_missing_file_is_empty() {
        let dir = tempdir();
        let store = JsonStore::new(dir.join("missing.json"));
        assert!(store.load_all().unwrap().is_empty());
    }

    #[test]
    fn json_store_rejects_write_when_existing_record_invalid() {
        // A structurally-deserializable but invalid record planted on disk
        // (Stopped without a rootfs) must make the next write fail loud, not be
        // silently preserved/rewritten.
        let dir = tempdir();
        let path = dir.join("state.json");
        let invalid = PersistedRecord {
            rootfs_path: None,
            ..base("sb-bad")
        };
        let mut planted = BTreeMap::new();
        planted.insert("sb-bad".to_string(), invalid);
        std::fs::write(&path, serde_json::to_vec(&planted).unwrap()).unwrap();
        let store = JsonStore::new(&path);
        // upsert of a fresh valid record still aborts (sb-bad stays invalid).
        assert!(store.upsert(&base("sb-1")).is_err());
        // delete of an unrelated id also aborts rather than rewriting sb-bad.
        assert!(store.delete(&SandboxId("sb-1".into())).is_err());
    }

    #[test]
    fn committed_unsynced_error_is_distinguished() {
        // A committed-but-unsynced write (rename done, dir fsync failed) is
        // detectable and carries its source, while ordinary io errors are not —
        // so a caller never mistakes a rollback-safe failure for a committed one.
        let committed = committed_unsynced_error(io::Error::other("dir fsync failed"));
        assert!(is_committed_unsynced_error(&committed));
        assert!(committed.to_string().contains("dir fsync failed"));

        assert!(!is_committed_unsynced_error(&io::Error::other("plain")));
        assert!(!is_committed_unsynced_error(&io::Error::new(
            io::ErrorKind::NotFound,
            "missing"
        )));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn require_pid_start_time_ok_for_self() {
        assert!(require_pid_start_time(std::process::id() as i32).is_ok());
    }

    #[test]
    fn json_store_corrupt_file_is_error() {
        let dir = tempdir();
        let path = dir.join("state.json");
        std::fs::write(&path, b"{not json").unwrap();
        let store = JsonStore::new(&path);
        assert!(store.load_all().is_err());
    }

    #[test]
    fn json_store_concurrent_upserts_all_land() {
        let dir = tempdir();
        let store = std::sync::Arc::new(JsonStore::new(dir.join("state.json")));
        let mut handles = vec![];
        for i in 0..16 {
            let s = store.clone();
            handles.push(std::thread::spawn(move || {
                s.upsert(&base(&format!("sb-{i}"))).unwrap();
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(store.load_all().unwrap().len(), 16);
    }

    #[test]
    fn in_memory_store_roundtrip() {
        let store: &dyn Store = &InMemoryStore::new();
        store.upsert(&base("sb-1")).unwrap();
        store.upsert(&running("sb-2")).unwrap();
        assert_eq!(store.load_all().unwrap().len(), 2);
        store.delete(&SandboxId("sb-1".into())).unwrap();
        assert_eq!(store.load_all().unwrap().len(), 1);
    }

    // --- PID verification -------------------------------------------------

    // These exercise /proc start-time semantics and only hold on Linux; the
    // non-Linux contract (pid_start_time is unsupported) is asserted separately.
    #[cfg(target_os = "linux")]
    #[test]
    fn verify_pid_matches_own_process() {
        let me = std::process::id() as i32;
        let start = pid_start_time(me).expect("own start time");
        assert!(verify_pid(me, start));
        assert!(!verify_pid(me, start + 1), "wrong start time must fail");
    }

    #[test]
    fn verify_pid_nonexistent_is_false() {
        assert!(pid_start_time(-1).is_none());
        assert!(!verify_pid(0x7fff_fffe, 1));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn verify_pid_reaped_child_is_false() {
        let child = std::process::Command::new("true")
            .spawn()
            .expect("spawn true");
        let pid = child.id() as i32;
        let mut child = child;
        child.wait().unwrap();
        // Reaped: /proc entry is gone.
        assert!(pid_start_time(pid).is_none());
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn pid_start_time_is_unsupported_off_linux() {
        // No /proc: start-time is unavailable, so nothing ever verifies.
        let me = std::process::id() as i32;
        assert!(pid_start_time(me).is_none());
        assert!(!verify_pid(me, 0));
        assert!(require_pid_start_time(me).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parse_starttime_handles_parens_in_comm() {
        // comm field contains spaces and a `) ` sequence.
        let line = "1234 (weird ) name) S 1 1234 1234 0 -1 0 0 0 0 0 0 0 0 0 \
                    20 0 1 0 99887766 0";
        // After the LAST ')', field 22 (starttime) is 99887766.
        assert_eq!(parse_starttime(line), Some(99887766));
    }

    // --- Record validation ------------------------------------------------

    fn ok(r: &PersistedRecord) {
        validate_record(&r.id.0, r).expect("expected valid record");
    }
    fn bad(r: &PersistedRecord) {
        assert!(
            validate_record(&r.id.0, r).is_err(),
            "expected invalid record"
        );
    }

    #[test]
    fn accept_matrix_valid_rows() {
        // Genesis (all desireds).
        for d in [
            DesiredState::Stopped,
            DesiredState::Running,
            DesiredState::Destroyed,
        ] {
            ok(&PersistedRecord {
                state: None,
                desired: d,
                generation: 1,
                observed_generation: 0,
                rootfs_path: None,
                ..base("sb-1")
            });
        }
        // Stopped+Stopped at rest and accepted-no-op-pending.
        ok(&base("sb-1"));
        ok(&PersistedRecord {
            generation: 2,
            observed_generation: 1,
            ..base("sb-1")
        });
        // Stopped pending start/destroy.
        for d in [DesiredState::Running, DesiredState::Destroyed] {
            ok(&PersistedRecord {
                desired: d,
                generation: 2,
                observed_generation: 1,
                ..base("sb-1")
            });
        }
        // Running converged and accepted-no-op-pending.
        ok(&running("sb-1"));
        ok(&PersistedRecord {
            generation: 2,
            observed_generation: 1,
            ..running("sb-1")
        });
        // Running pending stop/destroy.
        for d in [DesiredState::Stopped, DesiredState::Destroyed] {
            ok(&PersistedRecord {
                desired: d,
                generation: 2,
                observed_generation: 1,
                ..running("sb-1")
            });
        }
        // Failed+Running for each reopen-able reason.
        for reason in [
            FailureReason::ProvisionFailed,
            FailureReason::StartFailed,
            FailureReason::Crashed,
        ] {
            ok(&PersistedRecord {
                desired: DesiredState::Running,
                generation: 2,
                observed_generation: 1,
                ..failed("sb-1", reason)
            });
        }
        // Failed+Stopped latched provision_failed.
        ok(&PersistedRecord {
            desired: DesiredState::Stopped,
            ..failed("sb-1", FailureReason::ProvisionFailed)
        });
        // Failed+Destroyed pending (any reason).
        for reason in [
            FailureReason::ProvisionFailed,
            FailureReason::StartFailed,
            FailureReason::Crashed,
            FailureReason::DestroyFailed,
        ] {
            ok(&PersistedRecord {
                desired: DesiredState::Destroyed,
                generation: 2,
                observed_generation: 1,
                ..failed("sb-1", reason)
            });
        }
        // Failed+Destroyed latched destroy_failed.
        ok(&PersistedRecord {
            desired: DesiredState::Destroyed,
            ..failed("sb-1", FailureReason::DestroyFailed)
        });
        // Failed+Destroyed latched destroy_failed WITHOUT a rootfs (destroying a
        // never-provisioned sandbox whose session-dir cleanup failed).
        ok(&PersistedRecord {
            state: Some(State::Failed),
            desired: DesiredState::Destroyed,
            reason: Some(FailureReason::DestroyFailed),
            message: Some("boom".into()),
            rootfs_path: None,
            ..base("sb-1")
        });
        // Destroyed converged.
        ok(&PersistedRecord {
            state: Some(State::Destroyed),
            desired: DesiredState::Destroyed,
            rootfs_path: None,
            ..base("sb-1")
        });
    }

    #[test]
    fn reject_cross_cutting_violations() {
        bad(&PersistedRecord {
            generation: 0,
            observed_generation: 0,
            ..base("sb-1")
        });
        bad(&PersistedRecord {
            generation: 1,
            observed_generation: 2,
            ..base("sb-1")
        });
        // map key mismatch
        let r = base("sb-1");
        assert!(validate_record("sb-OTHER", &r).is_err());
        // pid xor start
        bad(&PersistedRecord {
            pid: Some(1),
            pid_start_time: None,
            ..running("sb-1")
        });
        // non-Failed carrying reason
        bad(&PersistedRecord {
            reason: Some(FailureReason::Crashed),
            ..base("sb-1")
        });
        // Failed without reason
        bad(&PersistedRecord {
            state: Some(State::Failed),
            reason: None,
            message: None,
            ..base("sb-1")
        });
        // Failed without message (message is mandatory for Failed)
        bad(&PersistedRecord {
            desired: DesiredState::Running,
            generation: 2,
            observed_generation: 1,
            message: None,
            ..failed("sb-1", FailureReason::Crashed)
        });
    }

    #[test]
    fn reject_unreachable_state_tuples() {
        // Stopped+Running+observed==gen (converged-but-not-at-desired)
        bad(&PersistedRecord {
            desired: DesiredState::Running,
            generation: 1,
            observed_generation: 1,
            ..base("sb-1")
        });
        // None+observed==gen
        bad(&PersistedRecord {
            state: None,
            generation: 1,
            observed_generation: 1,
            rootfs_path: None,
            ..base("sb-1")
        });
        // destroy_failed with desired != Destroyed
        bad(&PersistedRecord {
            desired: DesiredState::Running,
            generation: 2,
            observed_generation: 1,
            ..failed("sb-1", FailureReason::DestroyFailed)
        });
        // crashed with desired=Stopped
        bad(&PersistedRecord {
            desired: DesiredState::Stopped,
            generation: 1,
            observed_generation: 1,
            ..failed("sb-1", FailureReason::Crashed)
        });
        // Failed+Stopped+observed<gen
        bad(&PersistedRecord {
            desired: DesiredState::Stopped,
            generation: 2,
            observed_generation: 1,
            ..failed("sb-1", FailureReason::ProvisionFailed)
        });
        // Destroyed with desired != Destroyed
        bad(&PersistedRecord {
            state: Some(State::Destroyed),
            desired: DesiredState::Stopped,
            rootfs_path: None,
            ..base("sb-1")
        });
        // Destroyed not converged
        bad(&PersistedRecord {
            state: Some(State::Destroyed),
            desired: DesiredState::Destroyed,
            generation: 2,
            observed_generation: 1,
            rootfs_path: None,
            ..base("sb-1")
        });
        // Running without pid
        bad(&PersistedRecord {
            state: Some(State::Running),
            desired: DesiredState::Running,
            pid: None,
            pid_start_time: None,
            ..base("sb-1")
        });
        // Stopped without rootfs
        bad(&PersistedRecord {
            rootfs_path: None,
            ..base("sb-1")
        });
        // provision_failed carrying a rootfs
        bad(&PersistedRecord {
            desired: DesiredState::Running,
            generation: 2,
            observed_generation: 1,
            rootfs_path: Some(PathBuf::from("/tmp/rootfs")),
            ..failed("sb-1", FailureReason::ProvisionFailed)
        });
    }

    // --- Entrypoint-exit carrier invariant -------------------------------

    fn with_carrier(r: PersistedRecord) -> PersistedRecord {
        PersistedRecord {
            entrypoint_exit: Some(EntrypointExit::Exited { code: 7 }),
            ..r
        }
    }

    /// A latched, valid `Failed(reason)` with `desired = Running` (the shape the
    /// crash/start-failure commits produce). `crashed`/`start_failed` carry a
    /// rootfs; `provision_failed` does not.
    fn failed_running(id: &str, reason: FailureReason) -> PersistedRecord {
        PersistedRecord {
            state: Some(State::Failed),
            desired: DesiredState::Running,
            reason: Some(reason),
            message: Some("boom".into()),
            rootfs_path: if reason == FailureReason::ProvisionFailed {
                None
            } else {
                Some(PathBuf::from("/tmp/rootfs"))
            },
            ..base(id)
        }
    }

    #[test]
    fn carrier_valid_only_on_failed_crashed() {
        // Failed(Crashed) with or without the carrier is valid.
        ok(&with_carrier(failed_running(
            "sb-1",
            FailureReason::Crashed,
        )));
        ok(&failed_running("sb-1", FailureReason::Crashed));
        // Every other state carrying the carrier is corrupt — on records that are
        // otherwise valid, so the carrier rule is what rejects them.
        bad(&with_carrier(base("sb-1"))); // Stopped
        bad(&with_carrier(running("sb-1"))); // Running
        bad(&with_carrier(failed_running(
            "sb-1",
            FailureReason::StartFailed,
        )));
        bad(&with_carrier(failed_running(
            "sb-1",
            FailureReason::ProvisionFailed,
        )));
        bad(&with_carrier(PersistedRecord {
            desired: DesiredState::Destroyed,
            ..failed("sb-1", FailureReason::DestroyFailed)
        }));
        bad(&with_carrier(PersistedRecord {
            state: Some(State::Destroyed),
            desired: DesiredState::Destroyed,
            rootfs_path: None,
            ..base("sb-1")
        }));
    }

    #[test]
    fn json_store_roundtrips_crashed_carrier() {
        let dir = tempdir();
        let store = JsonStore::new(dir.join("state.json"));
        let rec = with_carrier(failed_running("sb-1", FailureReason::Crashed));
        store.upsert(&rec).unwrap();
        let loaded = store.load_all().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(
            loaded[0].entrypoint_exit,
            Some(EntrypointExit::Exited { code: 7 })
        );
    }

    #[test]
    fn upsert_rejects_carrier_on_non_crashed_record() {
        // The store-level structural backstop: a deliberately missed clear-site
        // (here an otherwise-valid Failed(StartFailed) carrying the carrier) fails
        // loud at upsert, never silently persisted.
        let store = InMemoryStore::new();
        let invalid = with_carrier(failed_running("sb-1", FailureReason::StartFailed));
        assert!(store.upsert(&invalid).is_err());
        assert!(store.load_all().unwrap().is_empty());
    }

    #[test]
    fn validate_record_rejects_corrupt_persisted_entrypoint() {
        // A malformed persisted main-process command fails loud at the store, so
        // a corrupt record never reconciles into a boot.
        let mut r = base("sb-1");
        r.config.entrypoint = Some(vec![]);
        bad(&r);
        r.config.entrypoint = Some(vec![String::new()]);
        bad(&r);
        r.config.entrypoint = Some(vec!["bad\0arg".into()]);
        bad(&r);
        // A well-formed command is accepted.
        r.config.entrypoint = Some(vec!["/bin/true".into()]);
        ok(&r);
    }

    #[test]
    fn json_store_surfaces_io_errors() {
        let dir = tempdir();
        let blocker = dir.join("blocker");
        std::fs::write(&blocker, b"x").unwrap();
        // Parent is a regular file: the atomic write + dir fsync cannot succeed,
        // and the error must propagate rather than being silently swallowed.
        let store = JsonStore::new(blocker.join("state.json"));
        assert!(store.upsert(&base("sb-1")).is_err());
    }

    #[test]
    fn upsert_rejects_invalid_record() {
        let store = InMemoryStore::new();
        // Stopped without a rootfs is invalid -> upsert fails loud, never stored.
        let invalid = PersistedRecord {
            rootfs_path: None,
            ..base("sb-1")
        };
        assert!(store.upsert(&invalid).is_err());
        assert!(store.load_all().unwrap().is_empty());
        // A valid record upserts fine.
        assert!(store.upsert(&base("sb-1")).is_ok());
    }

    // --- Probe ----------------------------------------------------------------

    fn is_root() -> bool {
        unsafe { libc::geteuid() == 0 }
    }

    fn dir_entries(dir: &std::path::Path) -> Vec<String> {
        let mut names: Vec<_> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    fn set_mode(dir: &std::path::Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    #[test]
    fn probe_ok_on_fresh_and_populated_store() {
        let dir = tempdir();
        let store = JsonStore::new(dir.join("state.json"));
        store.probe().unwrap();
        store.upsert(&base("sb-1")).unwrap();
        store.probe().unwrap();
    }

    #[test]
    fn probe_fails_on_corrupt_state() {
        let dir = tempdir();
        std::fs::write(dir.join("state.json"), b"{not json").unwrap();
        let store = JsonStore::new(dir.join("state.json"));
        let err = store.probe().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Other);
        assert!(err.to_string().contains("key must be a string"), "{err}");
    }

    #[test]
    fn probe_fails_on_invalid_record() {
        let dir = tempdir();
        let mut map = BTreeMap::new();
        map.insert("sb-1".to_string(), with_carrier(base("sb-1")));
        std::fs::write(
            dir.join("state.json"),
            serde_json::to_vec_pretty(&map).unwrap(),
        )
        .unwrap();
        let store = JsonStore::new(dir.join("state.json"));
        let err = store.probe().unwrap_err();
        assert_eq!(
            err.to_string(),
            "entrypoint_exit present only on failed+crashed records"
        );
    }

    #[test]
    fn probe_fails_on_readonly_dir() {
        if is_root() {
            eprintln!("skipped: root bypasses directory permissions");
            return;
        }
        let dir = tempdir();
        let store = JsonStore::new(dir.join("state.json"));
        store.upsert(&base("sb-1")).unwrap();
        set_mode(&dir, 0o500);
        let result = store.probe();
        set_mode(&dir, 0o700);
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(dir_entries(&dir), vec!["state.json"]);
    }

    #[test]
    fn probe_fails_when_dir_sync_fails() {
        if is_root() {
            eprintln!("skipped: root bypasses directory permissions");
            return;
        }
        let dir = tempdir();
        let store = JsonStore::new(dir.join("state.json"));
        store.upsert(&base("sb-1")).unwrap();
        // Write and search permission without read: the temp can be created,
        // but the directory cannot be opened for its fsync.
        set_mode(&dir, 0o300);
        let result = store.probe();
        set_mode(&dir, 0o700);
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(dir_entries(&dir), vec!["state.json"]);
    }

    #[test]
    fn probe_leaves_state_unchanged() {
        let dir = tempdir();
        let store = JsonStore::new(dir.join("state.json"));
        store.upsert(&base("sb-1")).unwrap();
        store.upsert(&running("sb-2")).unwrap();
        let before = std::fs::read(dir.join("state.json")).unwrap();
        store.probe().unwrap();
        assert_eq!(std::fs::read(dir.join("state.json")).unwrap(), before);
        assert_eq!(dir_entries(&dir), vec!["state.json"]);
    }

    #[test]
    fn probe_fails_when_store_mutex_poisoned() {
        let dir = tempdir();
        let store = std::sync::Arc::new(JsonStore::new(dir.join("state.json")));
        let holder = store.clone();
        let joined = std::thread::spawn(move || {
            let _guard = holder.lock.lock().unwrap();
            panic!("poison the store mutex");
        })
        .join();
        assert!(joined.is_err());
        let err = store.probe().unwrap_err();
        assert_eq!(err.to_string(), "store lock poisoned");
    }

    #[test]
    fn wedged_store_mutex_times_out_then_recovers() {
        use crate::backend::health::{StoreProbe, Unhealthy};
        use std::time::Duration;

        let dir = tempdir();
        let json = std::sync::Arc::new(JsonStore::new(dir.join("state.json")));
        let store: std::sync::Arc<dyn Store> = json.clone();
        let probe = StoreProbe::new(Duration::from_millis(200));
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();

        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let (held_tx, held_rx) = std::sync::mpsc::channel::<()>();
        let holder = json.clone();
        let wedge = std::thread::spawn(move || {
            let _guard = holder.lock.lock().unwrap();
            held_tx.send(()).unwrap();
            release_rx.recv().unwrap();
        });
        held_rx.recv().unwrap();

        let (first, second) =
            rt.block_on(async { tokio::join!(probe.check(&store), probe.check(&store)) });
        assert!(matches!(first, Err(Unhealthy::StoreTimeout)), "{first:?}");
        assert!(matches!(second, Err(Unhealthy::StoreTimeout)), "{second:?}");
        assert_eq!(probe.started(), 1);

        release_tx.send(()).unwrap();
        wedge.join().unwrap();
        probe.wait_idle();
        rt.block_on(probe.check(&store)).unwrap();
        assert_eq!(probe.started(), 2);
    }

    fn tempdir() -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "pp-store-test-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&p).unwrap();
        p
    }
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
}
