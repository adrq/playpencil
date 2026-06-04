use std::cell::RefCell;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

use crate::backend::libkrun::LibkrunBackend;
use crate::backend::{BackendError, SandboxBackendSend};
use crate::rootfs::linux::LinuxRootfsProvider;
use crate::types::{ExecEvent, ExecIo, ExecRequest, SandboxConfig, SandboxId};

// ---------------------------------------------------------------------------
// Thread-local last error
// ---------------------------------------------------------------------------

thread_local! {
    static LAST_ERROR: RefCell<Option<CString>> = const { RefCell::new(None) };
}

fn set_last_error(msg: &str) {
    LAST_ERROR.with(|e| {
        *e.borrow_mut() = Some(
            CString::new(msg)
                .unwrap_or_else(|_| CString::new("error message contained null byte").unwrap()),
        );
    });
}

fn clear_last_error() {
    LAST_ERROR.with(|e| {
        *e.borrow_mut() = None;
    });
}

// ---------------------------------------------------------------------------
// Panic-catching wrapper
// ---------------------------------------------------------------------------

macro_rules! ffi_catch {
    ($default:expr, $body:expr) => {
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| $body)) {
            Ok(val) => val,
            Err(_) => {
                set_last_error("internal panic");
                $default
            }
        }
    };
}

// ---------------------------------------------------------------------------
// Shared runtime internals (kept alive by Arc in all handles)
// ---------------------------------------------------------------------------

struct RuntimeInner {
    // Rust drops fields in declaration order (first field first). backend must be
    // declared first so it drops while tokio_rt is still alive — LibkrunBackend::drop
    // may need the runtime to cancel async tasks.
    backend: LibkrunBackend,
    tokio_rt: tokio::runtime::Runtime,
}

// ---------------------------------------------------------------------------
// Opaque handle types
// ---------------------------------------------------------------------------

pub struct PpRuntime {
    inner: Arc<RuntimeInner>,
}

pub struct PpSandbox {
    id: SandboxId,
    inner: Arc<RuntimeInner>,
}

pub struct PpExec {
    events: Mutex<tokio::sync::mpsc::Receiver<ExecEvent>>,
    io: ExecIo,
    inner: Arc<RuntimeInner>,
}

// ---------------------------------------------------------------------------
// Runtime config JSON
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct RuntimeConfig {
    data_dir: String,
    init_binary: String,
}

// ---------------------------------------------------------------------------
// Helper: convert BackendError to last-error string
// ---------------------------------------------------------------------------

fn backend_err(e: &BackendError) -> String {
    e.to_string()
}

/// Returns true (and sets last error) if called from inside a tokio runtime.
fn in_async_context() -> bool {
    if tokio::runtime::Handle::try_current().is_ok() {
        set_last_error("must not be called from within a Tokio async context");
        true
    } else {
        false
    }
}

/// Wire format for exec events over the C ABI. Binary data is base64-encoded
/// so it survives as a NUL-terminated C string.
#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ExecEventDto {
    Stdout { data: String },
    Stderr { data: String },
    StartError { message: String },
    Exit { code: i32 },
}

impl From<&ExecEvent> for ExecEventDto {
    fn from(event: &ExecEvent) -> Self {
        match event {
            ExecEvent::Stdout(data) => Self::Stdout {
                data: crate::util::base64_encode(data),
            },
            ExecEvent::Stderr(data) => Self::Stderr {
                data: crate::util::base64_encode(data),
            },
            ExecEvent::StartError(message) => Self::StartError {
                message: message.clone(),
            },
            ExecEvent::Exit { code } => Self::Exit { code: *code },
        }
    }
}

fn exec_event_to_json(event: &ExecEvent) -> String {
    serde_json::to_string(&ExecEventDto::from(event)).expect("ExecEventDto is always serializable")
}

/// Turn a Rust String into a heap-allocated C string pointer.
/// Caller must free with pp_string_free.
fn string_to_c(s: String) -> *mut c_char {
    match CString::new(s) {
        Ok(cs) => cs.into_raw(),
        Err(_) => {
            set_last_error("string contains interior null byte");
            std::ptr::null_mut()
        }
    }
}

// ---------------------------------------------------------------------------
// Exported C functions
// ---------------------------------------------------------------------------

/// # Safety
/// `config_json` must be a valid, NUL-terminated UTF-8 string or NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pp_runtime_new(config_json: *const c_char) -> *mut PpRuntime {
    clear_last_error();
    ffi_catch!(std::ptr::null_mut(), {
        let json_str = if config_json.is_null() {
            set_last_error("config_json is NULL");
            return std::ptr::null_mut();
        } else {
            match unsafe { CStr::from_ptr(config_json) }.to_str() {
                Ok(s) => s,
                Err(_) => {
                    set_last_error("config_json is not valid UTF-8");
                    return std::ptr::null_mut();
                }
            }
        };

        let cfg: RuntimeConfig = match serde_json::from_str(json_str) {
            Ok(c) => c,
            Err(e) => {
                set_last_error(&format!("invalid config JSON: {e}"));
                return std::ptr::null_mut();
            }
        };

        let tokio_rt = match tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(e) => {
                set_last_error(&format!("failed to create tokio runtime: {e}"));
                return std::ptr::null_mut();
            }
        };

        let rootfs_provider = Arc::new(LinuxRootfsProvider);
        let backend = match LibkrunBackend::new(&cfg.data_dir, &cfg.init_binary, rootfs_provider) {
            Ok(b) => b,
            Err(e) => {
                set_last_error(&backend_err(&e));
                return std::ptr::null_mut();
            }
        };

        // Reconstruct persisted sandboxes before serving.
        if let Err(e) = tokio_rt.block_on(backend.recover()) {
            set_last_error(&backend_err(&e));
            return std::ptr::null_mut();
        }

        let rt = PpRuntime {
            inner: Arc::new(RuntimeInner { backend, tokio_rt }),
        };
        Box::into_raw(Box::new(rt))
    })
}

/// # Safety
/// `handle` must be a valid PpRuntime pointer from `pp_runtime_new`, or NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pp_runtime_free(handle: *mut PpRuntime) {
    ffi_catch!((), {
        if !handle.is_null() {
            drop(unsafe { Box::from_raw(handle) });
        }
    })
}

/// # Safety
/// `rt` must be a valid PpRuntime pointer. `config_json` must be a valid C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pp_sandbox_create(
    rt: *mut PpRuntime,
    config_json: *const c_char,
) -> *mut PpSandbox {
    clear_last_error();
    ffi_catch!(std::ptr::null_mut(), {
        if rt.is_null() {
            set_last_error("runtime handle is NULL");
            return std::ptr::null_mut();
        }
        if in_async_context() {
            return std::ptr::null_mut();
        }
        let rt = unsafe { &*rt };

        let json_str = if config_json.is_null() {
            set_last_error("config_json is NULL");
            return std::ptr::null_mut();
        } else {
            match unsafe { CStr::from_ptr(config_json) }.to_str() {
                Ok(s) => s,
                Err(_) => {
                    set_last_error("config_json is not valid UTF-8");
                    return std::ptr::null_mut();
                }
            }
        };

        let config: SandboxConfig = match serde_json::from_str(json_str) {
            Ok(c) => c,
            Err(e) => {
                set_last_error(&format!("invalid sandbox config JSON: {e}"));
                return std::ptr::null_mut();
            }
        };

        let inner = Arc::clone(&rt.inner);
        let id = match inner.tokio_rt.block_on(inner.backend.create(config)) {
            Ok(id) => id,
            Err(e) => {
                set_last_error(&backend_err(&e));
                return std::ptr::null_mut();
            }
        };

        Box::into_raw(Box::new(PpSandbox { id, inner }))
    })
}

/// # Safety
/// `rt` must be a valid PpRuntime pointer. `config_json` must be a valid C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pp_sandbox_create_and_start(
    rt: *mut PpRuntime,
    config_json: *const c_char,
) -> *mut PpSandbox {
    clear_last_error();
    ffi_catch!(std::ptr::null_mut(), {
        if rt.is_null() {
            set_last_error("runtime handle is NULL");
            return std::ptr::null_mut();
        }
        if in_async_context() {
            return std::ptr::null_mut();
        }
        let rt = unsafe { &*rt };

        let json_str = if config_json.is_null() {
            set_last_error("config_json is NULL");
            return std::ptr::null_mut();
        } else {
            match unsafe { CStr::from_ptr(config_json) }.to_str() {
                Ok(s) => s,
                Err(_) => {
                    set_last_error("config_json is not valid UTF-8");
                    return std::ptr::null_mut();
                }
            }
        };

        let config: SandboxConfig = match serde_json::from_str(json_str) {
            Ok(c) => c,
            Err(e) => {
                set_last_error(&format!("invalid sandbox config JSON: {e}"));
                return std::ptr::null_mut();
            }
        };

        let inner = Arc::clone(&rt.inner);
        let id = match inner
            .tokio_rt
            .block_on(inner.backend.create_and_start(config))
        {
            Ok(id) => id,
            Err(e) => {
                set_last_error(&backend_err(&e));
                return std::ptr::null_mut();
            }
        };

        Box::into_raw(Box::new(PpSandbox { id, inner }))
    })
}

/// # Safety
/// `sb` must be a valid PpSandbox pointer or NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pp_sandbox_start(sb: *mut PpSandbox) -> i32 {
    clear_last_error();
    ffi_catch!(-1, {
        if sb.is_null() {
            set_last_error("sandbox handle is NULL");
            return -1;
        }
        if in_async_context() {
            return -1;
        }
        let sb = unsafe { &*sb };
        match sb.inner.tokio_rt.block_on(sb.inner.backend.start(&sb.id)) {
            Ok(()) => 0,
            Err(e) => {
                set_last_error(&backend_err(&e));
                -1
            }
        }
    })
}

/// # Safety
/// `sb` must be a valid PpSandbox pointer or NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pp_sandbox_stop(sb: *mut PpSandbox) -> i32 {
    clear_last_error();
    ffi_catch!(-1, {
        if sb.is_null() {
            set_last_error("sandbox handle is NULL");
            return -1;
        }
        if in_async_context() {
            return -1;
        }
        let sb = unsafe { &*sb };
        match sb.inner.tokio_rt.block_on(sb.inner.backend.stop(&sb.id)) {
            Ok(()) => 0,
            Err(e) => {
                set_last_error(&backend_err(&e));
                -1
            }
        }
    })
}

/// # Safety
/// `sb` must be a valid PpSandbox pointer or NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pp_sandbox_destroy(sb: *mut PpSandbox) -> i32 {
    clear_last_error();
    ffi_catch!(-1, {
        if sb.is_null() {
            set_last_error("sandbox handle is NULL");
            return -1;
        }
        if in_async_context() {
            return -1;
        }
        let sb = unsafe { &*sb };
        match sb.inner.tokio_rt.block_on(sb.inner.backend.destroy(&sb.id)) {
            Ok(()) => 0,
            Err(e) => {
                set_last_error(&backend_err(&e));
                -1
            }
        }
    })
}

/// # Safety
/// `sb` must be a valid PpSandbox pointer or NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pp_sandbox_status(sb: *mut PpSandbox) -> *mut c_char {
    clear_last_error();
    ffi_catch!(std::ptr::null_mut(), {
        if sb.is_null() {
            set_last_error("sandbox handle is NULL");
            return std::ptr::null_mut();
        }
        if in_async_context() {
            return std::ptr::null_mut();
        }
        let sb = unsafe { &*sb };
        match sb.inner.tokio_rt.block_on(sb.inner.backend.status(&sb.id)) {
            Ok(view) => match serde_json::to_string(&view.status) {
                Ok(json) => string_to_c(json),
                Err(e) => {
                    set_last_error(&format!("failed to serialize status: {e}"));
                    std::ptr::null_mut()
                }
            },
            Err(e) => {
                set_last_error(&backend_err(&e));
                std::ptr::null_mut()
            }
        }
    })
}

/// # Safety
/// `handle` must be a valid PpSandbox pointer from `pp_sandbox_create`, or NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pp_sandbox_free(handle: *mut PpSandbox) {
    ffi_catch!((), {
        if !handle.is_null() {
            drop(unsafe { Box::from_raw(handle) });
        }
    })
}

/// # Safety
/// `sb` must be a valid PpSandbox pointer. `cmd_json` must be a valid C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pp_sandbox_exec(
    sb: *mut PpSandbox,
    cmd_json: *const c_char,
) -> *mut PpExec {
    clear_last_error();
    ffi_catch!(std::ptr::null_mut(), {
        if sb.is_null() {
            set_last_error("sandbox handle is NULL");
            return std::ptr::null_mut();
        }
        if in_async_context() {
            return std::ptr::null_mut();
        }
        let sb = unsafe { &*sb };

        let json_str = if cmd_json.is_null() {
            set_last_error("cmd_json is NULL");
            return std::ptr::null_mut();
        } else {
            match unsafe { CStr::from_ptr(cmd_json) }.to_str() {
                Ok(s) => s,
                Err(_) => {
                    set_last_error("cmd_json is not valid UTF-8");
                    return std::ptr::null_mut();
                }
            }
        };

        let req: ExecRequest = match serde_json::from_str(json_str) {
            Ok(r) => r,
            Err(e) => {
                set_last_error(&format!("invalid exec request JSON: {e}"));
                return std::ptr::null_mut();
            }
        };

        let inner = Arc::clone(&sb.inner);
        let handle = match inner.tokio_rt.block_on(inner.backend.exec(&sb.id, req)) {
            Ok(h) => h,
            Err(e) => {
                set_last_error(&backend_err(&e));
                return std::ptr::null_mut();
            }
        };

        let (events, io) = handle.split();
        let exec = PpExec {
            events: Mutex::new(events),
            io,
            inner,
        };
        Box::into_raw(Box::new(exec))
    })
}

/// # Safety
/// `exec` must be a valid PpExec pointer or NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pp_exec_next_event(exec: *mut PpExec) -> *mut c_char {
    clear_last_error();
    ffi_catch!(std::ptr::null_mut(), {
        if exec.is_null() {
            set_last_error("exec handle is NULL");
            return std::ptr::null_mut();
        }
        if in_async_context() {
            return std::ptr::null_mut();
        }
        let exec = unsafe { &*exec };
        let event = {
            // Mutex held through block_on(recv): concurrent callers serialize
            // on the OS mutex until an event arrives. Guard released before
            // JSON serialization to minimize lock scope.
            let mut rx = exec.events.lock().unwrap_or_else(|e| e.into_inner());
            exec.inner.tokio_rt.block_on(rx.recv())
        };
        match event {
            Some(event) => {
                // The C caller is the consumer: release output credit (raw
                // process bytes) for the data we are handing it.
                let raw = match &event {
                    ExecEvent::Stdout(b) | ExecEvent::Stderr(b) => b.len(),
                    _ => 0,
                };
                if raw > 0 {
                    exec.io.release_credit(raw);
                }
                string_to_c(exec_event_to_json(&event))
            }
            None => std::ptr::null_mut(), // EOF — last_error stays NULL
        }
    })
}

/// # Safety
/// `exec` must be a valid PpExec pointer. `data` must point to `len` readable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pp_exec_write_stdin(
    exec: *mut PpExec,
    data: *const u8,
    len: usize,
) -> i32 {
    clear_last_error();
    ffi_catch!(-1, {
        if exec.is_null() {
            set_last_error("exec handle is NULL");
            return -1;
        }
        if len == 0 {
            return 0;
        }
        if data.is_null() {
            set_last_error("data is NULL");
            return -1;
        }
        if len > isize::MAX as usize {
            set_last_error("stdin write length exceeds maximum");
            return -1;
        }
        if in_async_context() {
            return -1;
        }
        let exec = unsafe { &*exec };
        let bytes = unsafe { std::slice::from_raw_parts(data, len) };
        // Byte-bounded ingress: write_stdin splits into frames no larger than the
        // per-frame cap so a single huge call never buffers an unbounded Vec; the
        // bounded relay channel back-pressures the caller between chunks.
        match exec.inner.tokio_rt.block_on(exec.io.write_stdin(bytes)) {
            Ok(()) => 0,
            Err(()) => {
                set_last_error("stdin channel closed");
                -1
            }
        }
    })
}

/// # Safety
/// `exec` must be a valid PpExec pointer or NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pp_exec_close_stdin(exec: *mut PpExec) -> i32 {
    clear_last_error();
    ffi_catch!(-1, {
        if exec.is_null() {
            set_last_error("exec handle is NULL");
            return -1;
        }
        if in_async_context() {
            return -1;
        }
        let exec = unsafe { &*exec };
        // Signal EOF to the guest. Idempotent: a second close (relay already
        // gone) is a no-op.
        let _ = exec.inner.tokio_rt.block_on(exec.io.close_stdin());
        0
    })
}

/// # Safety
/// `exec` must be a valid PpExec pointer or NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pp_exec_signal(exec: *mut PpExec, signum: i32) -> i32 {
    clear_last_error();
    ffi_catch!(-1, {
        if exec.is_null() {
            set_last_error("exec handle is NULL");
            return -1;
        }
        if in_async_context() {
            return -1;
        }
        let exec = unsafe { &*exec };
        match exec.inner.tokio_rt.block_on(exec.io.signal(signum)) {
            Ok(()) => 0,
            Err(_) => {
                set_last_error("control channel closed");
                -1
            }
        }
    })
}

/// # Safety
/// `exec` must be a valid PpExec pointer or NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pp_exec_resize(exec: *mut PpExec, cols: u16, rows: u16) -> i32 {
    clear_last_error();
    ffi_catch!(-1, {
        if exec.is_null() {
            set_last_error("exec handle is NULL");
            return -1;
        }
        if in_async_context() {
            return -1;
        }
        let exec = unsafe { &*exec };
        match exec.inner.tokio_rt.block_on(exec.io.resize(cols, rows)) {
            Ok(()) => 0,
            Err(_) => {
                set_last_error("control channel closed");
                -1
            }
        }
    })
}

/// # Safety
/// `handle` must be a valid PpExec pointer from `pp_sandbox_exec`, or NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pp_exec_free(handle: *mut PpExec) {
    ffi_catch!((), {
        if !handle.is_null() {
            drop(unsafe { Box::from_raw(handle) });
        }
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn pp_last_error() -> *const c_char {
    ffi_catch!(std::ptr::null(), {
        LAST_ERROR.with(|e| match e.borrow().as_ref() {
            Some(cs) => cs.as_ptr(),
            None => std::ptr::null(),
        })
    })
}

/// # Safety
/// `s` must be a pointer returned by a pp_* function, or NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pp_string_free(s: *mut c_char) {
    ffi_catch!((), {
        if !s.is_null() {
            drop(unsafe { CString::from_raw(s) });
        }
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn pp_version() -> *const c_char {
    ffi_catch!(std::ptr::null(), {
        static VERSION: std::sync::LazyLock<CString> = std::sync::LazyLock::new(|| {
            CString::new(crate::version()).expect("version has no null bytes")
        });
        VERSION.as_ptr()
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_contains_all_exported_symbols() {
        let header = include_str!("../include/playpencil.h");
        let symbols = [
            "pp_runtime_new",
            "pp_runtime_free",
            "pp_sandbox_create",
            "pp_sandbox_create_and_start",
            "pp_sandbox_start",
            "pp_sandbox_stop",
            "pp_sandbox_destroy",
            "pp_sandbox_status",
            "pp_sandbox_free",
            "pp_sandbox_exec",
            "pp_exec_next_event",
            "pp_exec_write_stdin",
            "pp_exec_close_stdin",
            "pp_exec_signal",
            "pp_exec_resize",
            "pp_exec_free",
            "pp_last_error",
            "pp_string_free",
            "pp_version",
        ];
        for sym in &symbols {
            assert!(header.contains(sym), "header is missing symbol: {sym}");
        }
    }

    #[test]
    fn test_last_error_roundtrip() {
        clear_last_error();
        assert!(pp_last_error().is_null());
        set_last_error("test error");
        let ptr = pp_last_error();
        assert!(!ptr.is_null());
        let msg = unsafe { CStr::from_ptr(ptr) }.to_str().unwrap();
        assert_eq!(msg, "test error");
        clear_last_error();
        assert!(pp_last_error().is_null());
    }

    #[test]
    fn test_null_handle_safety() {
        unsafe {
            pp_runtime_free(std::ptr::null_mut());
            pp_sandbox_free(std::ptr::null_mut());
            pp_exec_free(std::ptr::null_mut());
            pp_string_free(std::ptr::null_mut());
        }
    }

    #[test]
    fn test_exec_event_json_stdout() {
        let event = ExecEvent::Stdout(b"hello".to_vec());
        let json = exec_event_to_json(&event);
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["type"], "stdout");
        assert_eq!(v["data"], crate::util::base64_encode(b"hello"));
    }

    #[test]
    fn test_exec_event_json_exit() {
        let event = ExecEvent::Exit { code: 42 };
        let json = exec_event_to_json(&event);
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["type"], "exit");
        assert_eq!(v["code"], 42);
    }

    #[test]
    fn test_create_null_runtime() {
        unsafe {
            let sb = pp_sandbox_create(std::ptr::null_mut(), std::ptr::null());
            assert!(sb.is_null());
            assert!(!pp_last_error().is_null());
        }
    }

    #[test]
    fn test_start_null_sandbox() {
        unsafe {
            assert_eq!(pp_sandbox_start(std::ptr::null_mut()), -1);
            assert!(!pp_last_error().is_null());
        }
    }

    #[test]
    fn test_version_returns_valid_string() {
        let ptr = pp_version();
        assert!(!ptr.is_null());
        let s = unsafe { CStr::from_ptr(ptr) }.to_str().unwrap();
        assert!(!s.is_empty());
    }

    #[test]
    fn test_clear_on_entry() {
        // Result-returning functions clear last_error on entry.
        // pp_sandbox_start(NULL) sets an error, then a second call clears it.
        unsafe {
            pp_sandbox_start(std::ptr::null_mut());
            assert!(!pp_last_error().is_null());
            // Another result-returning call clears the stale error
            pp_sandbox_stop(std::ptr::null_mut());
            let err = CStr::from_ptr(pp_last_error()).to_str().unwrap();
            assert_eq!(err, "sandbox handle is NULL");
        }
    }

    #[test]
    fn test_exec_null_handle_returns_error() {
        unsafe {
            assert_eq!(
                pp_exec_write_stdin(std::ptr::null_mut(), std::ptr::null(), 0),
                -1
            );
            assert!(!pp_last_error().is_null());

            assert_eq!(pp_exec_close_stdin(std::ptr::null_mut()), -1);
            assert!(!pp_last_error().is_null());

            assert_eq!(pp_exec_signal(std::ptr::null_mut(), 15), -1);
            assert!(!pp_last_error().is_null());

            assert_eq!(pp_exec_resize(std::ptr::null_mut(), 80, 24), -1);
            assert!(!pp_last_error().is_null());

            let event = pp_exec_next_event(std::ptr::null_mut());
            assert!(event.is_null());
            assert!(!pp_last_error().is_null());
        }
    }
}
