/*
 * playpencil C ABI — sandbox lifecycle and exec operations.
 *
 * Platform: Linux x86_64 with KVM.
 *
 * Ownership rules:
 *   - Handles returned by pp_*() are heap-allocated. Free with the matching
 *     pp_*_free() function. All free functions accept NULL (no-op).
 *   - Strings returned as char* must be freed with pp_string_free().
 *   - Input strings (const char*) are borrowed for the duration of the call.
 *   - pp_version() returns a static pointer — do not free.
 *   - pp_last_error() returns a thread-local pointer valid until the next
 *     pp_* call on the same thread.
 *
 * Lifetime:
 *   Child handles (PpSandbox, PpExec) hold internal Arc references to the
 *   runtime, so freeing PpRuntime while children exist is safe — resources
 *   stay alive until the last handle is freed. Callers should still free
 *   children before the runtime as a matter of hygiene.
 *
 *   Freeing a PpSandbox without calling pp_sandbox_destroy first leaks the
 *   backend record (the sandbox becomes unreachable but stays in memory).
 *
 *   Destroying a sandbox while exec handles exist closes exec channels.
 *   Blocked pp_exec_next_event() calls return NULL (normal EOF).
 *
 * Thread safety:
 *   Handles are usable from multiple threads with external synchronization.
 *   Internal Mutex serializes concurrent pp_exec_next_event() calls.
 *   pp_*_free() and pp_sandbox_destroy() must not race other operations
 *   on the same handle.
 *
 * Error handling:
 *   Result-returning pp_* functions clear the thread-local error on entry.
 *   Free functions (pp_*_free, pp_string_free) do NOT clear the error,
 *   so callers can safely read pp_last_error() then free handles.
 *   Functions returning pointers return NULL on error.
 *   Functions returning int return 0 on success, -1 on error.
 *   After an error, pp_last_error() has the detail string.
 *   For pp_exec_next_event() returning NULL: pp_last_error()==NULL means
 *   normal EOF, non-NULL means error.
 *
 * Must NOT be called from within a tokio async context (block_on panics).
 */

#ifndef PLAYPENCIL_H
#define PLAYPENCIL_H

#ifndef __linux__
#error "playpencil C ABI is only supported on Linux"
#endif

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Opaque handle types */
typedef struct PpRuntime PpRuntime;
typedef struct PpSandbox PpSandbox;
typedef struct PpExec PpExec;

/* ---- Runtime ---- */

/*
 * Create a new runtime with a libkrun backend.
 * config_json: UTF-8 JSON with required fields:
 *   - "data_dir": path to data directory
 *   - "init_binary": path to playpencil-init binary
 * Returns NULL on failure.
 */
PpRuntime *pp_runtime_new(const char *config_json);

/* Free the runtime handle. NULL is a no-op. */
void pp_runtime_free(PpRuntime *handle);

/* ---- Sandbox ---- */

/*
 * Create a sandbox. config_json is a UTF-8 JSON matching SandboxConfig.
 * Returns NULL on failure.
 */
PpSandbox *pp_sandbox_create(PpRuntime *rt, const char *config_json);

/* Start the sandbox VM. Returns 0 on success, -1 on error. */
int pp_sandbox_start(PpSandbox *sb);

/* Stop the sandbox VM. Returns 0 on success, -1 on error. */
int pp_sandbox_stop(PpSandbox *sb);

/* Destroy the sandbox and release backend resources (async teardown).
 * Separate from pp_sandbox_free because destroy involves async backend
 * cleanup (stopping the VM, unmounting rootfs) while free only reclaims
 * the handle's heap allocation. */
int pp_sandbox_destroy(PpSandbox *sb);

/*
 * Get sandbox status as a JSON string.
 * Caller must free with pp_string_free(). Returns NULL on error.
 */
char *pp_sandbox_status(PpSandbox *sb);

/*
 * Free the sandbox handle (heap reclamation only). Does NOT destroy
 * the sandbox — call pp_sandbox_destroy first to avoid leaking
 * backend resources. NULL is a no-op.
 */
void pp_sandbox_free(PpSandbox *handle);

/* ---- Exec ---- */

/*
 * Start an exec session. cmd_json is a UTF-8 JSON matching ExecRequest.
 * Returns NULL on failure.
 */
PpExec *pp_sandbox_exec(PpSandbox *sb, const char *cmd_json);

/*
 * Block until the next exec event. May block indefinitely until an event
 * arrives or the stream closes. Concurrent calls on the same handle
 * serialize on an internal mutex for the full blocking duration —
 * use a dedicated reader thread per exec handle. Returns a JSON string:
 *   {"type":"stdout","data":"<base64>"} or
 *   {"type":"stderr","data":"<base64>"} or
 *   {"type":"exit","code":<int>}
 * Returns NULL on EOF (stream closed) or error.
 * Check pp_last_error() to distinguish: NULL=EOF, non-NULL=error.
 * Caller must free with pp_string_free().
 */
char *pp_exec_next_event(PpExec *exec);

/* Write bytes to the exec session's stdin. */
int pp_exec_write_stdin(PpExec *exec, const uint8_t *data, size_t len);

/* Close stdin, signaling EOF to the guest process. Idempotent. */
int pp_exec_close_stdin(PpExec *exec);

/* Send a signal to the exec session. */
int pp_exec_signal(PpExec *exec, int signum);

/* Send a terminal resize to the exec session. */
int pp_exec_resize(PpExec *exec, uint16_t cols, uint16_t rows);

/* Free the exec handle. NULL is a no-op. */
void pp_exec_free(PpExec *handle);

/* ---- Error / utility ---- */

/*
 * Get the last error message for the current thread.
 * Returns NULL if no error. Valid until the next pp_* call on this thread.
 */
const char *pp_last_error(void);

/* Free a string returned by any pp_* function. NULL is a no-op. */
void pp_string_free(char *s);

/* Get the library version string. Do not free.
 * Does not clear pp_last_error (always succeeds). */
const char *pp_version(void);

#ifdef __cplusplus
}
#endif

#endif /* PLAYPENCIL_H */
