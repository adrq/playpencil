//! Exec / process-I/O-multiplex capability for playpencil.
//!
//! This crate factors the exec machinery — running a command inside a guest,
//! multiplexing many concurrent execs over one transport, and the byte-exact
//! credit flow-control that keeps them bounded — into one cohesive unit. It is a
//! pure relocation of logic that previously lived spread across `init/`, `core/`,
//! and `server/`; the wire protocol and observable behavior are unchanged.
//!
//! # The four-capability model
//!
//! The crate is one cohesive unit with four capabilities, each behind a Cargo
//! feature (except [`protocol`], which is always on):
//!
//! - **[`protocol`]** (always on) — the wire frames ([`protocol::HostFrame`] /
//!   [`protocol::GuestFrame`]), the base64 [`protocol::codec`], and the
//!   flow-control [`protocol::limits`] that form the host/guest credit contract.
//!   Pure data + serde: no runtime, no libc, no tokio, platform-neutral.
//! - **producer** (`feature = "producer"`) — fork/exec children, multiplex them
//!   over one channel by string id, own their pipes, per-id input/output flow
//!   control, start-error semantics, credential drop, process-group signalling +
//!   reaping. `std` + `libc`, **no tokio**, cross-platform (Linux + macOS).
//!   Enabled by `init`.
//! - **relay** (`feature = "relay"`) — demux frames between one async transport
//!   and N per-id sessions; credit accounting; priority/bulk write scheduling;
//!   teardown. `tokio`, no libc. Mac-portable. Enabled by `core` (the libkrun
//!   backend).
//! - **consumer** (`feature = "consumer"`) — terminate the protocol: drive
//!   stdin/resize, decode output to text, release output credit. The reusable
//!   parts (incremental UTF-8 decode, TERM→KILL escalation, the `ExecHandle`
//!   driving API) live here; the transports (SSE/WS/C-ABI) stay in their edges.
//!   Enabled by `core` (the C ABI) and `server`.
//!
//! `host = ["relay", "consumer"]` is a convenience alias. The shared
//! `ExecHandle` type family is the relay↔consumer seam and compiles whenever
//! either is on.
//!
//! # Producer firewall (enforced only by the `init` musl build)
//!
//! **Producer code MUST NOT use tokio or any async runtime.** Because this is one
//! crate with feature unification, a whole-workspace `cargo build` (host target)
//! turns `tokio` ON (for `relay`/`consumer`) *and* compiles the `producer`
//! module, so a stray `use tokio` in producer code COMPILES on the host — the
//! compiler will not catch it there. The real guard is the `init` musl-target
//! build (`make build` / `make check-exec-features`): `init` enables ONLY
//! `producer`, so tokio is absent and a violation fails to link. Do not "fix" a
//! producer file by reaching for tokio; keep it `std`+`libc`, sync.
//!
//! # Feature gating is by feature, not `target_os`
//!
//! Gating is by FEATURE to keep each consumer minimal (init pulls only
//! `producer`, no tokio). It is NOT `target_os`-gated: the producer is
//! cross-platform (Linux + macOS), and the `ExecHandle` type family must stay
//! macOS-compilable because `core` compiles it unconditionally today. Whole-
//! workspace `make check` is already Linux-only because `init` itself is — that
//! predates this crate and is unrelated to the gating here.

#![cfg_attr(not(feature = "producer"), forbid(unsafe_code))]

// Crate-owned POSIX signal numbers. Defined here (not via `libc`) so the `relay`
// and `consumer` capabilities — which classify cancellation escalation by signal
// — stay libc-free; `make check-exec-features` asserts libc is absent from their
// dependency graphs. The integers are identical to the libc constants.
/// Interrupt (libc `SIGINT`).
pub const SIGINT: i32 = 2;
/// Terminate (libc `SIGTERM`).
pub const SIGTERM: i32 = 15;
/// Kill (libc `SIGKILL`).
pub const SIGKILL: i32 = 9;

pub mod protocol;

#[cfg(feature = "producer")]
pub mod producer;

#[cfg(feature = "relay")]
pub mod relay;

#[cfg(feature = "consumer")]
pub mod consumer;

// The shared ExecHandle/ExecIo/ExecEvent type family is the relay↔consumer seam:
// the relay builds a handle in `open`, the consumer drives it. Compiled whenever
// either capability is on; tokio is enabled by either.
#[cfg(any(feature = "relay", feature = "consumer"))]
pub mod handle;
