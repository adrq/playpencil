//! The HTTP exec faces. The transport-neutral consumer-edge helpers
//! (`Utf8StreamDecoder`, `spawn_escalation`) live in `pipemux::consumer`;
//! these modules are the axum SSE/WS transports that drive them.

pub(crate) mod command;
pub(crate) mod duplex;
