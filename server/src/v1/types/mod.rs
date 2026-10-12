//! Wire types of the `/v1` API.

pub(crate) mod capabilities;
pub(crate) mod command;
pub(crate) mod config;
pub(crate) mod event;
pub(crate) mod network;
pub(crate) mod open_union;
pub(crate) mod problem;
pub(crate) mod process;
pub(crate) mod query;
pub(crate) mod sandbox;
pub(crate) mod serde_util;

#[cfg(test)]
mod tests;
