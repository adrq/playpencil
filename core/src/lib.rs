pub mod backend;
#[cfg(target_os = "linux")]
pub(crate) mod ffi;
pub mod krun;
pub mod lifecycle;
pub mod net;
pub mod oci;
pub mod rootfs;
pub mod types;

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
