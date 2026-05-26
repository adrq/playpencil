pub mod backend;
pub mod krun;
pub mod lifecycle;
pub mod types;

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
