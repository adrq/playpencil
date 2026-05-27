pub mod cache;
pub mod client;
pub mod extract;

pub use cache::ImageCache;
pub use client::RegistryClient;
pub use extract::LayerCompression;
pub use oci_spec::distribution::Reference as ImageReference;

#[derive(Debug, thiserror::Error)]
pub enum OciError {
    #[error("invalid image reference: {0}")]
    InvalidReference(String),

    #[error("registry error: {status} from {url}")]
    Registry { url: String, status: u16 },

    #[error("authentication failed for {registry}")]
    Auth { registry: String },

    #[error("manifest not found for {reference}")]
    ManifestNotFound { reference: String },

    #[error("no matching platform in manifest list (wanted {wanted})")]
    NoPlatformMatch { wanted: String },

    #[error("digest mismatch: expected {expected}, got {actual}")]
    DigestMismatch { expected: String, actual: String },

    #[error("unsupported media type: {0}")]
    UnsupportedMediaType(String),

    #[error("layer extraction failed: {0}")]
    Extraction(String),

    #[error("unsafe tar entry: {0}")]
    UnsafeTarEntry(String),

    #[error(transparent)]
    Http(#[from] reqwest::Error),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Json(#[from] serde_json::Error),
}
