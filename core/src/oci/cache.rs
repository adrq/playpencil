use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use super::ImageReference;
use super::OciError;
use super::client::RegistryClient;
use super::extract::{LayerCompression, extract_layer};

pub struct ImageCache {
    base_dir: PathBuf,
}

/// Guard that removes a temp directory on drop unless disarmed.
struct TmpGuard {
    path: Option<PathBuf>,
}

impl TmpGuard {
    fn new(path: PathBuf) -> Self {
        Self { path: Some(path) }
    }

    fn disarm(&mut self) {
        self.path = None;
    }
}

impl Drop for TmpGuard {
    fn drop(&mut self) {
        if let Some(path) = &self.path {
            let _ = fs::remove_dir_all(path);
        }
    }
}

/// Validate that a digest is exactly `sha256:<64 lowercase hex chars>`.
fn validate_digest(digest: &str) -> Result<&str, OciError> {
    let hex = digest.strip_prefix("sha256:").ok_or_else(|| {
        OciError::InvalidReference(format!("digest must start with sha256: — got: {digest}"))
    })?;
    if hex.len() != 64
        || !hex
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    {
        return Err(OciError::InvalidReference(format!(
            "invalid sha256 digest: {digest}"
        )));
    }
    Ok(hex)
}

impl ImageCache {
    /// Create a new image cache rooted at `<data_dir>/images/`.
    /// Cleans stale entries from `tmp/` on construction.
    pub fn new(data_dir: &Path) -> Self {
        let base_dir = data_dir.join("images");
        let cache = Self { base_dir };
        cache.clean_stale_tmp();
        cache
    }

    /// Returns the rootfs path if the image is already cached by manifest digest.
    /// `digest` should be in the form `sha256:<hex>`.
    pub fn get(&self, digest: &str) -> Option<PathBuf> {
        let hex = validate_digest(digest).ok()?;
        let rootfs = self.base_dir.join("sha256").join(hex).join("rootfs");
        if rootfs.is_dir() { Some(rootfs) } else { None }
    }

    /// Pull an image if not cached, extract layers, and return the cached rootfs path.
    pub async fn ensure(
        &self,
        client: &mut RegistryClient,
        image: &ImageReference,
    ) -> Result<PathBuf, OciError> {
        // A digest-pinned reference names immutable content, so a cache hit is
        // definitionally the right bits: short-circuit before any network call.
        // The pinned digest must be the platform-specific manifest digest for the
        // host arch (our cache key); if it is something else (e.g. an index) the
        // lookup misses and we fall through to the normal resolve+pull. A tag
        // reference is mutable, so it always resolves to learn its current digest.
        if let Some(digest) = image.digest()
            && let Some(rootfs) = self.get(digest)
        {
            return Ok(rootfs);
        }

        let (manifest, digest) = client.resolve_manifest(image).await?;
        let hex = validate_digest(&digest)?;

        // Check cache after resolving (we now know the platform-specific digest)
        if let Some(rootfs) = self.get(&digest) {
            return Ok(rootfs);
        }

        // Set up temp working directory with cleanup guard
        let tmp_id = uuid_v4()?;
        let tmp_dir = self.base_dir.join("tmp").join(&tmp_id);
        let tmp_rootfs = tmp_dir.join("rootfs");
        let tmp_blobs = tmp_dir.join("blobs");
        fs::create_dir_all(&tmp_rootfs)?;
        fs::create_dir_all(&tmp_blobs)?;
        let mut guard = TmpGuard::new(tmp_dir.clone());

        // Download and extract each layer in order
        let layers = manifest.layers();
        for layer_desc in layers {
            let media_type = layer_desc.media_type().to_string();
            let compression = detect_layer_compression(&media_type)
                .ok_or_else(|| OciError::UnsupportedMediaType(media_type.clone()))?;

            let layer_digest = layer_desc.digest().to_string();
            let layer_size = layer_desc.size();
            let layer_hex = validate_digest(&layer_digest)?;

            let blob_path = tmp_blobs.join(layer_hex);

            // Download the blob
            let mut file = tokio::fs::File::create(&blob_path).await?;
            client
                .pull_blob(image, &layer_digest, layer_size, &mut file)
                .await?;

            // Extract synchronously (tar + fs operations)
            extract_layer(&blob_path, &tmp_rootfs, compression)?;

            // Remove the blob to save disk space
            let _ = fs::remove_file(&blob_path);
        }

        // Store manifest for debugging
        let manifest_json = serde_json::to_string_pretty(&manifest)?;
        fs::write(tmp_dir.join("manifest.json"), manifest_json)?;

        // Atomic commit: rename temp dir to final location
        let final_dir = self.base_dir.join("sha256").join(hex);
        if let Some(parent) = final_dir.parent() {
            fs::create_dir_all(parent)?;
        }

        match fs::rename(&tmp_dir, &final_dir) {
            Ok(()) => {
                guard.disarm();
            }
            Err(e) if final_dir.exists() => {
                tracing::debug!("concurrent pull won for {digest}: {e}");
                // guard will clean up tmp_dir on drop
                // Verify the existing entry is actually valid
                if self.get(&digest).is_none() {
                    return Err(OciError::Extraction(format!(
                        "cache entry exists but incomplete for {digest}"
                    )));
                }
            }
            Err(e) => {
                // guard will clean up tmp_dir on drop
                return Err(e.into());
            }
        }

        Ok(final_dir.join("rootfs"))
    }

    /// Remove a cached image by digest.
    pub fn evict(&self, digest: &str) -> Result<(), OciError> {
        let hex = validate_digest(digest)?;
        let dir = self.base_dir.join("sha256").join(hex);
        if dir.exists() {
            fs::remove_dir_all(&dir)?;
        }
        Ok(())
    }

    fn clean_stale_tmp(&self) {
        let tmp_dir = self.base_dir.join("tmp");
        let threshold = Duration::from_secs(3600);
        let now = SystemTime::now();
        if let Ok(entries) = fs::read_dir(&tmp_dir) {
            for entry in entries.flatten() {
                let dominated = entry
                    .metadata()
                    .ok()
                    .and_then(|m| m.modified().ok())
                    .is_some_and(|mtime| {
                        now.duration_since(mtime).unwrap_or(Duration::ZERO) >= threshold
                    });
                if dominated {
                    let _ = fs::remove_dir_all(entry.path());
                }
            }
        }
    }
}

fn detect_layer_compression(media_type: &str) -> Option<LayerCompression> {
    if media_type.contains("tar+gzip") || media_type.contains("tar.gzip") {
        Some(LayerCompression::Gzip)
    } else if media_type.contains("tar+zstd") {
        Some(LayerCompression::Zstd)
    } else if (media_type.contains(".tar") || media_type.contains("/tar"))
        && !media_type.contains('+')
    {
        Some(LayerCompression::None)
    } else {
        None
    }
}

fn uuid_v4() -> Result<String, OciError> {
    use std::io::Read;
    let mut bytes = [0u8; 16];
    let mut f = fs::File::open("/dev/urandom")?;
    f.read_exact(&mut bytes)?;
    // Set version 4 and variant bits
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Ok(format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15]
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_returns_none_for_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = ImageCache::new(tmp.path());
        assert!(
            cache
                .get("sha256:0000000000000000000000000000000000000000000000000000000000000000")
                .is_none()
        );
    }

    #[test]
    fn get_returns_some_after_manual_creation() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = ImageCache::new(tmp.path());
        let hex = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        let rootfs = tmp.path().join("images/sha256").join(hex).join("rootfs");
        fs::create_dir_all(&rootfs).unwrap();

        let result = cache.get(&format!("sha256:{hex}"));
        assert_eq!(result, Some(rootfs));
    }

    #[test]
    fn get_returns_none_for_invalid_prefix() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = ImageCache::new(tmp.path());
        assert!(cache.get("md5:abc").is_none());
    }

    #[test]
    fn get_rejects_traversal_digest() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = ImageCache::new(tmp.path());
        assert!(cache.get("sha256:../../../etc").is_none());
    }

    #[test]
    fn get_rejects_short_digest() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = ImageCache::new(tmp.path());
        assert!(cache.get("sha256:abcdef").is_none());
    }

    #[test]
    fn get_rejects_uppercase_digest() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = ImageCache::new(tmp.path());
        assert!(
            cache
                .get("sha256:ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789")
                .is_none()
        );
    }

    #[tokio::test]
    async fn ensure_digest_pinned_short_circuits_cache_without_network() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = ImageCache::new(tmp.path());
        let hex = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        let rootfs = tmp.path().join("images/sha256").join(hex).join("rootfs");
        fs::create_dir_all(&rootfs).unwrap();

        // Pin the cached digest behind an unreachable registry (127.0.0.1:1): any
        // resolve/pull would fail fast, so a successful return proves ensure()
        // returned the cached rootfs without touching the client at all.
        let image: ImageReference = format!("127.0.0.1:1/library/x@sha256:{hex}")
            .parse()
            .unwrap();
        let mut client = RegistryClient::new().unwrap();
        let result = cache.ensure(&mut client, &image).await.unwrap();
        assert_eq!(result, rootfs);
    }

    #[test]
    fn evict_removes_cached_entry() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = ImageCache::new(tmp.path());
        let hex = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        let rootfs = tmp.path().join("images/sha256").join(hex).join("rootfs");
        fs::create_dir_all(&rootfs).unwrap();

        cache.evict(&format!("sha256:{hex}")).unwrap();
        assert!(cache.get(&format!("sha256:{hex}")).is_none());
    }

    #[test]
    fn evict_rejects_traversal_digest() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = ImageCache::new(tmp.path());
        let result = cache.evict("sha256:../../../etc");
        assert!(result.is_err());
    }

    #[test]
    fn validate_digest_accepts_valid() {
        let hex = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        assert!(validate_digest(&format!("sha256:{hex}")).is_ok());
    }

    #[test]
    fn validate_digest_rejects_non_hex() {
        assert!(
            validate_digest(
                "sha256:zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
            )
            .is_err()
        );
    }

    #[test]
    fn validate_digest_rejects_wrong_length() {
        assert!(validate_digest("sha256:abcdef").is_err());
    }

    #[test]
    fn validate_digest_rejects_traversal() {
        assert!(validate_digest("sha256:../../../etc").is_err());
    }

    #[test]
    fn clean_stale_tmp_skips_recent_entries() {
        let tmp = tempfile::tempdir().unwrap();
        let recent = tmp.path().join("images/tmp/recent-session");
        fs::create_dir_all(&recent).unwrap();
        fs::write(recent.join("data"), "in-progress").unwrap();

        let _cache = ImageCache::new(tmp.path());

        assert!(recent.exists());
    }

    #[test]
    fn clean_stale_tmp_removes_old_entries() {
        use filetime::FileTime;

        let tmp = tempfile::tempdir().unwrap();
        let stale = tmp.path().join("images/tmp/stale-session");
        fs::create_dir_all(&stale).unwrap();
        fs::write(stale.join("junk"), "leftover").unwrap();

        let two_hours_ago = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 7200;
        let ft = FileTime::from_unix_time(two_hours_ago as i64, 0);
        filetime::set_file_mtime(&stale, ft).unwrap();

        let _cache = ImageCache::new(tmp.path());

        assert!(!stale.exists());
    }

    #[test]
    fn uuid_v4_format() {
        let id = uuid_v4().unwrap();
        assert_eq!(id.len(), 36);
        assert_eq!(id.chars().filter(|c| *c == '-').count(), 4);
    }

    #[test]
    fn detect_compression_gzip() {
        assert_eq!(
            detect_layer_compression("application/vnd.oci.image.layer.v1.tar+gzip"),
            Some(LayerCompression::Gzip)
        );
        assert_eq!(
            detect_layer_compression("application/vnd.docker.image.rootfs.diff.tar.gzip"),
            Some(LayerCompression::Gzip)
        );
    }

    #[test]
    fn detect_compression_zstd() {
        assert_eq!(
            detect_layer_compression("application/vnd.oci.image.layer.v1.tar+zstd"),
            Some(LayerCompression::Zstd)
        );
    }

    #[test]
    fn detect_compression_none() {
        assert_eq!(
            detect_layer_compression("application/vnd.oci.image.layer.v1.tar"),
            Some(LayerCompression::None)
        );
        assert_eq!(
            detect_layer_compression("application/vnd.docker.image.rootfs.diff.tar"),
            Some(LayerCompression::None)
        );
    }

    #[test]
    fn detect_compression_unknown() {
        assert_eq!(
            detect_layer_compression("application/vnd.oci.image.layer.v1.tar+encrypted"),
            None
        );
        assert_eq!(detect_layer_compression("application/octet-stream"), None);
    }
}
