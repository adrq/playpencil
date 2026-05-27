use std::collections::HashMap;
use std::time::{Duration, Instant};

use futures_util::StreamExt;
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;

use super::ImageReference;
use super::OciError;

const DOCKER_AUTH_URL: &str = "https://auth.docker.io/token";
const MAX_MANIFEST_SIZE: usize = 10 * 1024 * 1024;

const ACCEPT_MANIFEST: &str = "\
    application/vnd.oci.image.manifest.v1+json, \
    application/vnd.oci.image.index.v1+json, \
    application/vnd.docker.distribution.manifest.v2+json, \
    application/vnd.docker.distribution.manifest.list.v2+json";

struct CachedToken {
    token: String,
    expires_at: Instant,
}

pub struct RegistryClient {
    http: reqwest::Client,
    tokens: HashMap<String, CachedToken>,
}

fn registry_base_url(image: &ImageReference) -> String {
    let host = image.resolve_registry();
    let host = if host == "index.docker.io" {
        "registry-1.docker.io"
    } else {
        host
    };
    format!("https://{host}")
}

fn is_docker_hub(image: &ImageReference) -> bool {
    image.registry() == "docker.io"
}

fn manifest_ref(image: &ImageReference) -> &str {
    if let Some(d) = image.digest() {
        d
    } else if let Some(t) = image.tag() {
        t
    } else {
        "latest"
    }
}

fn token_key(image: &ImageReference) -> String {
    format!("{}/{}", image.resolve_registry(), image.repository())
}

impl RegistryClient {
    pub fn new() -> Result<Self, OciError> {
        let http = reqwest::Client::builder()
            .user_agent("playpencil/0.1")
            .timeout(Duration::from_secs(300))
            .build()?;
        Ok(Self {
            http,
            tokens: HashMap::new(),
        })
    }

    /// Resolve an image reference to a platform-specific manifest and its digest.
    pub async fn resolve_manifest(
        &mut self,
        image: &ImageReference,
    ) -> Result<(oci_spec::image::ImageManifest, String), OciError> {
        self.ensure_auth(image).await?;

        let base = registry_base_url(image);
        let url = format!(
            "{base}/v2/{}/manifests/{}",
            image.repository(),
            manifest_ref(image)
        );

        let resp = self.authed_get(image, &url, Some(ACCEPT_MANIFEST)).await?;
        let status = resp.status();
        if status == reqwest::StatusCode::NOT_FOUND {
            return Err(OciError::ManifestNotFound {
                reference: image.to_string(),
            });
        }
        if !status.is_success() {
            return Err(OciError::Registry {
                url,
                status: status.as_u16(),
            });
        }

        let content_type = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        let body = resp.bytes().await?;
        if body.len() > MAX_MANIFEST_SIZE {
            return Err(OciError::Extraction(format!(
                "manifest exceeds {}MB size limit",
                MAX_MANIFEST_SIZE / 1024 / 1024
            )));
        }
        let digest = format!("sha256:{:x}", Sha256::digest(&body));

        if let Some(expected) = image.digest()
            && digest != expected
        {
            return Err(OciError::DigestMismatch {
                expected: expected.to_string(),
                actual: digest,
            });
        }

        if is_index_media_type(&content_type) {
            let index: oci_spec::image::ImageIndex = serde_json::from_slice(&body)?;
            let platform_digest = select_platform(&index)?;

            let manifest_url = format!(
                "{base}/v2/{}/manifests/{platform_digest}",
                image.repository(),
            );
            let resp2 = self
                .authed_get(image, &manifest_url, Some(ACCEPT_MANIFEST))
                .await?;
            if !resp2.status().is_success() {
                return Err(OciError::Registry {
                    url: manifest_url,
                    status: resp2.status().as_u16(),
                });
            }
            let body2 = resp2.bytes().await?;
            if body2.len() > MAX_MANIFEST_SIZE {
                return Err(OciError::Extraction(format!(
                    "manifest exceeds {}MB size limit",
                    MAX_MANIFEST_SIZE / 1024 / 1024
                )));
            }
            let digest2 = format!("sha256:{:x}", Sha256::digest(&body2));
            if digest2 != platform_digest {
                return Err(OciError::DigestMismatch {
                    expected: platform_digest,
                    actual: digest2,
                });
            }
            let manifest: oci_spec::image::ImageManifest = serde_json::from_slice(&body2)?;
            Ok((manifest, digest2))
        } else if is_manifest_media_type(&content_type) {
            let manifest: oci_spec::image::ImageManifest = serde_json::from_slice(&body)?;
            Ok((manifest, digest))
        } else {
            Err(OciError::UnsupportedMediaType(content_type))
        }
    }

    /// Download a blob by digest, streaming to a writer.
    /// Verifies sha256 and enforces `expected_size`.
    pub async fn pull_blob(
        &mut self,
        image: &ImageReference,
        digest: &str,
        expected_size: u64,
        dest: &mut (impl tokio::io::AsyncWrite + Unpin),
    ) -> Result<u64, OciError> {
        self.ensure_auth(image).await?;

        let base = registry_base_url(image);
        let url = format!("{base}/v2/{}/blobs/{digest}", image.repository());

        let resp = self.authed_get(image, &url, None).await?;
        if !resp.status().is_success() {
            return Err(OciError::Registry {
                url,
                status: resp.status().as_u16(),
            });
        }

        let mut hasher = Sha256::new();
        let mut total: u64 = 0;
        let mut stream = resp.bytes_stream();
        while let Some(chunk_result) = stream.next().await {
            let chunk = chunk_result?;
            total += chunk.len() as u64;
            if total > expected_size {
                return Err(OciError::Extraction(format!(
                    "blob exceeds expected size {expected_size}: received {total}+ bytes"
                )));
            }
            hasher.update(&chunk);
            dest.write_all(&chunk).await?;
        }
        dest.flush().await?;

        if total != expected_size {
            return Err(OciError::Extraction(format!(
                "blob size mismatch: expected {expected_size}, got {total}"
            )));
        }

        let actual = format!("sha256:{:x}", hasher.finalize());
        if actual != digest {
            return Err(OciError::DigestMismatch {
                expected: digest.to_string(),
                actual,
            });
        }

        Ok(total)
    }

    async fn ensure_auth(&mut self, image: &ImageReference) -> Result<(), OciError> {
        let key = token_key(image);
        if let Some(cached) = self.tokens.get(&key)
            && cached.expires_at > Instant::now()
        {
            return Ok(());
        }
        self.authenticate(image).await?;
        Ok(())
    }

    async fn authenticate(&mut self, image: &ImageReference) -> Result<(), OciError> {
        let key = token_key(image);
        let registry = image.resolve_registry();
        let repository = image.repository();

        if is_docker_hub(image) {
            let mut token_url = url::Url::parse(DOCKER_AUTH_URL).map_err(|_| OciError::Auth {
                registry: registry.to_string(),
            })?;
            token_url
                .query_pairs_mut()
                .append_pair("service", "registry.docker.io")
                .append_pair("scope", &format!("repository:{repository}:pull"));

            let resp = self.http.get(token_url).send().await?;
            if !resp.status().is_success() {
                return Err(OciError::Auth {
                    registry: registry.to_string(),
                });
            }
            let body: serde_json::Value = resp.json().await?;
            let token = body["token"]
                .as_str()
                .or_else(|| body["access_token"].as_str())
                .ok_or_else(|| OciError::Auth {
                    registry: registry.to_string(),
                })?
                .to_string();

            let expires_in = body["expires_in"].as_u64().unwrap_or(300);
            self.tokens.insert(
                key,
                CachedToken {
                    token,
                    expires_at: Instant::now() + Duration::from_secs(expires_in.saturating_sub(30)),
                },
            );
            return Ok(());
        }

        // Generic registry: probe /v2/, parse Www-Authenticate on 401
        let base_url = format!("https://{registry}");
        let resp = self.http.get(format!("{base_url}/v2/")).send().await?;

        if resp.status() == reqwest::StatusCode::OK {
            self.tokens.insert(
                key,
                CachedToken {
                    token: String::new(),
                    expires_at: Instant::now() + Duration::from_secs(3600),
                },
            );
            return Ok(());
        }

        if resp.status() != reqwest::StatusCode::UNAUTHORIZED {
            return Err(OciError::Auth {
                registry: registry.to_string(),
            });
        }

        let www_auth = resp
            .headers()
            .get("www-authenticate")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");

        let (realm, service) = parse_www_authenticate(www_auth);
        if realm.is_empty() {
            return Err(OciError::Auth {
                registry: registry.to_string(),
            });
        }

        let mut token_url = url::Url::parse(&realm).map_err(|_| OciError::Auth {
            registry: registry.to_string(),
        })?;
        token_url
            .query_pairs_mut()
            .append_pair("scope", &format!("repository:{repository}:pull"));
        if !service.is_empty() {
            token_url.query_pairs_mut().append_pair("service", &service);
        }

        let token_resp = self.http.get(token_url).send().await?;
        if !token_resp.status().is_success() {
            return Err(OciError::Auth {
                registry: registry.to_string(),
            });
        }

        let body: serde_json::Value = token_resp.json().await?;
        let token = body["token"]
            .as_str()
            .or_else(|| body["access_token"].as_str())
            .ok_or_else(|| OciError::Auth {
                registry: registry.to_string(),
            })?
            .to_string();

        let expires_in = body["expires_in"].as_u64().unwrap_or(300);
        self.tokens.insert(
            key,
            CachedToken {
                token,
                expires_at: Instant::now() + Duration::from_secs(expires_in.saturating_sub(30)),
            },
        );

        Ok(())
    }

    async fn authed_get(
        &self,
        image: &ImageReference,
        url: &str,
        accept: Option<&str>,
    ) -> Result<reqwest::Response, OciError> {
        let key = token_key(image);
        let mut req = self.http.get(url);
        if let Some(accept) = accept {
            req = req.header("Accept", accept);
        }
        if let Some(cached) = self.tokens.get(&key)
            && !cached.token.is_empty()
        {
            req = req.header("Authorization", format!("Bearer {}", cached.token));
        }
        Ok(req.send().await?)
    }
}

fn host_arch() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => other,
    }
}

fn select_platform(index: &oci_spec::image::ImageIndex) -> Result<String, OciError> {
    let wanted_arch = host_arch();
    let wanted = format!("linux/{wanted_arch}");

    for manifest in index.manifests() {
        if let Some(platform) = manifest.platform() {
            let os = platform.os().to_string();
            let arch = platform.architecture().to_string();
            if os == "linux" && arch == wanted_arch {
                let digest = manifest.digest().to_string();
                return Ok(digest);
            }
        }
    }

    Err(OciError::NoPlatformMatch { wanted })
}

fn is_index_media_type(ct: &str) -> bool {
    ct.contains("image.index") || ct.contains("manifest.list")
}

fn is_manifest_media_type(ct: &str) -> bool {
    ct.contains("image.manifest") || ct.contains("distribution.manifest.v2")
}

fn parse_www_authenticate(header: &str) -> (String, String) {
    let header = header.strip_prefix("Bearer ").unwrap_or(header);

    let mut realm = String::new();
    let mut service = String::new();

    for part in header.split(',') {
        let part = part.trim();
        if let Some(val) = part.strip_prefix("realm=") {
            realm = val.trim_matches('"').to_string();
        } else if let Some(val) = part.strip_prefix("service=") {
            service = val.trim_matches('"').to_string();
        }
    }

    (realm, service)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_arch_returns_expected_value() {
        let arch = host_arch();
        #[cfg(target_arch = "x86_64")]
        assert_eq!(arch, "amd64");
        #[cfg(target_arch = "aarch64")]
        assert_eq!(arch, "arm64");
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        assert_eq!(arch, std::env::consts::ARCH);
    }

    #[test]
    fn parse_www_authenticate_standard() {
        let header = r#"Bearer realm="https://auth.example.com/token",service="registry.example.com",scope="repository:org/repo:pull""#;
        let (realm, service) = parse_www_authenticate(header);
        assert_eq!(realm, "https://auth.example.com/token");
        assert_eq!(service, "registry.example.com");
    }

    #[test]
    fn parse_www_authenticate_empty() {
        let (realm, service) = parse_www_authenticate("");
        assert!(realm.is_empty());
        assert!(service.is_empty());
    }

    #[test]
    fn is_index_detects_oci_index() {
        assert!(is_index_media_type(
            "application/vnd.oci.image.index.v1+json"
        ));
        assert!(is_index_media_type(
            "application/vnd.docker.distribution.manifest.list.v2+json"
        ));
        assert!(!is_index_media_type(
            "application/vnd.oci.image.manifest.v1+json"
        ));
    }

    #[test]
    fn is_manifest_detects_oci_manifest() {
        assert!(is_manifest_media_type(
            "application/vnd.oci.image.manifest.v1+json"
        ));
        assert!(is_manifest_media_type(
            "application/vnd.docker.distribution.manifest.v2+json"
        ));
        assert!(!is_manifest_media_type(
            "application/vnd.oci.image.index.v1+json"
        ));
    }

    #[test]
    fn registry_base_url_docker_hub() {
        let image: ImageReference = "ubuntu:22.04".parse().unwrap();
        assert_eq!(registry_base_url(&image), "https://registry-1.docker.io");
    }

    #[test]
    fn registry_base_url_ghcr() {
        let image: ImageReference = "ghcr.io/org/image:v1".parse().unwrap();
        assert_eq!(registry_base_url(&image), "https://ghcr.io");
    }

    #[test]
    fn manifest_ref_uses_tag() {
        let image: ImageReference = "ubuntu:22.04".parse().unwrap();
        assert_eq!(manifest_ref(&image), "22.04");
    }
}
