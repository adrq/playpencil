use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;

fn normalize_domain(domain: &str) -> String {
    domain
        .to_ascii_lowercase()
        .trim_end_matches('.')
        .to_string()
}

/// Enforces domain-based network allowlisting with bidirectional IP tracking.
///
/// IPs are allowed as long as at least one allowed domain still resolves to them.
/// This handles CDN scenarios where multiple domains share IPs.
pub struct PolicyEngine {
    allowed_domains: Vec<String>,
    gateway_ip: Ipv4Addr,
    /// domain → current resolved IPs
    domain_ips: HashMap<String, HashSet<Ipv4Addr>>,
    /// IP → set of domains that resolve to it (refcount)
    ip_domains: HashMap<Ipv4Addr, HashSet<String>>,
}

impl PolicyEngine {
    pub fn new(allowed_domains: Vec<String>, gateway_ip: Ipv4Addr) -> Self {
        let normalized: Vec<String> = allowed_domains
            .into_iter()
            .map(|d| normalize_domain(&d))
            .collect();
        Self {
            allowed_domains: normalized,
            gateway_ip,
            domain_ips: HashMap::new(),
            ip_domains: HashMap::new(),
        }
    }

    pub fn is_domain_allowed(&self, domain: &str) -> bool {
        let norm = normalize_domain(domain);
        self.allowed_domains
            .iter()
            .any(|allowed| norm == *allowed || norm.ends_with(&format!(".{allowed}")))
    }

    /// Update the IP set for a domain. Removes stale IPs that no other domain references.
    pub fn register_resolved_ips(&mut self, domain: &str, new_ips: &[Ipv4Addr]) {
        let norm = normalize_domain(domain);
        let new_set: HashSet<Ipv4Addr> = new_ips.iter().copied().collect();

        // Remove old IPs that are no longer in the new set
        if let Some(old_ips) = self.domain_ips.get(&norm) {
            for old_ip in old_ips {
                if !new_set.contains(old_ip)
                    && let Some(domains) = self.ip_domains.get_mut(old_ip)
                {
                    domains.remove(&norm);
                    if domains.is_empty() {
                        self.ip_domains.remove(old_ip);
                    }
                }
            }
        }

        // Add new IPs
        for &ip in &new_set {
            self.ip_domains.entry(ip).or_default().insert(norm.clone());
        }

        self.domain_ips.insert(norm, new_set);
    }

    pub fn is_ip_allowed(&self, ip: &Ipv4Addr) -> bool {
        *ip == self.gateway_ip || ip.is_loopback() || self.ip_domains.contains_key(ip)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn engine(domains: &[&str]) -> PolicyEngine {
        PolicyEngine::new(
            domains.iter().map(|s| s.to_string()).collect(),
            Ipv4Addr::new(10, 0, 2, 1),
        )
    }

    #[test]
    fn test_exact_domain_match() {
        let e = engine(&["example.com"]);
        assert!(e.is_domain_allowed("example.com"));
    }

    #[test]
    fn test_subdomain_match() {
        let e = engine(&["example.com"]);
        assert!(e.is_domain_allowed("sub.example.com"));
        assert!(e.is_domain_allowed("deep.sub.example.com"));
    }

    #[test]
    fn test_unrelated_domain_blocked() {
        let e = engine(&["example.com"]);
        assert!(!e.is_domain_allowed("notexample.com"));
        assert!(!e.is_domain_allowed("evil.com"));
    }

    #[test]
    fn test_case_insensitive() {
        let e = engine(&["Example.COM"]);
        assert!(e.is_domain_allowed("example.com"));
        assert!(e.is_domain_allowed("EXAMPLE.COM"));
        assert!(e.is_domain_allowed("sub.Example.com"));
    }

    #[test]
    fn test_register_and_check_ip() {
        let mut e = engine(&["example.com"]);
        let ip = Ipv4Addr::new(93, 184, 216, 34);
        e.register_resolved_ips("example.com", &[ip]);
        assert!(e.is_ip_allowed(&ip));
    }

    #[test]
    fn test_gateway_ip_always_allowed() {
        let e = engine(&[]);
        assert!(e.is_ip_allowed(&Ipv4Addr::new(10, 0, 2, 1)));
    }

    #[test]
    fn test_loopback_always_allowed() {
        let e = engine(&[]);
        assert!(e.is_ip_allowed(&Ipv4Addr::LOCALHOST));
    }

    #[test]
    fn test_unregistered_ip_blocked() {
        let e = engine(&["example.com"]);
        assert!(!e.is_ip_allowed(&Ipv4Addr::new(1, 2, 3, 4)));
    }

    #[test]
    fn test_re_resolution_replaces_old_ips() {
        let mut e = engine(&["example.com"]);
        let ip_a = Ipv4Addr::new(1, 1, 1, 1);
        let ip_b = Ipv4Addr::new(2, 2, 2, 2);
        e.register_resolved_ips("example.com", &[ip_a]);
        assert!(e.is_ip_allowed(&ip_a));

        e.register_resolved_ips("example.com", &[ip_b]);
        assert!(!e.is_ip_allowed(&ip_a));
        assert!(e.is_ip_allowed(&ip_b));
    }

    #[test]
    fn test_domain_normalization_case() {
        let mut e = engine(&["example.com"]);
        let ip = Ipv4Addr::new(1, 1, 1, 1);
        e.register_resolved_ips("Example.COM", &[ip]);
        assert!(e.is_ip_allowed(&ip));
        // Verify it's the same canonical key
        assert!(e.is_domain_allowed("example.com"));
        assert!(e.is_domain_allowed("Example.COM"));
    }

    #[test]
    fn test_domain_normalization_trailing_dot() {
        let mut e = engine(&["example.com"]);
        let ip = Ipv4Addr::new(1, 1, 1, 1);
        e.register_resolved_ips("example.com.", &[ip]);
        assert!(e.is_ip_allowed(&ip));
    }

    #[test]
    fn test_re_resolve_with_different_case() {
        let mut e = engine(&["example.com"]);
        let ip_a = Ipv4Addr::new(1, 1, 1, 1);
        let ip_b = Ipv4Addr::new(2, 2, 2, 2);
        e.register_resolved_ips("example.com", &[ip_a]);
        assert!(e.is_ip_allowed(&ip_a));

        // Re-resolve with different casing — should replace
        e.register_resolved_ips("Example.COM", &[ip_b]);
        assert!(!e.is_ip_allowed(&ip_a));
        assert!(e.is_ip_allowed(&ip_b));
    }

    #[test]
    fn test_shared_ip_not_revoked_on_re_resolve() {
        let mut e = engine(&["a.com", "b.com"]);
        let shared_ip = Ipv4Addr::new(1, 1, 1, 1);
        let new_ip = Ipv4Addr::new(2, 2, 2, 2);

        e.register_resolved_ips("a.com", &[shared_ip]);
        e.register_resolved_ips("b.com", &[shared_ip]);
        assert!(e.is_ip_allowed(&shared_ip));

        // Re-resolve a.com to a different IP
        e.register_resolved_ips("a.com", &[new_ip]);

        // shared_ip should still be allowed (b.com still references it)
        assert!(e.is_ip_allowed(&shared_ip));
        assert!(e.is_ip_allowed(&new_ip));
    }
}
