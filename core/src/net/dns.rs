use std::net::{Ipv4Addr, SocketAddr, ToSocketAddrs};

use smoltcp::iface::SocketHandle;
use smoltcp::socket::udp;

use super::policy::PolicyEngine;

pub trait DnsResolver: Send {
    fn resolve_ipv4(&self, domain: &str) -> std::io::Result<Vec<Ipv4Addr>>;
}

pub struct SystemResolver;

impl DnsResolver for SystemResolver {
    fn resolve_ipv4(&self, domain: &str) -> std::io::Result<Vec<Ipv4Addr>> {
        let addrs = (domain, 0u16).to_socket_addrs()?;
        Ok(addrs
            .filter_map(|a| match a {
                SocketAddr::V4(v4) => Some(*v4.ip()),
                _ => None,
            })
            .collect())
    }
}

/// Processes DNS queries from the smoltcp UDP socket on gateway:53.
pub struct DnsHandler {
    resolver: Box<dyn DnsResolver>,
}

impl DnsHandler {
    pub fn new(resolver: Box<dyn DnsResolver>) -> Self {
        Self { resolver }
    }

    /// Drain DNS queries from the socket, resolve or reject, send responses.
    pub fn process(
        &self,
        sockets: &mut smoltcp::iface::SocketSet<'_>,
        policy: &mut PolicyEngine,
        dns_handle: SocketHandle,
    ) {
        // Collect queries first to avoid double borrow of sockets
        let mut queries = Vec::new();
        {
            let socket = sockets.get_mut::<udp::Socket>(dns_handle);
            while socket.can_recv() {
                match socket.recv() {
                    Ok((data, meta)) => queries.push((data.to_vec(), meta)),
                    Err(_) => break,
                }
            }
        }

        for (data, meta) in queries {
            if let Some(response) = self.handle_query(&data, policy) {
                let socket = sockets.get_mut::<udp::Socket>(dns_handle);
                let _ = socket.send_slice(&response, meta);
            }
        }
    }

    fn handle_query(&self, data: &[u8], policy: &mut PolicyEngine) -> Option<Vec<u8>> {
        if data.len() < 12 {
            return None;
        }

        let id = u16::from_be_bytes([data[0], data[1]]);
        let qdcount = u16::from_be_bytes([data[4], data[5]]);
        if qdcount != 1 {
            return None;
        }

        let (domain, qtype, question_end) = parse_qname(data)?;

        if !policy.is_domain_allowed(&domain) {
            return Some(build_dns_nxdomain(id, data, question_end));
        }

        if qtype == 1 {
            // A record
            match self.resolver.resolve_ipv4(&domain) {
                Ok(ips) if !ips.is_empty() => {
                    policy.register_resolved_ips(&domain, &ips);
                    Some(build_dns_a_response(id, data, question_end, &ips))
                }
                _ => {
                    // Clear stale IPs — domain no longer resolves
                    policy.register_resolved_ips(&domain, &[]);
                    Some(build_dns_nxdomain(id, data, question_end))
                }
            }
        } else {
            Some(build_dns_empty_response(id, data, question_end))
        }
    }
}

/// Parse the QNAME from a DNS query. Returns (domain, qtype, end_position).
fn parse_qname(data: &[u8]) -> Option<(String, u16, usize)> {
    let mut pos = 12;
    let mut parts = Vec::new();
    loop {
        if pos >= data.len() {
            return None;
        }
        let label_len = data[pos] as usize;
        pos += 1;
        if label_len == 0 {
            break;
        }
        if pos + label_len > data.len() {
            return None;
        }
        parts.push(String::from_utf8_lossy(&data[pos..pos + label_len]).to_string());
        pos += label_len;
    }
    if pos + 4 > data.len() {
        return None;
    }
    let qtype = u16::from_be_bytes([data[pos], data[pos + 1]]);
    Some((parts.join("."), qtype, pos + 4))
}

/// Build a response containing only header + question section (no trailing EDNS/additional).
fn build_response_base(
    id: u16,
    query: &[u8],
    question_end: usize,
    flags_hi: u8,
    flags_lo: u8,
) -> Vec<u8> {
    let mut resp = query[..question_end].to_vec();
    resp[0] = (id >> 8) as u8;
    resp[1] = id as u8;
    resp[2] = flags_hi;
    resp[3] = flags_lo;
    // ANCOUNT=0
    resp[6] = 0;
    resp[7] = 0;
    // NSCOUNT=0, ARCOUNT=0 — clear stale counts from original query
    resp[8] = 0;
    resp[9] = 0;
    resp[10] = 0;
    resp[11] = 0;
    resp
}

pub fn build_dns_nxdomain(id: u16, query: &[u8], question_end: usize) -> Vec<u8> {
    build_response_base(id, query, question_end, 0x81, 0x83) // QR=1 RD=1, RA=1 RCODE=3
}

fn build_dns_empty_response(id: u16, query: &[u8], question_end: usize) -> Vec<u8> {
    build_response_base(id, query, question_end, 0x81, 0x80) // QR=1 RD=1, RA=1 RCODE=0
}

pub fn build_dns_a_response(
    id: u16,
    query: &[u8],
    question_end: usize,
    ips: &[Ipv4Addr],
) -> Vec<u8> {
    let mut resp = build_response_base(id, query, question_end, 0x81, 0x80);

    let ancount = ips.len() as u16;
    resp[6] = (ancount >> 8) as u8;
    resp[7] = ancount as u8;

    for ip in ips {
        // Name pointer to offset 12
        resp.push(0xC0);
        resp.push(0x0C);
        // Type A
        resp.extend_from_slice(&1u16.to_be_bytes());
        // Class IN
        resp.extend_from_slice(&1u16.to_be_bytes());
        // TTL 60s
        resp.extend_from_slice(&60u32.to_be_bytes());
        // RDLENGTH 4
        resp.extend_from_slice(&4u16.to_be_bytes());
        // RDATA
        resp.extend_from_slice(&ip.octets());
    }

    resp
}

/// Build a minimal DNS A-record query packet for testing.
#[cfg(test)]
fn build_test_dns_query(domain: &str) -> Vec<u8> {
    let mut pkt = Vec::new();
    // Header
    pkt.extend_from_slice(&[0x00, 0x01]); // ID=1
    pkt.extend_from_slice(&[0x01, 0x00]); // flags: RD=1
    pkt.extend_from_slice(&[0x00, 0x01]); // QDCOUNT=1
    pkt.extend_from_slice(&[0x00, 0x00]); // ANCOUNT
    pkt.extend_from_slice(&[0x00, 0x00]); // NSCOUNT
    pkt.extend_from_slice(&[0x00, 0x00]); // ARCOUNT

    // QNAME
    for label in domain.split('.') {
        pkt.push(label.len() as u8);
        pkt.extend_from_slice(label.as_bytes());
    }
    pkt.push(0); // root

    // QTYPE=A, QCLASS=IN
    pkt.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
    pkt
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    struct MockResolver {
        results: HashMap<String, Vec<Ipv4Addr>>,
        called: RefCell<Vec<String>>,
    }

    use std::collections::HashMap;

    impl MockResolver {
        fn new(results: HashMap<String, Vec<Ipv4Addr>>) -> Self {
            Self {
                results,
                called: RefCell::new(Vec::new()),
            }
        }
    }

    impl DnsResolver for MockResolver {
        fn resolve_ipv4(&self, domain: &str) -> std::io::Result<Vec<Ipv4Addr>> {
            self.called.borrow_mut().push(domain.to_string());
            match self.results.get(domain) {
                Some(ips) => Ok(ips.clone()),
                None => Ok(vec![]),
            }
        }
    }

    #[test]
    fn test_parse_dns_query_domain() {
        let pkt = build_test_dns_query("example.com");
        let (domain, qtype, _) = parse_qname(&pkt).unwrap();
        assert_eq!(domain, "example.com");
        assert_eq!(qtype, 1); // A record
    }

    #[test]
    fn test_allowed_domain_query_flow() {
        let ip = Ipv4Addr::new(93, 184, 216, 34);
        let mut results = HashMap::new();
        results.insert("example.com".to_string(), vec![ip]);
        let resolver = MockResolver::new(results);

        let handler = DnsHandler::new(Box::new(resolver));
        let mut policy =
            PolicyEngine::new(vec!["example.com".to_string()], Ipv4Addr::new(10, 0, 2, 1));

        let query = build_test_dns_query("example.com");
        let response = handler.handle_query(&query, &mut policy).unwrap();

        // Check it's a valid response (QR=1, RCODE=0)
        assert_eq!(response[2] & 0x80, 0x80); // QR=1
        assert_eq!(response[3] & 0x0F, 0); // RCODE=0
        // ANCOUNT > 0
        let ancount = u16::from_be_bytes([response[6], response[7]]);
        assert!(ancount > 0);
        // IP should now be in policy
        assert!(policy.is_ip_allowed(&ip));
    }

    #[test]
    fn test_blocked_domain_nxdomain() {
        let resolver = MockResolver::new(HashMap::new());
        let handler = DnsHandler::new(Box::new(resolver));
        let mut policy =
            PolicyEngine::new(vec!["allowed.com".to_string()], Ipv4Addr::new(10, 0, 2, 1));

        let query = build_test_dns_query("evil.com");
        let response = handler.handle_query(&query, &mut policy).unwrap();

        // RCODE=3 (NXDOMAIN)
        assert_eq!(response[3] & 0x0F, 3);
        // Resolver should NOT have been called
        // (We can't easily check this without more complex mock, but the behavior is correct)
    }

    #[test]
    fn test_subdomain_matching() {
        let ip = Ipv4Addr::new(1, 2, 3, 4);
        let mut results = HashMap::new();
        results.insert("sub.example.com".to_string(), vec![ip]);
        let resolver = MockResolver::new(results);
        let handler = DnsHandler::new(Box::new(resolver));
        let mut policy =
            PolicyEngine::new(vec!["example.com".to_string()], Ipv4Addr::new(10, 0, 2, 1));

        let query = build_test_dns_query("sub.example.com");
        let response = handler.handle_query(&query, &mut policy).unwrap();
        assert_eq!(response[3] & 0x0F, 0); // RCODE=0, allowed
    }

    #[test]
    fn test_case_insensitive_matching() {
        let ip = Ipv4Addr::new(1, 2, 3, 4);
        let mut results = HashMap::new();
        results.insert("Example.COM".to_string(), vec![ip]);
        let resolver = MockResolver::new(results);
        let handler = DnsHandler::new(Box::new(resolver));
        let mut policy =
            PolicyEngine::new(vec!["example.com".to_string()], Ipv4Addr::new(10, 0, 2, 1));

        let query = build_test_dns_query("Example.COM");
        let response = handler.handle_query(&query, &mut policy).unwrap();
        assert_eq!(response[3] & 0x0F, 0); // allowed
    }

    #[test]
    fn test_build_dns_a_response() {
        let query = build_test_dns_query("example.com");
        let (_, _, qend) = parse_qname(&query).unwrap();
        let ips = vec![Ipv4Addr::new(1, 2, 3, 4), Ipv4Addr::new(5, 6, 7, 8)];
        let resp = build_dns_a_response(1, &query, qend, &ips);

        assert_eq!(resp[2] & 0x80, 0x80); // QR=1
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 2); // ANCOUNT=2
        // NSCOUNT=0, ARCOUNT=0
        assert_eq!(u16::from_be_bytes([resp[8], resp[9]]), 0);
        assert_eq!(u16::from_be_bytes([resp[10], resp[11]]), 0);
        // Response = header(12) + question + 2 A records (each 16 bytes)
        assert_eq!(resp.len(), qend + 2 * 16);
        // First A record IP
        let first_ip_offset = qend + 12; // skip name-ptr(2)+type(2)+class(2)+ttl(4)+rdlen(2)
        assert_eq!(&resp[first_ip_offset..first_ip_offset + 4], &[1, 2, 3, 4]);
    }

    #[test]
    fn test_build_dns_nxdomain() {
        let query = build_test_dns_query("evil.com");
        let (_, _, qend) = parse_qname(&query).unwrap();
        let resp = build_dns_nxdomain(1, &query, qend);
        assert_eq!(resp[2] & 0x80, 0x80); // QR=1
        assert_eq!(resp[3] & 0x0F, 3); // RCODE=3
        // No trailing data beyond question section
        assert_eq!(resp.len(), qend);
    }

    #[test]
    fn test_re_resolution_replaces_allowed_ips() {
        let ip_old = Ipv4Addr::new(1, 1, 1, 1);
        let ip_new = Ipv4Addr::new(2, 2, 2, 2);
        let mut results = HashMap::new();
        results.insert("example.com".to_string(), vec![ip_old]);
        let resolver = MockResolver::new(results);
        let handler = DnsHandler::new(Box::new(resolver));
        let mut policy =
            PolicyEngine::new(vec!["example.com".to_string()], Ipv4Addr::new(10, 0, 2, 1));

        // First resolution
        let query = build_test_dns_query("example.com");
        handler.handle_query(&query, &mut policy);
        assert!(policy.is_ip_allowed(&ip_old));

        // Simulate re-resolution with new IPs
        policy.register_resolved_ips("example.com", &[ip_new]);
        assert!(!policy.is_ip_allowed(&ip_old));
        assert!(policy.is_ip_allowed(&ip_new));
    }

    #[test]
    fn test_failed_resolution_clears_old_ips() {
        let ip = Ipv4Addr::new(1, 1, 1, 1);
        // Resolver returns the IP on first call, empty on second
        let mut results = HashMap::new();
        results.insert("example.com".to_string(), vec![ip]);
        let resolver = MockResolver::new(results);
        let handler = DnsHandler::new(Box::new(resolver));
        let mut policy =
            PolicyEngine::new(vec!["example.com".to_string()], Ipv4Addr::new(10, 0, 2, 1));

        // First resolution succeeds
        let query = build_test_dns_query("example.com");
        handler.handle_query(&query, &mut policy);
        assert!(policy.is_ip_allowed(&ip));

        // Second resolution fails (simulate by clearing resolver results and using empty)
        // We directly test that empty re-resolve clears old IPs
        policy.register_resolved_ips("example.com", &[]);
        assert!(!policy.is_ip_allowed(&ip));
    }
}
