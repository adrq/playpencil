use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};

use smoltcp::iface::{SocketHandle, SocketSet};
use smoltcp::socket::udp;
use smoltcp::wire::{IpAddress, IpEndpoint};

use super::policy::PolicyEngine;

struct UdpRelayEntry {
    host_socket: UdpSocket,
}

/// Manages UDP forwarding between guest and host.
///
/// Each relay is keyed by `(src_port, dst_ip, dst_port)` and gets its own host
/// UdpSocket connected to the remote endpoint. smoltcp UDP sockets are shared
/// per `(dst_ip, dst_port)` so replies appear from the correct remote address.
pub struct UdpRelayManager {
    /// Per-flow relay state: (src_port, dst_ip, dst_port) → relay entry
    relays: HashMap<(u16, Ipv4Addr, u16), UdpRelayEntry>,
    /// Shared smoltcp sockets for the return path: (dst_ip, dst_port) → handle
    smol_sockets: HashMap<(Ipv4Addr, u16), SocketHandle>,
}

impl UdpRelayManager {
    pub fn new() -> Self {
        Self {
            relays: HashMap::new(),
            smol_sockets: HashMap::new(),
        }
    }

    /// Intercept an outbound UDP packet (non-DNS). Returns true if handled.
    pub fn intercept(
        &mut self,
        src_port: u16,
        dst_ip: Ipv4Addr,
        dst_port: u16,
        data: &[u8],
        policy: &PolicyEngine,
        sockets: &mut SocketSet<'_>,
    ) -> bool {
        if !policy.is_ip_allowed(&dst_ip) {
            return false;
        }

        let relay_key = (src_port, dst_ip, dst_port);
        let remote_key = (dst_ip, dst_port);

        // Create shared smoltcp socket for this remote endpoint if needed
        if let Entry::Vacant(e) = self.smol_sockets.entry(remote_key) {
            let rx_buf = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 8], vec![0; 4096]);
            let tx_buf = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 8], vec![0; 4096]);
            let mut sock = udp::Socket::new(rx_buf, tx_buf);
            let endpoint = IpEndpoint::new(IpAddress::Ipv4(dst_ip), dst_port);
            sock.bind(endpoint).ok();
            let handle = sockets.add(sock);
            e.insert(handle);
        }

        // Create per-flow host socket if needed, connected to the remote endpoint
        // so we only accept replies from the intended peer
        if let Entry::Vacant(e) = self.relays.entry(relay_key) {
            let host_sock = match UdpSocket::bind("0.0.0.0:0") {
                Ok(s) => s,
                Err(_) => return false,
            };
            let remote_addr = SocketAddr::new(dst_ip.into(), dst_port);
            if host_sock.connect(remote_addr).is_err() {
                return false;
            }
            host_sock.set_nonblocking(true).ok();
            e.insert(UdpRelayEntry {
                host_socket: host_sock,
            });
        }

        // Forward to host
        if let Some(entry) = self.relays.get(&relay_key) {
            let _ = entry.host_socket.send(data);
        }

        true
    }

    /// Check host sockets for replies and route them back to the correct guest port.
    pub fn process(&mut self, sockets: &mut SocketSet<'_>, guest_ip: Ipv4Addr) {
        let mut responses: Vec<((u16, Ipv4Addr, u16), Vec<u8>)> = Vec::new();

        for (key, entry) in &self.relays {
            let mut buf = [0u8; 4096];
            if let Ok(n) = entry.host_socket.recv(&mut buf) {
                responses.push((*key, buf[..n].to_vec()));
            }
        }

        for ((src_port, dst_ip, dst_port), data) in responses {
            let remote_key = (dst_ip, dst_port);
            if let Some(&handle) = self.smol_sockets.get(&remote_key) {
                let guest_ep = IpEndpoint::new(IpAddress::Ipv4(guest_ip), src_port);
                let socket = sockets.get_mut::<udp::Socket>(handle);
                let _ = socket.send_slice(&data, guest_ep);
            }
        }
    }

    pub fn cleanup(&mut self, sockets: &mut SocketSet<'_>) {
        for (_, handle) in self.smol_sockets.drain() {
            sockets.remove(handle);
        }
        self.relays.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> (PolicyEngine, SocketSet<'static>, UdpRelayManager) {
        let policy = PolicyEngine::new(vec!["example.com".to_string()], Ipv4Addr::new(10, 0, 2, 1));
        let sockets = SocketSet::new(vec![]);
        let relay = UdpRelayManager::new();
        (policy, sockets, relay)
    }

    #[test]
    fn test_multiple_source_ports_same_dest() {
        let (mut policy, mut sockets, mut relay) = setup();
        let ip = Ipv4Addr::new(1, 2, 3, 4);
        policy.register_resolved_ips("example.com", &[ip]);

        relay.intercept(1000, ip, 53, b"query1", &policy, &mut sockets);
        relay.intercept(1001, ip, 53, b"query2", &policy, &mut sockets);

        // 2 relay entries (separate host sockets), but only 1 shared smoltcp socket
        assert_eq!(relay.relays.len(), 2);
        assert_eq!(relay.smol_sockets.len(), 1);
    }

    #[test]
    fn test_udp_relay_cleanup_on_shutdown() {
        let (mut policy, mut sockets, mut relay) = setup();
        let ip = Ipv4Addr::new(1, 2, 3, 4);
        policy.register_resolved_ips("example.com", &[ip]);

        relay.intercept(1000, ip, 8080, b"data", &policy, &mut sockets);
        assert_eq!(relay.relays.len(), 1);
        assert_eq!(relay.smol_sockets.len(), 1);

        relay.cleanup(&mut sockets);
        assert!(relay.relays.is_empty());
        assert!(relay.smol_sockets.is_empty());
    }

    #[test]
    fn test_blocked_ip_rejected() {
        let (policy, mut sockets, mut relay) = setup();
        let blocked_ip = Ipv4Addr::new(6, 6, 6, 6);
        assert!(!relay.intercept(1000, blocked_ip, 80, b"data", &policy, &mut sockets));
        assert!(relay.relays.is_empty());
    }
}
