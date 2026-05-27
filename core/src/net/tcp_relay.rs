use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::time::Duration;

use smoltcp::iface::{SocketHandle, SocketSet};
use smoltcp::socket::tcp;
use smoltcp::wire::{IpAddress, IpListenEndpoint};

use super::policy::PolicyEngine;

const TCP_BUF_SIZE: usize = 65536;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

struct TcpProxyState {
    host_stream: Option<TcpStream>,
    dst_addr: SocketAddr,
    /// Bytes read from host but not yet accepted by smoltcp's send buffer
    pending_send: Vec<u8>,
    /// Set when we've called abort()/close() — waiting for smoltcp to flush FIN/RST
    closing: bool,
}

/// Manages TCP connections between smoltcp and host sockets.
///
/// For each outbound TCP SYN from the guest:
/// 1. A smoltcp TCP socket listens on the specific (dst_ip, dst_port) endpoint
/// 2. smoltcp completes the 3-way handshake with the guest
/// 3. Once Established, a host TCP connection is opened
/// 4. Data is relayed bidirectionally
pub struct TcpRelayManager {
    connections: HashMap<SocketHandle, TcpProxyState>,
    /// Deduplicates retransmitted SYNs: (dst_ip, dst_port, src_port) → handle
    syn_seen: HashMap<(Ipv4Addr, u16, u16), SocketHandle>,
}

impl TcpRelayManager {
    pub fn new() -> Self {
        Self {
            connections: HashMap::new(),
            syn_seen: HashMap::new(),
        }
    }

    /// Intercept an outbound TCP SYN. Returns true if allowed (and handled),
    /// false if blocked.
    pub fn intercept_syn(
        &mut self,
        dst_ip: Ipv4Addr,
        dst_port: u16,
        src_port: u16,
        policy: &PolicyEngine,
        sockets: &mut SocketSet<'_>,
    ) -> bool {
        let key = (dst_ip, dst_port, src_port);
        if self.syn_seen.contains_key(&key) {
            return true;
        }

        if !policy.is_ip_allowed(&dst_ip) {
            return false;
        }

        let tcp_rx = tcp::SocketBuffer::new(vec![0; TCP_BUF_SIZE]);
        let tcp_tx = tcp::SocketBuffer::new(vec![0; TCP_BUF_SIZE]);
        let tcp_socket = tcp::Socket::new(tcp_rx, tcp_tx);
        let handle = sockets.add(tcp_socket);

        // Listen on the specific (dst_ip, dst_port) so two connections to
        // different hosts on the same port don't collide.
        let endpoint = IpListenEndpoint {
            addr: Some(IpAddress::Ipv4(dst_ip)),
            port: dst_port,
        };
        let socket = sockets.get_mut::<tcp::Socket>(handle);
        if socket.listen(endpoint).is_err() {
            sockets.remove(handle);
            return false;
        }

        let addr = SocketAddr::new(dst_ip.into(), dst_port);
        self.connections.insert(
            handle,
            TcpProxyState {
                host_stream: None,
                dst_addr: addr,
                pending_send: Vec::new(),
                closing: false,
            },
        );
        self.syn_seen.insert(key, handle);
        true
    }

    /// Process all active TCP connections: connect to host when ready, relay data.
    pub fn process(&mut self, sockets: &mut SocketSet<'_>) {
        let mut to_remove = Vec::new();

        for (&handle, proxy) in &mut self.connections {
            let socket = sockets.get_mut::<tcp::Socket>(handle);

            // Only remove the smoltcp handle once the socket has fully closed,
            // giving smoltcp time to flush FIN/RST to the guest.
            if matches!(socket.state(), tcp::State::Closed | tcp::State::TimeWait) {
                to_remove.push(handle);
                continue;
            }

            if proxy.closing
                || matches!(socket.state(), tcp::State::Listen | tcp::State::SynReceived)
            {
                continue;
            }

            // Connect to host once smoltcp handshake completes
            if proxy.host_stream.is_none() {
                match TcpStream::connect_timeout(&proxy.dst_addr, CONNECT_TIMEOUT) {
                    Ok(stream) => {
                        stream.set_nonblocking(true).ok();
                        proxy.host_stream = Some(stream);
                    }
                    Err(_) => {
                        socket.abort();
                        proxy.closing = true;
                        continue;
                    }
                }
            }

            let host = proxy.host_stream.as_mut().unwrap();

            if !socket.may_recv() && !socket.may_send() {
                proxy.closing = true;
                continue;
            }

            // Host → guest: drain pending buffer first, then read more from host
            if socket.can_send() {
                // Flush any buffered bytes from a previous partial send
                if !proxy.pending_send.is_empty() {
                    match socket.send_slice(&proxy.pending_send) {
                        Ok(sent) => {
                            proxy.pending_send.drain(..sent);
                        }
                        Err(_) => {
                            socket.abort();
                            proxy.closing = true;
                            continue;
                        }
                    }
                }

                // Only read from host when pending buffer is fully drained
                if proxy.pending_send.is_empty() {
                    let mut buf = [0u8; 4096];
                    match host.read(&mut buf) {
                        Ok(0) => {
                            socket.close();
                            proxy.closing = true;
                            continue;
                        }
                        Ok(n) => match socket.send_slice(&buf[..n]) {
                            Ok(sent) if sent < n => {
                                proxy.pending_send.extend_from_slice(&buf[sent..n]);
                            }
                            Err(_) => {
                                socket.abort();
                                proxy.closing = true;
                                continue;
                            }
                            _ => {}
                        },
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                        Err(_) => {
                            socket.abort();
                            proxy.closing = true;
                            continue;
                        }
                    }
                }
            }

            // Guest → host
            if socket.can_recv() {
                let ok = socket
                    .recv(|data| {
                        host.set_nonblocking(false).ok();
                        let result = host.write_all(data);
                        host.set_nonblocking(true).ok();
                        match result {
                            Ok(()) => (data.len(), true),
                            Err(_) => (0, false), // Don't consume bytes we failed to forward
                        }
                    })
                    .unwrap_or(false);
                if !ok {
                    socket.abort();
                    proxy.closing = true;
                }
            }
        }

        for handle in to_remove {
            self.syn_seen.retain(|_, h| *h != handle);
            self.connections.remove(&handle);
            sockets.remove(handle);
        }
    }

    pub fn cleanup(&mut self, sockets: &mut SocketSet<'_>) {
        for &handle in self.connections.keys() {
            sockets.remove(handle);
        }
        self.connections.clear();
        self.syn_seen.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use smoltcp::iface::SocketSet;

    fn setup() -> (PolicyEngine, SocketSet<'static>, TcpRelayManager) {
        let policy = PolicyEngine::new(vec!["example.com".to_string()], Ipv4Addr::new(10, 0, 2, 1));
        let sockets = SocketSet::new(vec![]);
        let relay = TcpRelayManager::new();
        (policy, sockets, relay)
    }

    #[test]
    fn test_syn_dedup() {
        let (mut policy, mut sockets, mut relay) = setup();
        let ip = Ipv4Addr::new(93, 184, 216, 34);
        policy.register_resolved_ips("example.com", &[ip]);

        let ok1 = relay.intercept_syn(ip, 80, 12345, &policy, &mut sockets);
        let ok2 = relay.intercept_syn(ip, 80, 12345, &policy, &mut sockets);
        assert!(ok1);
        assert!(ok2);
        assert_eq!(relay.connections.len(), 1);
    }

    #[test]
    fn test_different_hosts_same_port() {
        let (mut policy, mut sockets, mut relay) = setup();
        let ip_a = Ipv4Addr::new(93, 184, 216, 34);
        let ip_b = Ipv4Addr::new(104, 20, 23, 154);
        policy.register_resolved_ips("example.com", &[ip_a, ip_b]);

        // Two connections to different hosts on port 80 must not collide
        let ok1 = relay.intercept_syn(ip_a, 80, 12345, &policy, &mut sockets);
        let ok2 = relay.intercept_syn(ip_b, 80, 12346, &policy, &mut sockets);
        assert!(ok1);
        assert!(ok2);
        assert_eq!(relay.connections.len(), 2);
    }

    #[test]
    fn test_blocked_ip_returns_false() {
        let (policy, mut sockets, mut relay) = setup();
        let blocked_ip = Ipv4Addr::new(6, 6, 6, 6);
        assert!(!relay.intercept_syn(blocked_ip, 80, 12345, &policy, &mut sockets));
        assert!(relay.connections.is_empty());
    }

    #[test]
    fn test_cleanup_removes_tracking() {
        let (mut policy, mut sockets, mut relay) = setup();
        let ip = Ipv4Addr::new(93, 184, 216, 34);
        policy.register_resolved_ips("example.com", &[ip]);

        relay.intercept_syn(ip, 80, 12345, &policy, &mut sockets);
        assert_eq!(relay.connections.len(), 1);
        assert_eq!(relay.syn_seen.len(), 1);

        relay.cleanup(&mut sockets);
        assert!(relay.connections.is_empty());
        assert!(relay.syn_seen.is_empty());
    }
}
