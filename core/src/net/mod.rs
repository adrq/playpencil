mod device;
mod dhcp;
pub mod dns;
mod policy;
mod tcp_relay;
mod udp_relay;
mod wire;

use std::net::Ipv4Addr;
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::socket::udp;
use smoltcp::wire::{EthernetAddress, HardwareAddress, IpAddress, IpCidr, IpEndpoint, Ipv4Cidr};

use self::device::VirtioNetDevice;
use self::dhcp::DhcpConfig;
use self::dns::{DnsHandler, DnsResolver, SystemResolver};
use self::policy::PolicyEngine;
use self::tcp_relay::TcpRelayManager;
use self::udp_relay::UdpRelayManager;
use self::wire::{FrameReader, FrameWriter};

/// Configuration for the network backend.
pub struct NetBackendConfig {
    /// The host-side end of the Unix stream socketpair.
    pub socket: UnixStream,
    /// Allowed domain names for the allowlist policy.
    pub allowed_domains: Vec<String>,
    /// MAC address for the backend (gateway) side.
    pub backend_mac: [u8; 6],
    /// MAC address assigned to the guest (unused by this module, but kept for symmetry).
    pub guest_mac: [u8; 6],
    /// Gateway IP address (also used as DHCP server and DNS server).
    pub gateway_ip: Ipv4Addr,
    /// IP address to assign to the guest via DHCP.
    pub guest_ip: Ipv4Addr,
}

/// Handle to a running network backend.
pub struct NetBackendHandle {
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<Result<(), NetError>>>,
}

#[derive(Debug, thiserror::Error)]
pub enum NetError {
    #[error("backend thread panicked")]
    ThreadPanicked,
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

impl NetBackendHandle {
    /// Signal the backend to stop, wait for the thread to exit, and
    /// propagate any error the backend encountered during its run.
    pub fn stop(mut self) -> Result<(), NetError> {
        self.stop.store(true, Ordering::Relaxed);
        match self.thread.take().unwrap().join() {
            Ok(result) => result,
            Err(_) => Err(NetError::ThreadPanicked),
        }
    }
}

impl Drop for NetBackendHandle {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// Start a network backend on a new thread using the system DNS resolver.
pub fn start(config: NetBackendConfig) -> Result<NetBackendHandle, NetError> {
    start_with_resolver(config, Box::new(SystemResolver))
}

/// Start with a custom resolver (for testing).
pub(crate) fn start_with_resolver(
    config: NetBackendConfig,
    resolver: Box<dyn DnsResolver>,
) -> Result<NetBackendHandle, NetError> {
    let stop = Arc::new(AtomicBool::new(false));
    let stop_clone = stop.clone();

    let NetBackendConfig {
        socket,
        allowed_domains,
        backend_mac,
        guest_mac: _,
        gateway_ip,
        guest_ip,
    } = config;
    socket.set_nonblocking(true)?;

    let thread = thread::Builder::new()
        .name("net-backend".into())
        .spawn(move || {
            run_backend(
                socket,
                allowed_domains,
                backend_mac,
                gateway_ip,
                guest_ip,
                resolver,
                stop_clone,
            )
        })?;

    Ok(NetBackendHandle {
        stop,
        thread: Some(thread),
    })
}

fn run_backend(
    mut socket: UnixStream,
    allowed_domains: Vec<String>,
    backend_mac: [u8; 6],
    gateway_ip: Ipv4Addr,
    guest_ip: Ipv4Addr,
    resolver: Box<dyn DnsResolver>,
    stop: Arc<AtomicBool>,
) -> Result<(), NetError> {
    let mut dev = VirtioNetDevice::new();
    let hw_addr = EthernetAddress(backend_mac);
    let smol_config = Config::new(HardwareAddress::Ethernet(hw_addr));
    let mut iface = Interface::new(
        smol_config,
        &mut dev,
        smoltcp::time::Instant::from_millis(0),
    );

    iface.update_ip_addrs(|addrs| {
        addrs
            .push(IpCidr::Ipv4(Ipv4Cidr::new(gateway_ip, 24)))
            .unwrap();
    });
    // Accept packets to any IP so we can relay traffic to remote hosts
    iface.set_any_ip(true);
    iface
        .routes_mut()
        .add_default_ipv4_route(gateway_ip)
        .unwrap();

    let mut sockets = SocketSet::new(vec![]);

    // DNS UDP socket on gateway:53
    let dns_rx = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 16], vec![0; 4096]);
    let dns_tx = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 16], vec![0; 4096]);
    let mut dns_socket = udp::Socket::new(dns_rx, dns_tx);
    dns_socket
        .bind(IpEndpoint::new(IpAddress::Ipv4(gateway_ip), 53))
        .unwrap();
    let dns_handle = sockets.add(dns_socket);

    let mut policy = PolicyEngine::new(allowed_domains, gateway_ip);
    let dns_handler = DnsHandler::new(resolver);
    let mut tcp_relay = TcpRelayManager::new();
    let mut udp_relay = UdpRelayManager::new();
    let mut frame_reader = FrameReader::new();

    let dhcp_config = DhcpConfig {
        backend_mac,
        gateway_ip,
        guest_ip,
    };

    let mut eof = false;
    while !stop.load(Ordering::Relaxed) && !eof {
        let mut got_frame = false;

        // 1. Read and process incoming frames
        loop {
            match frame_reader.poll(&mut socket) {
                Ok(Some(frame)) => {
                    got_frame = true;

                    // DHCP interception — respond directly, skip smoltcp
                    if let Some(response) = dhcp::try_handle_dhcp_frame(&frame, &dhcp_config) {
                        let _ = FrameWriter::write_frame(&mut socket, &response);
                        continue;
                    }

                    // Parse outbound packets for interception
                    if let Some(action) = classify_outbound(&frame, gateway_ip) {
                        match action {
                            OutboundAction::TcpSyn {
                                dst_ip,
                                dst_port,
                                src_port,
                            } => {
                                tcp_relay.intercept_syn(
                                    dst_ip,
                                    dst_port,
                                    src_port,
                                    &policy,
                                    &mut sockets,
                                );
                                // Still feed to smoltcp for handshake
                            }
                            OutboundAction::Udp {
                                dst_ip,
                                dst_port,
                                src_port,
                                data_offset,
                                data_len,
                            } => {
                                let data = &frame[data_offset..data_offset + data_len];
                                if udp_relay.intercept(
                                    src_port,
                                    dst_ip,
                                    dst_port,
                                    data,
                                    &policy,
                                    &mut sockets,
                                ) {
                                    continue; // Short-circuit: don't feed to smoltcp
                                }
                            }
                        }
                    }

                    dev.feed_frame(frame);
                    let ts = smol_now();
                    iface.poll(ts, &mut dev, &mut sockets);
                }
                Ok(None) => break,
                Err(e)
                    if e.kind() == std::io::ErrorKind::ConnectionReset
                        || e.kind() == std::io::ErrorKind::UnexpectedEof =>
                {
                    // VM socket closed
                    eof = true;
                    break;
                }
                Err(e) if e.kind() == std::io::ErrorKind::InvalidData => {
                    continue;
                }
                Err(_) => {
                    eof = true;
                    break;
                }
            }
        }

        // 2. Process pending work
        dns_handler.process(&mut sockets, &mut policy, dns_handle);
        tcp_relay.process(&mut sockets);
        udp_relay.process(&mut sockets, guest_ip);

        // 3. Poll egress
        let ts = smol_now();
        iface.poll(ts, &mut dev, &mut sockets);
        let tx_frames = dev.take_tx_frames();
        let had_tx = !tx_frames.is_empty();
        for frame in &tx_frames {
            let _ = FrameWriter::write_frame(&mut socket, frame);
        }

        // 4. Sleep if idle
        if !got_frame && !had_tx {
            thread::sleep(Duration::from_millis(1));
        }
    }

    // Cleanup
    tcp_relay.cleanup(&mut sockets);
    udp_relay.cleanup(&mut sockets);

    Ok(())
}

fn smol_now() -> smoltcp::time::Instant {
    let ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    smoltcp::time::Instant::from_millis(ms)
}

enum OutboundAction {
    TcpSyn {
        dst_ip: Ipv4Addr,
        dst_port: u16,
        src_port: u16,
    },
    Udp {
        dst_ip: Ipv4Addr,
        dst_port: u16,
        src_port: u16,
        data_offset: usize,
        data_len: usize,
    },
}

/// Classify outbound IPv4 packets that need interception.
/// Returns None for malformed or non-interceptable packets.
fn classify_outbound(frame: &[u8], gateway_ip: Ipv4Addr) -> Option<OutboundAction> {
    use etherparse::SlicedPacket;

    let packet = SlicedPacket::from_ethernet(frame).ok()?;

    let ipv4 = match packet.net {
        Some(etherparse::NetSlice::Ipv4(ref v4)) => v4,
        _ => return None,
    };

    // Reject fragmented packets
    if ipv4.header().is_fragmenting_payload() {
        return None;
    }

    let dst_ip = ipv4.header().destination_addr();

    if dst_ip == gateway_ip
        || dst_ip.is_loopback()
        || dst_ip.is_broadcast()
        || dst_ip == Ipv4Addr::new(255, 255, 255, 255)
    {
        return None;
    }

    match packet.transport {
        Some(etherparse::TransportSlice::Tcp(ref tcp)) => {
            let is_syn = tcp.syn() && !tcp.ack();
            if is_syn {
                Some(OutboundAction::TcpSyn {
                    dst_ip,
                    dst_port: tcp.destination_port(),
                    src_port: tcp.source_port(),
                })
            } else {
                None
            }
        }
        Some(etherparse::TransportSlice::Udp(ref udp)) => {
            if udp.destination_port() == 53 {
                return None;
            }
            let payload = udp.payload();
            // Find payload offset within the original frame
            let data_offset = payload.as_ptr() as usize - frame.as_ptr() as usize;
            Some(OutboundAction::Udp {
                dst_ip,
                dst_port: udp.destination_port(),
                src_port: udp.source_port(),
                data_offset,
                data_len: payload.len(),
            })
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::io::{Read, Write};
    use std::net::Ipv4Addr;

    struct MockResolver {
        results: HashMap<String, Vec<Ipv4Addr>>,
    }

    impl DnsResolver for MockResolver {
        fn resolve_ipv4(&self, domain: &str) -> std::io::Result<Vec<Ipv4Addr>> {
            Ok(self.results.get(domain).cloned().unwrap_or_default())
        }
    }

    fn test_config(socket: UnixStream) -> NetBackendConfig {
        NetBackendConfig {
            socket,
            allowed_domains: vec!["example.com".to_string()],
            backend_mac: [0x52, 0x54, 0x00, 0x12, 0x34, 0x56],
            guest_mac: [0x52, 0x54, 0x00, 0xAB, 0xCD, 0xEF],
            gateway_ip: Ipv4Addr::new(10, 0, 2, 1),
            guest_ip: Ipv4Addr::new(10, 0, 2, 15),
        }
    }

    #[test]
    fn test_backend_start_stop() {
        let (backend_sock, _vm_sock) = UnixStream::pair().unwrap();
        let config = test_config(backend_sock);
        let handle = start(config).unwrap();

        // Give it a moment to spin up
        thread::sleep(Duration::from_millis(50));

        handle.stop().unwrap();
    }

    #[test]
    fn test_dhcp_through_backend() {
        let (backend_sock, mut vm_sock) = UnixStream::pair().unwrap();
        let config = test_config(backend_sock);
        let resolver = MockResolver {
            results: HashMap::new(),
        };
        let handle = start_with_resolver(config, Box::new(resolver)).unwrap();

        // Build and send a DHCP DISCOVER frame
        let discover = dhcp::build_test_dhcp_frame(1);
        let len = (discover.len() as u32).to_be_bytes();
        vm_sock.set_nonblocking(false).unwrap();
        vm_sock.write_all(&len).unwrap();
        vm_sock.write_all(&discover).unwrap();

        // Read response with timeout
        vm_sock
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut len_buf = [0u8; 4];
        vm_sock.read_exact(&mut len_buf).unwrap();
        let frame_len = u32::from_be_bytes(len_buf) as usize;
        let mut response = vec![0u8; frame_len];
        vm_sock.read_exact(&mut response).unwrap();

        // Verify DHCP OFFER: check BOOTP reply (op=2) at DHCP offset
        assert!(response.len() > 42);
        assert_eq!(response[42], 2); // BOOTREPLY

        // Verify no ICMP port-unreachable follows (DHCP frame was short-circuited)
        vm_sock
            .set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let mut extra_buf = [0u8; 4];
        assert!(
            vm_sock.read_exact(&mut extra_buf).is_err(),
            "unexpected frame after DHCP OFFER (likely ICMP port unreachable)"
        );

        handle.stop().unwrap();
    }

    #[test]
    fn test_tcp_syn_installs_listener_before_ingress() {
        // This test verifies the interception ordering:
        // classify_outbound extracts SYN info, intercept_syn creates the listener,
        // THEN the frame is fed to smoltcp. If ordering were wrong, smoltcp
        // would RST the SYN instead of accepting it.
        let gateway_ip = Ipv4Addr::new(10, 0, 2, 1);
        let dst_ip = Ipv4Addr::new(93, 184, 216, 34);
        let src_port: u16 = 12345;
        let dst_port: u16 = 80;

        // Build a TCP SYN frame
        let guest_mac: [u8; 6] = [0x52, 0x54, 0x00, 0xAB, 0xCD, 0xEF];
        let backend_mac: [u8; 6] = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
        let mut frame = vec![0u8; 54]; // Ethernet(14) + IP(20) + TCP(20)
        // Ethernet
        frame[0..6].copy_from_slice(&backend_mac); // dst
        frame[6..12].copy_from_slice(&guest_mac); // src
        frame[12..14].copy_from_slice(&[0x08, 0x00]); // IPv4
        // IP
        frame[14] = 0x45;
        frame[16..18].copy_from_slice(&40u16.to_be_bytes()); // total len
        frame[22] = 64; // TTL
        frame[23] = 6; // TCP
        frame[26..30].copy_from_slice(&[10, 0, 2, 15]); // src IP
        frame[30..34].copy_from_slice(&dst_ip.octets()); // dst IP
        // TCP
        frame[34..36].copy_from_slice(&src_port.to_be_bytes());
        frame[36..38].copy_from_slice(&dst_port.to_be_bytes());
        frame[46] = 0x50; // data offset = 5 words
        frame[47] = 0x02; // SYN flag

        // Verify classify_outbound identifies this as a SYN
        let action = classify_outbound(&frame, gateway_ip);
        assert!(matches!(action, Some(OutboundAction::TcpSyn { .. })));

        // Now simulate the interception + ingress path
        let mut dev = VirtioNetDevice::new();
        let hw_addr = EthernetAddress(backend_mac);
        let smol_config = Config::new(HardwareAddress::Ethernet(hw_addr));
        let mut iface = Interface::new(
            smol_config,
            &mut dev,
            smoltcp::time::Instant::from_millis(0),
        );
        iface.update_ip_addrs(|addrs| {
            addrs
                .push(IpCidr::Ipv4(Ipv4Cidr::new(gateway_ip, 24)))
                .unwrap();
        });
        iface.set_any_ip(true);

        let mut sockets = SocketSet::new(vec![]);
        let mut policy = PolicyEngine::new(vec!["example.com".to_string()], gateway_ip);
        policy.register_resolved_ips("example.com", &[dst_ip]);
        let mut tcp_relay = TcpRelayManager::new();

        // Intercept SYN (creates listener)
        let intercepted =
            tcp_relay.intercept_syn(dst_ip, dst_port, src_port, &policy, &mut sockets);
        assert!(intercepted);

        // Feed frame to smoltcp
        dev.feed_frame(frame);
        iface.poll(
            smoltcp::time::Instant::from_millis(1),
            &mut dev,
            &mut sockets,
        );

        // If the listener was correctly installed before poll(), smoltcp will
        // generate a SYN-ACK (not a RST). Check tx_frames for a TCP response.
        let tx = dev.take_tx_frames();
        assert!(!tx.is_empty(), "expected SYN-ACK frame");
        // Verify the response has TCP flags with SYN+ACK (0x12)
        let resp = &tx[0];
        if resp.len() >= 48 {
            let flags = resp[47];
            assert_eq!(
                flags & 0x12,
                0x12,
                "expected SYN-ACK flags, got {flags:#04x}"
            );
        }

        tcp_relay.cleanup(&mut sockets);
    }
}
