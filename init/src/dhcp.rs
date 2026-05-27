use std::io;
use std::net::Ipv4Addr;
use std::time::Duration;

use crate::Error;

const DHCP_SERVER_PORT: u16 = 67;
const DHCP_CLIENT_PORT: u16 = 68;
const BOOTP_MAGIC_COOKIE: [u8; 4] = [99, 130, 83, 99];
const MAX_RETRIES: u32 = 3;

/// RAII guard that closes an fd on drop.
struct OwnedFd(i32);

impl Drop for OwnedFd {
    fn drop(&mut self) {
        unsafe { libc::close(self.0) };
    }
}
const MAX_PACKET_SIZE: usize = 1500;

pub struct DhcpLease {
    pub ip: Ipv4Addr,
    pub subnet_mask: Ipv4Addr,
    pub gateway: Ipv4Addr,
    pub dns_servers: Vec<Ipv4Addr>,
}

struct DhcpOptions {
    msg_type: u8,
    server_id: Option<Ipv4Addr>,
    subnet_mask: Option<Ipv4Addr>,
    router: Option<Ipv4Addr>,
    dns_servers: Vec<Ipv4Addr>,
}

pub fn run_dhcp(ifname: &str, mac: &[u8; 6]) -> Result<DhcpLease, Error> {
    let sock = OwnedFd(create_dhcp_socket(ifname)?);
    let fd = sock.0;

    // Use PID as xid for uniqueness within the VM
    let xid: u32 = std::process::id();

    // Phase 1: DISCOVER -> OFFER
    let offer = dhcp_exchange(fd, mac, xid, build_discover(mac, xid), 2)?;

    let offered_ip = offer.0;
    let server_id = offer
        .1
        .server_id
        .ok_or_else(|| Error::Dhcp("OFFER missing server identifier".to_string()))?;

    // Phase 2: REQUEST -> ACK
    let ack = dhcp_exchange(
        fd,
        mac,
        xid,
        build_request(mac, xid, offered_ip, server_id),
        5,
    )?;

    drop(sock);

    let opts = ack.1;
    let subnet_mask = opts
        .subnet_mask
        .ok_or_else(|| Error::Dhcp("ACK missing subnet mask".to_string()))?;
    let gateway = opts
        .router
        .ok_or_else(|| Error::Dhcp("ACK missing router".to_string()))?;

    Ok(DhcpLease {
        ip: ack.0,
        subnet_mask,
        gateway,
        dns_servers: opts.dns_servers,
    })
}

fn create_dhcp_socket(ifname: &str) -> Result<i32, Error> {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if fd < 0 {
        return Err(Error::Io(io::Error::last_os_error()));
    }

    // SO_BROADCAST
    let one: libc::c_int = 1;
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_BROADCAST,
            &one as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as u32,
        )
    };
    if ret < 0 {
        let e = io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(Error::Io(e));
    }

    // SO_BINDTODEVICE
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            ifname.as_ptr() as *const libc::c_void,
            ifname.len() as u32,
        )
    };
    if ret < 0 {
        let e = io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(Error::Io(e));
    }

    // Bind to 0.0.0.0:68
    let addr = libc::sockaddr_in {
        sin_family: libc::AF_INET as u16,
        sin_port: DHCP_CLIENT_PORT.to_be(),
        sin_addr: libc::in_addr { s_addr: 0 },
        sin_zero: [0; 8],
    };
    let ret = unsafe {
        libc::bind(
            fd,
            &addr as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as u32,
        )
    };
    if ret < 0 {
        let e = io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(Error::Io(e));
    }

    Ok(fd)
}

/// Send a DHCP packet and wait for a response with the expected message type.
/// Retransmits with exponential backoff (2s, 4s, 8s).
fn dhcp_exchange(
    fd: i32,
    mac: &[u8; 6],
    xid: u32,
    packet: Vec<u8>,
    expected_msg_type: u8,
) -> Result<(Ipv4Addr, DhcpOptions), Error> {
    let dest = libc::sockaddr_in {
        sin_family: libc::AF_INET as u16,
        sin_port: DHCP_SERVER_PORT.to_be(),
        sin_addr: libc::in_addr {
            s_addr: 0xFFFFFFFF_u32.to_be(),
        },
        sin_zero: [0; 8],
    };

    for retry in 0..=MAX_RETRIES {
        let timeout_secs = 2u64 << retry;

        let ret = unsafe {
            libc::sendto(
                fd,
                packet.as_ptr() as *const libc::c_void,
                packet.len(),
                0,
                &dest as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in>() as u32,
            )
        };
        if ret < 0 {
            return Err(Error::Dhcp(format!(
                "sendto: {}",
                io::Error::last_os_error()
            )));
        }

        // Set receive timeout
        let tv = libc::timeval {
            tv_sec: timeout_secs as i64,
            tv_usec: 0,
        };
        let ret = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &tv as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::timeval>() as u32,
            )
        };
        if ret < 0 {
            return Err(Error::Dhcp(format!(
                "setsockopt SO_RCVTIMEO: {}",
                io::Error::last_os_error()
            )));
        }

        // Try to receive a valid response within the timeout
        let deadline = std::time::Instant::now() + Duration::from_secs(timeout_secs);
        loop {
            if std::time::Instant::now() >= deadline {
                break;
            }

            let mut buf = [0u8; MAX_PACKET_SIZE];
            let n = unsafe {
                libc::recvfrom(
                    fd,
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                    0,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            };
            if n <= 0 {
                break; // Timeout or error
            }

            let data = &buf[..n as usize];
            if let Ok(resp) = parse_dhcp_response(data, xid, mac, expected_msg_type) {
                return Ok(resp);
            }
            // Invalid packet, keep trying until timeout
        }
    }

    Err(Error::Dhcp(format!(
        "no DHCP response (type {expected_msg_type}) after {MAX_RETRIES} retries"
    )))
}

fn build_discover(mac: &[u8; 6], xid: u32) -> Vec<u8> {
    let mut pkt = vec![0u8; 300];
    fill_bootp_header(&mut pkt, mac, xid);

    let mut pos = 240;
    // Option 53: DHCP Message Type = DISCOVER (1)
    pos = add_option(&mut pkt, pos, 53, &[1]);
    // Option 61: Client Identifier (type=1/ethernet + MAC)
    let mut client_id = vec![1u8]; // hardware type ethernet
    client_id.extend_from_slice(mac);
    pos = add_option(&mut pkt, pos, 61, &client_id);
    // Option 55: Parameter Request List
    pos = add_option(&mut pkt, pos, 55, &[1, 3, 6]); // subnet, router, DNS
    // End
    pkt[pos] = 255;
    pkt.truncate(pos + 1);
    pkt
}

fn build_request(mac: &[u8; 6], xid: u32, offered_ip: Ipv4Addr, server_ip: Ipv4Addr) -> Vec<u8> {
    let mut pkt = vec![0u8; 300];
    fill_bootp_header(&mut pkt, mac, xid);

    let mut pos = 240;
    // Option 53: DHCP Message Type = REQUEST (3)
    pos = add_option(&mut pkt, pos, 53, &[3]);
    // Option 50: Requested IP
    pos = add_option(&mut pkt, pos, 50, &offered_ip.octets());
    // Option 54: Server Identifier
    pos = add_option(&mut pkt, pos, 54, &server_ip.octets());
    // Option 61: Client Identifier
    let mut client_id = vec![1u8];
    client_id.extend_from_slice(mac);
    pos = add_option(&mut pkt, pos, 61, &client_id);
    // Option 55: Parameter Request List
    pos = add_option(&mut pkt, pos, 55, &[1, 3, 6]);
    // End
    pkt[pos] = 255;
    pkt.truncate(pos + 1);
    pkt
}

fn fill_bootp_header(pkt: &mut [u8], mac: &[u8; 6], xid: u32) {
    pkt[0] = 1; // BOOTREQUEST
    pkt[1] = 1; // Ethernet
    pkt[2] = 6; // HW addr len
    // Hops = 0
    pkt[4..8].copy_from_slice(&xid.to_be_bytes());
    // Broadcast flag (bit 15)
    pkt[10] = 0x80;
    // chaddr at offset 28
    pkt[28..34].copy_from_slice(mac);
    // Magic cookie at offset 236
    pkt[236..240].copy_from_slice(&BOOTP_MAGIC_COOKIE);
}

fn add_option(pkt: &mut Vec<u8>, pos: usize, code: u8, data: &[u8]) -> usize {
    // Ensure capacity
    while pkt.len() < pos + 2 + data.len() {
        pkt.push(0);
    }
    pkt[pos] = code;
    pkt[pos + 1] = data.len() as u8;
    pkt[pos + 2..pos + 2 + data.len()].copy_from_slice(data);
    pos + 2 + data.len()
}

fn parse_dhcp_response(
    data: &[u8],
    expected_xid: u32,
    expected_mac: &[u8; 6],
    expected_msg_type: u8,
) -> Result<(Ipv4Addr, DhcpOptions), Error> {
    if data.len() < 240 {
        return Err(Error::Dhcp("packet too short".into()));
    }

    // Must be BOOTREPLY
    if data[0] != 2 {
        return Err(Error::Dhcp("not a BOOTREPLY".into()));
    }

    // Verify magic cookie
    if data[236..240] != BOOTP_MAGIC_COOKIE {
        return Err(Error::Dhcp("bad magic cookie".into()));
    }

    // Verify xid
    let xid = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    if xid != expected_xid {
        return Err(Error::Dhcp("xid mismatch".into()));
    }

    // Verify chaddr
    if data[28..34] != *expected_mac {
        return Err(Error::Dhcp("chaddr mismatch".into()));
    }

    // yiaddr (offered IP)
    let yiaddr = Ipv4Addr::new(data[16], data[17], data[18], data[19]);

    // Parse options
    let opts = parse_options(&data[240..], expected_msg_type)?;

    Ok((yiaddr, opts))
}

fn parse_options(data: &[u8], expected_msg_type: u8) -> Result<DhcpOptions, Error> {
    let mut opts = DhcpOptions {
        msg_type: 0,
        server_id: None,
        subnet_mask: None,
        router: None,
        dns_servers: Vec::new(),
    };

    let mut i = 0;
    while i < data.len() {
        let code = data[i];
        if code == 255 {
            break; // End
        }
        if code == 0 {
            i += 1; // Pad
            continue;
        }
        if i + 1 >= data.len() {
            break;
        }
        let len = data[i + 1] as usize;
        if i + 2 + len > data.len() {
            break;
        }
        let value = &data[i + 2..i + 2 + len];

        match code {
            1 if len == 4 => {
                opts.subnet_mask = Some(Ipv4Addr::new(value[0], value[1], value[2], value[3]));
            }
            3 if len >= 4 => {
                opts.router = Some(Ipv4Addr::new(value[0], value[1], value[2], value[3]));
            }
            6 => {
                // DNS servers, 4 bytes each
                for chunk in value.chunks_exact(4) {
                    opts.dns_servers
                        .push(Ipv4Addr::new(chunk[0], chunk[1], chunk[2], chunk[3]));
                }
            }
            53 if len == 1 => {
                opts.msg_type = value[0];
            }
            54 if len == 4 => {
                opts.server_id = Some(Ipv4Addr::new(value[0], value[1], value[2], value[3]));
            }
            _ => {}
        }
        i += 2 + len;
    }

    if opts.msg_type != expected_msg_type {
        return Err(Error::Dhcp(format!(
            "expected msg_type {expected_msg_type}, got {}",
            opts.msg_type
        )));
    }

    Ok(opts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_discover_structure() {
        let mac = [0x52, 0x54, 0x00, 0xAB, 0xCD, 0xEF];
        let pkt = build_discover(&mac, 0x12345678);

        assert_eq!(pkt[0], 1); // BOOTREQUEST
        assert_eq!(pkt[1], 1); // Ethernet
        assert_eq!(pkt[2], 6); // HW addr len
        assert_eq!(&pkt[4..8], &0x12345678u32.to_be_bytes());
        assert_eq!(pkt[10], 0x80); // Broadcast flag
        assert_eq!(&pkt[28..34], &mac);
        assert_eq!(&pkt[236..240], &BOOTP_MAGIC_COOKIE);
        // First option should be type 53 (message type) = 1 (DISCOVER)
        assert_eq!(pkt[240], 53);
        assert_eq!(pkt[241], 1);
        assert_eq!(pkt[242], 1);
    }

    #[test]
    fn test_build_request_has_server_and_ip() {
        let mac = [0x52, 0x54, 0x00, 0xAB, 0xCD, 0xEF];
        let pkt = build_request(
            &mac,
            0xAABBCCDD,
            Ipv4Addr::new(10, 0, 2, 15),
            Ipv4Addr::new(10, 0, 2, 1),
        );

        assert_eq!(pkt[0], 1);
        // Find option 50 (requested IP)
        let opts = &pkt[240..];
        assert!(find_option(opts, 50).is_some());
        assert!(find_option(opts, 54).is_some());
    }

    #[test]
    fn test_parse_dhcp_response_valid() {
        let mac = [0x52, 0x54, 0x00, 0xAB, 0xCD, 0xEF];
        let xid: u32 = 0x12345678;

        let mut pkt = vec![0u8; 300];
        pkt[0] = 2; // BOOTREPLY
        pkt[1] = 1;
        pkt[2] = 6;
        pkt[4..8].copy_from_slice(&xid.to_be_bytes());
        pkt[16..20].copy_from_slice(&[10, 0, 2, 15]); // yiaddr
        pkt[28..34].copy_from_slice(&mac);
        pkt[236..240].copy_from_slice(&BOOTP_MAGIC_COOKIE);

        let mut pos = 240;
        // Option 53: msg type = OFFER (2)
        pkt[pos] = 53;
        pkt[pos + 1] = 1;
        pkt[pos + 2] = 2;
        pos += 3;
        // Option 54: server id
        pkt[pos] = 54;
        pkt[pos + 1] = 4;
        pkt[pos + 2..pos + 6].copy_from_slice(&[10, 0, 2, 1]);
        pos += 6;
        // Option 1: subnet mask
        pkt[pos] = 1;
        pkt[pos + 1] = 4;
        pkt[pos + 2..pos + 6].copy_from_slice(&[255, 255, 255, 0]);
        pos += 6;
        // Option 3: router
        pkt[pos] = 3;
        pkt[pos + 1] = 4;
        pkt[pos + 2..pos + 6].copy_from_slice(&[10, 0, 2, 1]);
        pos += 6;
        // Option 6: DNS
        pkt[pos] = 6;
        pkt[pos + 1] = 4;
        pkt[pos + 2..pos + 6].copy_from_slice(&[8, 8, 8, 8]);
        pos += 6;
        // End
        pkt[pos] = 255;

        let (ip, opts) = parse_dhcp_response(&pkt, xid, &mac, 2).unwrap();
        assert_eq!(ip, Ipv4Addr::new(10, 0, 2, 15));
        assert_eq!(opts.msg_type, 2);
        assert_eq!(opts.server_id, Some(Ipv4Addr::new(10, 0, 2, 1)));
        assert_eq!(opts.subnet_mask, Some(Ipv4Addr::new(255, 255, 255, 0)));
        assert_eq!(opts.router, Some(Ipv4Addr::new(10, 0, 2, 1)));
        assert_eq!(opts.dns_servers, vec![Ipv4Addr::new(8, 8, 8, 8)]);
    }

    #[test]
    fn test_parse_dhcp_response_xid_mismatch() {
        let mac = [0x52, 0x54, 0x00, 0xAB, 0xCD, 0xEF];
        let mut pkt = vec![0u8; 260];
        pkt[0] = 2;
        pkt[4..8].copy_from_slice(&0x11111111u32.to_be_bytes());
        pkt[28..34].copy_from_slice(&mac);
        pkt[236..240].copy_from_slice(&BOOTP_MAGIC_COOKIE);
        pkt[240] = 53;
        pkt[241] = 1;
        pkt[242] = 2;
        pkt[243] = 255;

        let result = parse_dhcp_response(&pkt, 0x22222222, &mac, 2);
        assert!(result.is_err());
    }

    fn find_option(opts: &[u8], target: u8) -> Option<usize> {
        let mut i = 0;
        while i < opts.len() {
            if opts[i] == 255 {
                break;
            }
            if opts[i] == 0 {
                i += 1;
                continue;
            }
            if opts[i] == target {
                return Some(i);
            }
            if i + 1 >= opts.len() {
                break;
            }
            i += 2 + opts[i + 1] as usize;
        }
        None
    }
}
