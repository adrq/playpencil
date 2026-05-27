use std::net::Ipv4Addr;

/// Network configuration passed to DHCP response builders.
pub struct DhcpConfig {
    pub backend_mac: [u8; 6],
    pub gateway_ip: Ipv4Addr,
    pub guest_ip: Ipv4Addr,
}

/// Inspect a raw Ethernet frame. If it's a DHCP request (UDP dst port 67),
/// return a complete Ethernet frame containing the DHCP response.
///
/// Header parsing uses etherparse; DHCP option parsing is manual.
pub fn try_handle_dhcp_frame(frame: &[u8], config: &DhcpConfig) -> Option<Vec<u8>> {
    use etherparse::SlicedPacket;

    let packet = SlicedPacket::from_ethernet(frame).ok()?;

    // Must be IPv4 + UDP
    match packet.net {
        Some(etherparse::NetSlice::Ipv4(_)) => {}
        _ => return None,
    }
    let udp = match packet.transport {
        Some(etherparse::TransportSlice::Udp(ref u)) => u,
        _ => return None,
    };
    if udp.destination_port() != 67 {
        return None;
    }

    let dhcp_data = udp.payload();
    if dhcp_data.len() < 240 {
        return None;
    }
    // Verify DHCP magic cookie
    if dhcp_data[236..240] != [99, 130, 83, 99] {
        return None;
    }

    let msg_type = find_dhcp_option(dhcp_data, 53)?;
    let reply_type = match msg_type {
        1 => 2, // DISCOVER → OFFER
        3 => 5, // REQUEST → ACK
        _ => return None,
    };

    let dhcp_payload = build_dhcp_reply(dhcp_data, reply_type, config);
    Some(build_dhcp_ethernet_frame(&dhcp_payload, config))
}

/// Scan DHCP options for a 1-byte option value.
fn find_dhcp_option(dhcp_data: &[u8], target_option: u8) -> Option<u8> {
    let mut pos = 240;
    while pos < dhcp_data.len() {
        let opt = dhcp_data[pos];
        if opt == 255 {
            break;
        }
        if opt == 0 {
            pos += 1;
            continue;
        }
        if pos + 1 >= dhcp_data.len() {
            break;
        }
        let opt_len = dhcp_data[pos + 1] as usize;
        if pos + 2 + opt_len > dhcp_data.len() {
            break;
        }
        if opt == target_option && opt_len == 1 {
            return Some(dhcp_data[pos + 2]);
        }
        pos += 2 + opt_len;
    }
    None
}

fn build_dhcp_reply(request: &[u8], msg_type: u8, config: &DhcpConfig) -> Vec<u8> {
    let mut reply = vec![0u8; 300];
    reply[0] = 2; // BOOTREPLY
    reply[1] = 1; // Ethernet
    reply[2] = 6; // HW addr len
    reply[4..8].copy_from_slice(&request[4..8]); // xid
    reply[16..20].copy_from_slice(&config.guest_ip.octets()); // yiaddr
    reply[20..24].copy_from_slice(&config.gateway_ip.octets()); // siaddr
    reply[28..44].copy_from_slice(&request[28..44]); // chaddr

    // Magic cookie
    reply[236..240].copy_from_slice(&[99, 130, 83, 99]);

    let mut pos = 240;

    // Option 53: DHCP Message Type
    reply[pos] = 53;
    reply[pos + 1] = 1;
    reply[pos + 2] = msg_type;
    pos += 3;

    // Option 54: Server Identifier
    reply[pos] = 54;
    reply[pos + 1] = 4;
    reply[pos + 2..pos + 6].copy_from_slice(&config.gateway_ip.octets());
    pos += 6;

    // Option 51: Lease Time (3600s)
    reply[pos] = 51;
    reply[pos + 1] = 4;
    reply[pos + 2..pos + 6].copy_from_slice(&3600u32.to_be_bytes());
    pos += 6;

    // Option 1: Subnet Mask (/24)
    reply[pos] = 1;
    reply[pos + 1] = 4;
    reply[pos + 2..pos + 6].copy_from_slice(&[255, 255, 255, 0]);
    pos += 6;

    // Option 3: Router
    reply[pos] = 3;
    reply[pos + 1] = 4;
    reply[pos + 2..pos + 6].copy_from_slice(&config.gateway_ip.octets());
    pos += 6;

    // Option 6: DNS Server
    reply[pos] = 6;
    reply[pos + 1] = 4;
    reply[pos + 2..pos + 6].copy_from_slice(&config.gateway_ip.octets());
    pos += 6;

    // End
    reply[pos] = 255;
    pos += 1;

    reply.truncate(pos);
    reply
}

fn build_dhcp_ethernet_frame(dhcp_payload: &[u8], config: &DhcpConfig) -> Vec<u8> {
    let total_len = 14 + 20 + 8 + dhcp_payload.len();
    let mut frame = vec![0u8; total_len];

    // Ethernet: broadcast dst, backend src, IPv4
    frame[0..6].copy_from_slice(&[0xFF; 6]);
    frame[6..12].copy_from_slice(&config.backend_mac);
    frame[12..14].copy_from_slice(&[0x08, 0x00]);

    // IPv4 header
    let ip = &mut frame[14..34];
    ip[0] = 0x45;
    let ip_total = (20 + 8 + dhcp_payload.len()) as u16;
    ip[2..4].copy_from_slice(&ip_total.to_be_bytes());
    ip[6] = 0x40; // DF
    ip[8] = 64; // TTL
    ip[9] = 17; // UDP
    ip[12..16].copy_from_slice(&config.gateway_ip.octets());
    ip[16..20].copy_from_slice(&[255, 255, 255, 255]);
    let cksum = ip_checksum(&frame[14..34]);
    frame[24..26].copy_from_slice(&cksum.to_be_bytes());

    // UDP header
    let udp_start = 34;
    frame[udp_start..udp_start + 2].copy_from_slice(&67u16.to_be_bytes());
    frame[udp_start + 2..udp_start + 4].copy_from_slice(&68u16.to_be_bytes());
    let udp_len = (8 + dhcp_payload.len()) as u16;
    frame[udp_start + 4..udp_start + 6].copy_from_slice(&udp_len.to_be_bytes());
    // UDP checksum: 0 (optional for IPv4)

    // DHCP payload
    let dhcp_start = udp_start + 8;
    frame[dhcp_start..dhcp_start + dhcp_payload.len()].copy_from_slice(dhcp_payload);

    frame
}

fn ip_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for i in (0..header.len()).step_by(2) {
        if i == 10 {
            continue; // skip checksum field
        }
        let word = if i + 1 < header.len() {
            ((header[i] as u32) << 8) | (header[i + 1] as u32)
        } else {
            (header[i] as u32) << 8
        };
        sum += word;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !sum as u16
}

/// Build a minimal DHCP DISCOVER Ethernet frame for testing.
#[cfg(test)]
pub(crate) fn build_test_dhcp_frame(msg_type: u8) -> Vec<u8> {
    let guest_mac: [u8; 6] = [0x52, 0x54, 0x00, 0xAB, 0xCD, 0xEF];
    let mut frame = vec![0u8; 300];

    // Ethernet header
    frame[0..6].copy_from_slice(&[0xFF; 6]); // broadcast
    frame[6..12].copy_from_slice(&guest_mac);
    frame[12..14].copy_from_slice(&[0x08, 0x00]); // IPv4

    // IPv4 header
    frame[14] = 0x45;
    let ip_total = (20 + 8 + (300 - 42)) as u16;
    frame[16..18].copy_from_slice(&ip_total.to_be_bytes());
    frame[22] = 64; // TTL
    frame[23] = 17; // UDP

    // UDP header
    frame[34..36].copy_from_slice(&68u16.to_be_bytes()); // src: client
    frame[36..38].copy_from_slice(&67u16.to_be_bytes()); // dst: server

    // DHCP payload starts at offset 42
    let dhcp = &mut frame[42..];
    dhcp[0] = 1; // BOOTREQUEST
    dhcp[1] = 1; // Ethernet
    dhcp[2] = 6; // HW addr len
    dhcp[4..8].copy_from_slice(&[0x12, 0x34, 0x56, 0x78]); // xid
    dhcp[28..34].copy_from_slice(&guest_mac); // chaddr

    // Magic cookie
    dhcp[236..240].copy_from_slice(&[99, 130, 83, 99]);

    // Option 53: msg type
    dhcp[240] = 53;
    dhcp[241] = 1;
    dhcp[242] = msg_type;
    dhcp[243] = 255; // end

    frame
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> DhcpConfig {
        DhcpConfig {
            backend_mac: [0x52, 0x54, 0x00, 0x12, 0x34, 0x56],
            gateway_ip: Ipv4Addr::new(10, 0, 2, 1),
            guest_ip: Ipv4Addr::new(10, 0, 2, 15),
        }
    }

    #[test]
    fn test_try_handle_dhcp_discover() {
        let frame = build_test_dhcp_frame(1); // DISCOVER
        let config = test_config();
        let response = try_handle_dhcp_frame(&frame, &config).expect("should produce OFFER");

        // Verify it's an Ethernet frame with IPv4/UDP
        assert_eq!(&response[12..14], &[0x08, 0x00]);
        // Verify UDP src=67, dst=68
        assert_eq!(u16::from_be_bytes([response[34], response[35]]), 67);
        assert_eq!(u16::from_be_bytes([response[36], response[37]]), 68);
        // DHCP reply: offset 42
        let dhcp = &response[42..];
        assert_eq!(dhcp[0], 2); // BOOTREPLY
        // yiaddr should be guest_ip
        assert_eq!(&dhcp[16..20], &[10, 0, 2, 15]);
        // Check DHCP message type option (53) = OFFER (2)
        assert_eq!(find_dhcp_option(dhcp, 53), Some(2));
        // Check subnet mask option (1)
        assert_eq!(&dhcp_option_bytes(dhcp, 1).unwrap(), &[255, 255, 255, 0]);
        // Check router option (3)
        assert_eq!(&dhcp_option_bytes(dhcp, 3).unwrap(), &[10, 0, 2, 1]);
        // Check DNS option (6)
        assert_eq!(&dhcp_option_bytes(dhcp, 6).unwrap(), &[10, 0, 2, 1]);
    }

    #[test]
    fn test_try_handle_dhcp_request() {
        let frame = build_test_dhcp_frame(3); // REQUEST
        let config = test_config();
        let response = try_handle_dhcp_frame(&frame, &config).expect("should produce ACK");
        let dhcp = &response[42..];
        assert_eq!(find_dhcp_option(dhcp, 53), Some(5)); // ACK
    }

    #[test]
    fn test_non_dhcp_frame_returns_none() {
        let config = test_config();
        // ARP frame
        let mut arp = vec![0u8; 42];
        arp[12..14].copy_from_slice(&[0x08, 0x06]); // ARP ethertype
        assert!(try_handle_dhcp_frame(&arp, &config).is_none());

        // TCP frame (not UDP)
        let mut tcp = vec![0u8; 300];
        tcp[12..14].copy_from_slice(&[0x08, 0x00]);
        tcp[14] = 0x45;
        tcp[23] = 6; // TCP protocol
        assert!(try_handle_dhcp_frame(&tcp, &config).is_none());
    }

    #[test]
    fn test_short_frame_returns_none() {
        let config = test_config();
        assert!(try_handle_dhcp_frame(&[0u8; 10], &config).is_none());
        assert!(try_handle_dhcp_frame(&[], &config).is_none());
    }

    /// Extract a multi-byte DHCP option value for test assertions.
    fn dhcp_option_bytes(dhcp_data: &[u8], target_option: u8) -> Option<Vec<u8>> {
        let mut pos = 240;
        while pos < dhcp_data.len() {
            let opt = dhcp_data[pos];
            if opt == 255 {
                break;
            }
            if opt == 0 {
                pos += 1;
                continue;
            }
            if pos + 1 >= dhcp_data.len() {
                break;
            }
            let opt_len = dhcp_data[pos + 1] as usize;
            if opt == target_option {
                return Some(dhcp_data[pos + 2..pos + 2 + opt_len].to_vec());
            }
            pos += 2 + opt_len;
        }
        None
    }
}
