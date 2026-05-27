use smoltcp::phy::{Checksum, Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::time::Instant as SmolInstant;

/// Bridge between the Unix stream socket and smoltcp's packet processing.
///
/// The poll loop feeds frames in via `feed_frame()` and drains generated
/// frames out via `take_tx_frames()`. smoltcp sees this as an Ethernet device.
pub struct VirtioNetDevice {
    rx_buffer: Option<Vec<u8>>,
    tx_queue: Vec<Vec<u8>>,
}

impl VirtioNetDevice {
    pub fn new() -> Self {
        Self {
            rx_buffer: None,
            tx_queue: Vec::new(),
        }
    }

    /// Stage a frame for smoltcp to consume on the next `receive()` call.
    pub fn feed_frame(&mut self, frame: Vec<u8>) {
        self.rx_buffer = Some(frame);
    }

    /// Drain all frames that smoltcp generated during `poll()`.
    pub fn take_tx_frames(&mut self) -> Vec<Vec<u8>> {
        std::mem::take(&mut self.tx_queue)
    }
}

impl Device for VirtioNetDevice {
    type RxToken<'a> = VirtioRxToken<'a>;
    type TxToken<'a> = VirtioTxToken<'a>;

    fn receive(
        &mut self,
        _timestamp: SmolInstant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        if self.rx_buffer.is_some() {
            // Split borrows: rx from rx_buffer, tx to tx_queue
            let rx = VirtioRxToken {
                buffer: &mut self.rx_buffer,
            };
            let tx = VirtioTxToken {
                queue: &mut self.tx_queue,
            };
            Some((rx, tx))
        } else {
            None
        }
    }

    fn transmit(&mut self, _timestamp: SmolInstant) -> Option<Self::TxToken<'_>> {
        Some(VirtioTxToken {
            queue: &mut self.tx_queue,
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ethernet;
        caps.max_transmission_unit = 1500;
        // Generate checksums on outgoing, skip validation on incoming.
        // Guest sends with features=0 (no offloads) so checksums should be correct,
        // but we skip validation to be safe.
        caps.checksum.ipv4 = Checksum::Tx;
        caps.checksum.tcp = Checksum::Tx;
        caps.checksum.udp = Checksum::Tx;
        caps
    }
}

pub struct VirtioRxToken<'a> {
    buffer: &'a mut Option<Vec<u8>>,
}

impl<'a> RxToken for VirtioRxToken<'a> {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        let frame = self.buffer.take().expect("rx_buffer must be Some");
        f(&frame)
    }
}

pub struct VirtioTxToken<'a> {
    queue: &'a mut Vec<Vec<u8>>,
}

impl<'a> TxToken for VirtioTxToken<'a> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut buf = vec![0u8; len];
        let result = f(&mut buf);
        self.queue.push(buf);
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use smoltcp::iface::{Config, Interface, SocketSet};
    use smoltcp::wire::{EthernetAddress, HardwareAddress, IpCidr, Ipv4Cidr};

    #[test]
    fn test_feed_and_receive() {
        let mut dev = VirtioNetDevice::new();
        let frame = vec![0xAA; 64];
        dev.feed_frame(frame.clone());
        let ts = SmolInstant::from_millis(0);
        let (rx, _tx) = dev.receive(ts).expect("should have rx");
        let received = rx.consume(|data| data.to_vec());
        assert_eq!(received, frame);
    }

    #[test]
    fn test_transmit_captures() {
        let mut dev = VirtioNetDevice::new();
        let ts = SmolInstant::from_millis(0);
        let tx = dev.transmit(ts).expect("should have tx");
        tx.consume(10, |buf| {
            buf[0] = 0xFF;
        });
        let frames = dev.take_tx_frames();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].len(), 10);
        assert_eq!(frames[0][0], 0xFF);
    }

    #[test]
    fn test_arp_reply() {
        let mut dev = VirtioNetDevice::new();
        let backend_mac = EthernetAddress([0x52, 0x54, 0x00, 0x12, 0x34, 0x56]);
        let gateway_ip = smoltcp::wire::Ipv4Address::new(10, 0, 2, 1);
        let config = Config::new(HardwareAddress::Ethernet(backend_mac));
        let mut iface = Interface::new(config, &mut dev, SmolInstant::from_millis(0));
        iface.update_ip_addrs(|addrs| {
            addrs
                .push(IpCidr::Ipv4(Ipv4Cidr::new(gateway_ip, 24)))
                .unwrap();
        });

        // Build an ARP request: who-has 10.0.2.1 tell 10.0.2.15
        let guest_mac: [u8; 6] = [0x52, 0x54, 0x00, 0xAB, 0xCD, 0xEF];
        let mut arp_frame = vec![0u8; 42]; // 14 (eth) + 28 (arp)
        // Ethernet header
        arp_frame[0..6].copy_from_slice(&[0xFF; 6]); // dst: broadcast
        arp_frame[6..12].copy_from_slice(&guest_mac); // src
        arp_frame[12..14].copy_from_slice(&[0x08, 0x06]); // EtherType: ARP
        // ARP payload
        arp_frame[14..16].copy_from_slice(&[0x00, 0x01]); // HTYPE: Ethernet
        arp_frame[16..18].copy_from_slice(&[0x08, 0x00]); // PTYPE: IPv4
        arp_frame[18] = 6; // HLEN
        arp_frame[19] = 4; // PLEN
        arp_frame[20..22].copy_from_slice(&[0x00, 0x01]); // OPER: request
        arp_frame[22..28].copy_from_slice(&guest_mac); // SHA
        arp_frame[28..32].copy_from_slice(&[10, 0, 2, 15]); // SPA
        arp_frame[32..38].copy_from_slice(&[0x00; 6]); // THA
        arp_frame[38..42].copy_from_slice(&[10, 0, 2, 1]); // TPA

        dev.feed_frame(arp_frame);
        let mut sockets = SocketSet::new(vec![]);
        iface.poll(SmolInstant::from_millis(1), &mut dev, &mut sockets);

        let tx_frames = dev.take_tx_frames();
        assert!(!tx_frames.is_empty(), "expected ARP reply");
        // Verify the reply is an ARP response (EtherType 0x0806, OPER=2)
        let reply = &tx_frames[0];
        assert_eq!(&reply[12..14], &[0x08, 0x06]);
        assert_eq!(&reply[20..22], &[0x00, 0x02]); // ARP reply
    }
}
