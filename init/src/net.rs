use std::fs;
use std::io;
use std::net::Ipv4Addr;
use std::thread;
use std::time::Duration;

use crate::Error;

const RETRY_ATTEMPTS: u32 = 10;
const RETRY_DELAY: Duration = Duration::from_millis(200);

/// Discover the virtio-net interface by scanning /sys/class/net/.
/// Retries up to 10 times with 200ms delay for boot-time device race.
pub fn find_virtio_net_interface() -> Result<String, Error> {
    for attempt in 0..RETRY_ATTEMPTS {
        if let Some(name) = try_find_virtio_net() {
            return Ok(name);
        }
        if attempt < RETRY_ATTEMPTS - 1 {
            thread::sleep(RETRY_DELAY);
        }
    }
    Err(Error::Io(io::Error::new(
        io::ErrorKind::NotFound,
        "no virtio-net interface found after retries",
    )))
}

fn try_find_virtio_net() -> Option<String> {
    let entries = fs::read_dir("/sys/class/net/").ok()?;
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if name == "lo" {
            continue;
        }
        // Check if this is a virtio device
        let device_path = format!("/sys/class/net/{name}/device");
        if let Ok(resolved) = fs::read_link(&device_path) {
            let resolved_str = resolved.to_string_lossy();
            if resolved_str.contains("virtio") {
                return Some(name);
            }
        }
    }
    None
}

pub fn get_mac_address(ifname: &str) -> Result<[u8; 6], Error> {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if fd < 0 {
        return Err(Error::Io(io::Error::last_os_error()));
    }

    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    set_ifr_name(&mut ifr, ifname)?;

    let ret = unsafe { libc::ioctl(fd, libc::SIOCGIFHWADDR, &mut ifr) };
    unsafe { libc::close(fd) };
    if ret < 0 {
        return Err(Error::Io(io::Error::last_os_error()));
    }

    let mut mac = [0u8; 6];
    unsafe {
        mac.copy_from_slice(
            &ifr.ifr_ifru.ifru_hwaddr.sa_data[..6]
                .iter()
                .map(|&b| b as u8)
                .collect::<Vec<u8>>(),
        );
    }
    Ok(mac)
}

pub fn set_interface_up(ifname: &str) -> Result<(), Error> {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if fd < 0 {
        return Err(Error::Io(io::Error::last_os_error()));
    }

    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    set_ifr_name(&mut ifr, ifname)?;

    // Get current flags
    let ret = unsafe { libc::ioctl(fd, libc::SIOCGIFFLAGS, &mut ifr) };
    if ret < 0 {
        unsafe { libc::close(fd) };
        return Err(Error::Io(io::Error::last_os_error()));
    }

    // Set IFF_UP
    unsafe {
        ifr.ifr_ifru.ifru_flags |= libc::IFF_UP as i16;
    }
    let ret = unsafe { libc::ioctl(fd, libc::SIOCSIFFLAGS, &ifr) };
    unsafe { libc::close(fd) };
    if ret < 0 {
        return Err(Error::Io(io::Error::last_os_error()));
    }
    Ok(())
}

pub fn set_interface_addr(ifname: &str, addr: Ipv4Addr, mask: Ipv4Addr) -> Result<(), Error> {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if fd < 0 {
        return Err(Error::Io(io::Error::last_os_error()));
    }

    // Set address
    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    set_ifr_name(&mut ifr, ifname)?;
    set_sockaddr_in(&mut ifr, addr);
    let ret = unsafe { libc::ioctl(fd, libc::SIOCSIFADDR, &ifr) };
    if ret < 0 {
        unsafe { libc::close(fd) };
        return Err(Error::Io(io::Error::last_os_error()));
    }

    // Set netmask
    let mut ifr_mask: libc::ifreq = unsafe { std::mem::zeroed() };
    set_ifr_name(&mut ifr_mask, ifname)?;
    set_sockaddr_in(&mut ifr_mask, mask);
    let ret = unsafe { libc::ioctl(fd, libc::SIOCSIFNETMASK, &ifr_mask) };
    unsafe { libc::close(fd) };
    if ret < 0 {
        return Err(Error::Io(io::Error::last_os_error()));
    }
    Ok(())
}

pub fn add_default_route(gateway: Ipv4Addr) -> Result<(), Error> {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if fd < 0 {
        return Err(Error::Io(io::Error::last_os_error()));
    }

    let mut rt: libc::rtentry = unsafe { std::mem::zeroed() };

    // Destination: 0.0.0.0 (default route)
    let dst = &mut rt.rt_dst as *mut libc::sockaddr as *mut libc::sockaddr_in;
    unsafe {
        (*dst).sin_family = libc::AF_INET as u16;
        (*dst).sin_addr.s_addr = 0;
    }

    // Gateway
    let gw = &mut rt.rt_gateway as *mut libc::sockaddr as *mut libc::sockaddr_in;
    unsafe {
        (*gw).sin_family = libc::AF_INET as u16;
        (*gw).sin_addr.s_addr = u32::from(gateway).to_be();
    }

    // Netmask: 0.0.0.0
    let mask = &mut rt.rt_genmask as *mut libc::sockaddr as *mut libc::sockaddr_in;
    unsafe {
        (*mask).sin_family = libc::AF_INET as u16;
        (*mask).sin_addr.s_addr = 0;
    }

    rt.rt_flags = libc::RTF_UP | libc::RTF_GATEWAY;

    let ret = unsafe { libc::ioctl(fd, libc::SIOCADDRT, &rt) };
    unsafe { libc::close(fd) };
    if ret < 0 {
        return Err(Error::Io(io::Error::last_os_error()));
    }
    Ok(())
}

pub fn write_resolv_conf(dns_servers: &[Ipv4Addr]) -> Result<(), Error> {
    let mut content = String::new();
    for dns in dns_servers {
        content.push_str(&format!("nameserver {dns}\n"));
    }
    fs::write("/etc/resolv.conf", content).map_err(Error::Io)
}

fn set_ifr_name(ifr: &mut libc::ifreq, name: &str) -> Result<(), Error> {
    let bytes = name.as_bytes();
    if bytes.len() >= libc::IFNAMSIZ {
        return Err(Error::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "interface name too long",
        )));
    }
    unsafe {
        std::ptr::copy_nonoverlapping(
            bytes.as_ptr(),
            ifr.ifr_name.as_mut_ptr() as *mut u8,
            bytes.len(),
        );
    }
    Ok(())
}

fn set_sockaddr_in(ifr: &mut libc::ifreq, addr: Ipv4Addr) {
    let sa = &mut ifr.ifr_ifru as *mut _ as *mut libc::sockaddr_in;
    unsafe {
        (*sa).sin_family = libc::AF_INET as u16;
        (*sa).sin_addr.s_addr = u32::from(addr).to_be();
    }
}
