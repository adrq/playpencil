use std::ffi::CString;
use std::fs;
use std::io;

use crate::Error;

pub fn bootstrap_mounts() -> Result<(), Error> {
    // /proc first — we need /proc/mounts for subsequent checks
    ensure_dir("/proc")?;
    match try_mount("proc", "/proc", "proc", 0) {
        Ok(()) => {}
        Err(Error::Io(ref e)) if e.raw_os_error() == Some(libc::EBUSY) => {}
        Err(e) => return Err(e),
    }

    // /sys
    ensure_dir("/sys")?;
    match is_mounted("/sys")? {
        Some(ref fstype) if fstype == "sysfs" => {}
        _ => try_mount("sysfs", "/sys", "sysfs", 0)?,
    }

    // /dev — must be devtmpfs for virtio-console device nodes
    ensure_dir("/dev")?;
    match is_mounted("/dev")? {
        Some(ref fstype) if fstype == "devtmpfs" => {}
        _ => try_mount("devtmpfs", "/dev", "devtmpfs", 0)?,
    }

    // Compatibility symlinks
    create_dev_symlinks();

    // /dev/pts
    ensure_dir("/dev/pts")?;
    match is_mounted("/dev/pts")? {
        Some(_) => {}
        None => try_mount("devpts", "/dev/pts", "devpts", 0)?,
    }

    Ok(())
}

fn try_mount(source: &str, target: &str, fstype: &str, flags: u64) -> Result<(), Error> {
    let c_source = CString::new(source).map_err(|e| Error::Io(io::Error::other(e)))?;
    let c_target = CString::new(target).map_err(|e| Error::Io(io::Error::other(e)))?;
    let c_fstype = CString::new(fstype).map_err(|e| Error::Io(io::Error::other(e)))?;

    let ret = unsafe {
        libc::mount(
            c_source.as_ptr(),
            c_target.as_ptr(),
            c_fstype.as_ptr(),
            flags,
            std::ptr::null(),
        )
    };
    if ret < 0 {
        return Err(Error::Io(io::Error::last_os_error()));
    }
    Ok(())
}

fn ensure_dir(path: &str) -> Result<(), Error> {
    match fs::create_dir_all(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(()),
        Err(e) => Err(Error::Io(e)),
    }
}

/// Check /proc/mounts for a mounted filesystem at the given target.
/// Returns the filesystem type if mounted, None otherwise.
fn is_mounted(target: &str) -> Result<Option<String>, Error> {
    let content = match fs::read_to_string("/proc/mounts") {
        Ok(c) => c,
        Err(e) => return Err(Error::Io(e)),
    };
    for line in content.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 3 && parts[1] == target {
            return Ok(Some(parts[2].to_string()));
        }
    }
    Ok(None)
}

fn create_dev_symlinks() {
    let links = [
        ("/dev/fd", "/proc/self/fd"),
        ("/dev/stdin", "/proc/self/fd/0"),
        ("/dev/stdout", "/proc/self/fd/1"),
        ("/dev/stderr", "/proc/self/fd/2"),
    ];
    for (link, target) in links {
        // Ignore errors — symlink may already exist
        let _ = std::os::unix::fs::symlink(target, link);
    }
}
