//! Safe Rust wrapper around the libkrun C API (krun-sys FFI bindings).
//!
//! This module provides `KrunCtx`, a thin wrapper that converts Rust types
//! to C types and checks return codes. It has no dependencies on other
//! modules in this crate — higher-level code translates between domain
//! types and `KrunCtx` calls.

use std::cell::Cell;
use std::ffi::{CString, c_char, c_void};
use std::marker::PhantomData;
use std::path::Path;

use std::os::unix::ffi::OsStrExt;

#[derive(Debug, thiserror::Error)]
pub enum KrunError {
    /// libkrun FFI call returned a negative error code.
    #[error("{call} failed (code {code})")]
    Ffi { call: &'static str, code: i32 },

    /// Path contained interior NUL bytes.
    #[error("invalid path (interior NUL): {0}")]
    InvalidPath(String),

    /// String argument contained interior NUL bytes.
    #[error("invalid string argument: {0}")]
    InvalidString(#[from] std::ffi::NulError),

    /// fork() failed.
    #[error("fork failed: {0}")]
    Fork(std::io::Error),
}

pub type Result<T> = std::result::Result<T, KrunError>;

/// Check a zero-success FFI return value.
fn check_ret(call: &'static str, ret: i32) -> Result<()> {
    if ret < 0 {
        Err(KrunError::Ffi { call, code: ret })
    } else {
        Ok(())
    }
}

/// Check an ID-returning FFI call (non-negative = success).
fn check_id(call: &'static str, ret: i32) -> Result<u32> {
    if ret < 0 {
        Err(KrunError::Ffi { call, code: ret })
    } else {
        Ok(ret as u32)
    }
}

/// Convert a `Path` to `CString` using raw OS bytes, so non-UTF-8 paths work.
/// Only fails on interior NUL bytes.
fn path_to_cstring(path: &Path) -> Result<CString> {
    CString::new(path.as_os_str().as_bytes())
        .map_err(|_| KrunError::InvalidPath(path.display().to_string()))
}

/// libkrun reads exactly MAX_ARGS (4096) entries from pointer arrays via
/// `slice::from_raw_parts(ptr, 4096)`. We must allocate the full 4096
/// entries (padded with nulls) to avoid out-of-bounds reads.
const MAX_ARGS: usize = 4096;

/// Build a null-padded C string array from a slice of `&str`.
/// Returns both the owned `CString`s (which must outlive the pointer vec)
/// and the pointer array (always MAX_ARGS entries, null-padded).
fn build_c_string_array(strings: &[&str]) -> Result<(Vec<CString>, Vec<*const c_char>)> {
    if strings.len() >= MAX_ARGS {
        return Err(KrunError::Ffi {
            call: "build_c_string_array",
            code: -libc::E2BIG,
        });
    }
    let c_strings: Vec<CString> = strings
        .iter()
        .map(|s| CString::new(*s))
        .collect::<std::result::Result<_, _>>()?;
    let mut ptrs: Vec<*const c_char> = Vec::with_capacity(MAX_ARGS);
    ptrs.extend(c_strings.iter().map(|s| s.as_ptr()));
    ptrs.resize(MAX_ARGS, std::ptr::null());
    Ok((c_strings, ptrs))
}

/// Owned storage for an optional null-terminated C string array.
/// Keeps the CStrings alive while the pointer vec is in use.
struct OptionalCStringArray {
    /// Must be kept alive so ptrs remain valid.
    _strings: Option<Vec<CString>>,
    _ptrs: Option<Vec<*const c_char>>,
    ptr: *const *const c_char,
}

/// Build a null-terminated C string array, or return a null pointer for `None`.
fn build_optional_c_string_array(strings: Option<&[&str]>) -> Result<OptionalCStringArray> {
    match strings {
        Some(s) => {
            let (c_strings, ptrs) = build_c_string_array(s)?;
            let ptr = ptrs.as_ptr();
            Ok(OptionalCStringArray {
                _strings: Some(c_strings),
                _ptrs: Some(ptrs),
                ptr,
            })
        }
        None => Ok(OptionalCStringArray {
            _strings: None,
            _ptrs: None,
            ptr: std::ptr::null(),
        }),
    }
}

/// Wrapper around a libkrun context ID.
///
/// All unsafe libkrun FFI calls are wrapped in safe methods that convert
/// Rust types to C types and check return codes. The context is freed on
/// drop via `krun_free_ctx`.
///
/// Configuration methods take `&mut self` because they mutate hidden
/// libkrun state through the context ID. This enforces exclusive access
/// at the type level, preventing data races from concurrent calls.
pub struct KrunCtx {
    id: u32,
    _not_sync: PhantomData<Cell<()>>,
}

impl KrunCtx {
    /// Create a new libkrun context.
    pub fn new() -> Result<Self> {
        let ret = unsafe { krun_sys::krun_create_ctx() };
        let id = check_id("krun_create_ctx", ret)?;
        Ok(Self {
            id,
            _not_sync: PhantomData,
        })
    }

    /// Set the global log level. Not tied to a context.
    /// Level: 0=off, 1=error, 2=warn, 3=info, 4=debug, 5=trace.
    pub fn set_log_level(level: u32) -> Result<()> {
        check_ret("krun_set_log_level", unsafe {
            krun_sys::krun_set_log_level(level)
        })
    }

    /// Initialize structured logging.
    /// `target_fd`: fd to write logs to, or -1 (KRUN_LOG_TARGET_DEFAULT) for stderr.
    /// `level`: verbosity (KRUN_LOG_LEVEL_*).
    /// `style`: terminal escape sequences (KRUN_LOG_STYLE_*).
    /// `options`: bitmask (e.g., KRUN_LOG_OPTION_NO_ENV).
    pub fn init_log(target_fd: i32, level: u32, style: u32, options: u32) -> Result<()> {
        check_ret("krun_init_log", unsafe {
            krun_sys::krun_init_log(target_fd, level, style, options)
        })
    }

    /// Get the maximum number of vCPUs supported by the hypervisor.
    pub fn get_max_vcpus() -> Result<u32> {
        check_id("krun_get_max_vcpus", unsafe {
            krun_sys::krun_get_max_vcpus()
        })
    }

    /// Check if a build-time feature is enabled (KRUN_FEATURE_* constants).
    pub fn has_feature(feature: u64) -> Result<bool> {
        let ret = unsafe { krun_sys::krun_has_feature(feature) };
        if ret < 0 {
            Err(KrunError::Ffi {
                call: "krun_has_feature",
                code: ret,
            })
        } else {
            Ok(ret != 0)
        }
    }

    /// Check if nested virtualization is supported on this system.
    pub fn check_nested_virt() -> Result<bool> {
        let ret = unsafe { krun_sys::krun_check_nested_virt() };
        if ret < 0 {
            Err(KrunError::Ffi {
                call: "krun_check_nested_virt",
                code: ret,
            })
        } else {
            Ok(ret != 0)
        }
    }

    /// Get the eventfd for signaling guest shutdown. Must be called
    /// before `start()`. Returns the fd.
    pub fn get_shutdown_eventfd(&mut self) -> Result<i32> {
        let ret = unsafe { krun_sys::krun_get_shutdown_eventfd(self.id) };
        if ret < 0 {
            Err(KrunError::Ffi {
                call: "krun_get_shutdown_eventfd",
                code: ret,
            })
        } else {
            Ok(ret)
        }
    }

    /// Configure vCPUs and memory (MiB).
    pub fn set_vm_config(&mut self, vcpus: u8, ram_mib: u32) -> Result<()> {
        check_ret("krun_set_vm_config", unsafe {
            krun_sys::krun_set_vm_config(self.id, vcpus, ram_mib)
        })
    }

    /// Set a custom kernel to load.
    /// `kernel_format`: KRUN_KERNEL_FORMAT_* constant.
    /// `initramfs`: path to initramfs, or `None`.
    /// `cmdline`: kernel command line, or `None`.
    pub fn set_kernel(
        &mut self,
        kernel_path: &Path,
        kernel_format: u32,
        initramfs: Option<&Path>,
        cmdline: Option<&str>,
    ) -> Result<()> {
        let c_kernel = path_to_cstring(kernel_path)?;
        let c_initramfs = initramfs.map(path_to_cstring).transpose()?;
        let c_cmdline = cmdline.map(CString::new).transpose()?;

        check_ret("krun_set_kernel", unsafe {
            krun_sys::krun_set_kernel(
                self.id,
                c_kernel.as_ptr(),
                kernel_format,
                c_initramfs
                    .as_ref()
                    .map_or(std::ptr::null(), |s| s.as_ptr()),
                c_cmdline.as_ref().map_or(std::ptr::null(), |s| s.as_ptr()),
            )
        })
    }

    /// Set the firmware image path (host filesystem).
    pub fn set_firmware(&mut self, firmware_path: &Path) -> Result<()> {
        let c_path = path_to_cstring(firmware_path)?;
        check_ret("krun_set_firmware", unsafe {
            krun_sys::krun_set_firmware(self.id, c_path.as_ptr())
        })
    }

    /// Split IRQCHIP responsibilities between host and guest.
    pub fn split_irqchip(&mut self, enable: bool) -> Result<()> {
        check_ret("krun_split_irqchip", unsafe {
            krun_sys::krun_split_irqchip(self.id, enable)
        })
    }

    /// Enable nested virtualization in the microVM. Success does not
    /// guarantee the host supports it — only that it will be requested.
    pub fn set_nested_virt(&mut self, enabled: bool) -> Result<()> {
        check_ret("krun_set_nested_virt", unsafe {
            krun_sys::krun_set_nested_virt(self.id, enabled)
        })
    }

    /// Set SMBIOS OEM strings.
    pub fn set_smbios_oem_strings(&mut self, strings: &[&str]) -> Result<()> {
        let (_c_strings, ptrs) = build_c_string_array(strings)?;
        check_ret("krun_set_smbios_oem_strings", unsafe {
            krun_sys::krun_set_smbios_oem_strings(self.id, ptrs.as_ptr())
        })
    }

    /// Set TEE configuration file path (libkrun-sev only).
    pub fn set_tee_config_file(&mut self, path: &Path) -> Result<()> {
        let c_path = path_to_cstring(path)?;
        check_ret("krun_set_tee_config_file", unsafe {
            krun_sys::krun_set_tee_config_file(self.id, c_path.as_ptr())
        })
    }

    /// Set uid to drop to right before the microVM starts.
    pub fn setuid(&mut self, uid: u32) -> Result<()> {
        check_ret("krun_setuid", unsafe {
            krun_sys::krun_setuid(self.id, uid)
        })
    }

    /// Set gid to drop to right before the microVM starts.
    pub fn setgid(&mut self, gid: u32) -> Result<()> {
        check_ret("krun_setgid", unsafe {
            krun_sys::krun_setgid(self.id, gid)
        })
    }

    /// Set resource limits for the guest ("RESOURCE=RLIM_CUR:RLIM_MAX" strings).
    pub fn set_rlimits(&mut self, rlimits: &[&str]) -> Result<()> {
        let (_c_strings, ptrs) = build_c_string_array(rlimits)?;
        check_ret("krun_set_rlimits", unsafe {
            krun_sys::krun_set_rlimits(self.id, ptrs.as_ptr())
        })
    }

    /// Set the root filesystem path (virtio-fs mount at "/").
    pub fn set_root(&mut self, path: &Path) -> Result<()> {
        let c_path = path_to_cstring(path)?;
        check_ret("krun_set_root", unsafe {
            krun_sys::krun_set_root(self.id, c_path.as_ptr())
        })
    }

    /// Redirect VM console output to a file.
    /// Only affects the implicit console. No-op if the implicit console
    /// has been disabled via `disable_implicit_console()`.
    pub fn set_console_output(&mut self, path: &Path) -> Result<()> {
        let c_path = path_to_cstring(path)?;
        check_ret("krun_set_console_output", unsafe {
            krun_sys::krun_set_console_output(self.id, c_path.as_ptr())
        })
    }

    /// Add a virtio-fs shared directory with a tag.
    pub fn add_virtiofs(&mut self, tag: &str, path: &Path) -> Result<()> {
        let c_tag = CString::new(tag)?;
        let c_path = path_to_cstring(path)?;
        check_ret("krun_add_virtiofs", unsafe {
            krun_sys::krun_add_virtiofs(self.id, c_tag.as_ptr(), c_path.as_ptr())
        })
    }

    /// Add a virtio-fs shared directory with explicit DAX window size.
    pub fn add_virtiofs2(&mut self, tag: &str, path: &Path, shm_size: u64) -> Result<()> {
        let c_tag = CString::new(tag)?;
        let c_path = path_to_cstring(path)?;
        check_ret("krun_add_virtiofs2", unsafe {
            krun_sys::krun_add_virtiofs2(self.id, c_tag.as_ptr(), c_path.as_ptr(), shm_size)
        })
    }

    /// Add a virtio-fs shared directory with explicit DAX window size and
    /// read-only control. `shm_size` of 0 disables the DAX window.
    pub fn add_virtiofs3(
        &mut self,
        tag: &str,
        path: &Path,
        shm_size: u64,
        read_only: bool,
    ) -> Result<()> {
        let c_tag = CString::new(tag)?;
        let c_path = path_to_cstring(path)?;
        check_ret("krun_add_virtiofs3", unsafe {
            krun_sys::krun_add_virtiofs3(
                self.id,
                c_tag.as_ptr(),
                c_path.as_ptr(),
                shm_size,
                read_only,
            )
        })
    }

    /// Set mapped volumes ("host_path:guest_path" strings).
    ///
    /// Deprecated on Linux — only functional on macOS. Prefer
    /// `add_virtiofs()` / `add_virtiofs3()` for shared directories.
    pub fn set_mapped_volumes(&mut self, volumes: &[&str]) -> Result<()> {
        let (_c_strings, ptrs) = build_c_string_array(volumes)?;
        check_ret("krun_set_mapped_volumes", unsafe {
            krun_sys::krun_set_mapped_volumes(self.id, ptrs.as_ptr())
        })
    }

    /// Set a root disk image (block device). Deprecated — use `add_disk()`.
    pub fn set_root_disk(&mut self, path: &Path) -> Result<()> {
        let c_path = path_to_cstring(path)?;
        check_ret("krun_set_root_disk", unsafe {
            krun_sys::krun_set_root_disk(self.id, c_path.as_ptr())
        })
    }

    /// Set a data disk image. Deprecated — use `add_disk()`.
    pub fn set_data_disk(&mut self, path: &Path) -> Result<()> {
        let c_path = path_to_cstring(path)?;
        check_ret("krun_set_data_disk", unsafe {
            krun_sys::krun_set_data_disk(self.id, c_path.as_ptr())
        })
    }

    /// Add a raw disk image. `block_id`: partition identifier string.
    pub fn add_disk(&mut self, block_id: &str, disk_path: &Path, read_only: bool) -> Result<()> {
        let c_block_id = CString::new(block_id)?;
        let c_path = path_to_cstring(disk_path)?;
        check_ret("krun_add_disk", unsafe {
            krun_sys::krun_add_disk(self.id, c_block_id.as_ptr(), c_path.as_ptr(), read_only)
        })
    }

    /// Add a disk image with format selection (KRUN_DISK_FORMAT_* constants).
    /// See libkrun docs for security implications of non-raw formats.
    pub fn add_disk2(
        &mut self,
        block_id: &str,
        disk_path: &Path,
        disk_format: u32,
        read_only: bool,
    ) -> Result<()> {
        let c_block_id = CString::new(block_id)?;
        let c_path = path_to_cstring(disk_path)?;
        check_ret("krun_add_disk2", unsafe {
            krun_sys::krun_add_disk2(
                self.id,
                c_block_id.as_ptr(),
                c_path.as_ptr(),
                disk_format,
                read_only,
            )
        })
    }

    /// Add a disk image with format, direct I/O, and sync mode control.
    /// `sync_mode`: KRUN_SYNC_* constant.
    pub fn add_disk3(
        &mut self,
        block_id: &str,
        disk_path: &Path,
        disk_format: u32,
        read_only: bool,
        direct_io: bool,
        sync_mode: u32,
    ) -> Result<()> {
        let c_block_id = CString::new(block_id)?;
        let c_path = path_to_cstring(disk_path)?;
        check_ret("krun_add_disk3", unsafe {
            krun_sys::krun_add_disk3(
                self.id,
                c_block_id.as_ptr(),
                c_path.as_ptr(),
                disk_format,
                read_only,
                direct_io,
                sync_mode,
            )
        })
    }

    /// Configure a block device as root filesystem, remounting from
    /// the initial virtio-fs root.
    /// `device`: e.g., "/dev/vda1". `fstype`: e.g., "ext4" or `None` for auto.
    /// `options`: comma-separated mount options or `None`.
    pub fn set_root_disk_remount(
        &mut self,
        device: &str,
        fstype: Option<&str>,
        options: Option<&str>,
    ) -> Result<()> {
        let c_device = CString::new(device)?;
        let c_fstype = fstype.map(CString::new).transpose()?;
        let c_options = options.map(CString::new).transpose()?;
        check_ret("krun_set_root_disk_remount", unsafe {
            krun_sys::krun_set_root_disk_remount(
                self.id,
                c_device.as_ptr(),
                c_fstype.as_ref().map_or(std::ptr::null(), |s| s.as_ptr()),
                c_options.as_ref().map_or(std::ptr::null(), |s| s.as_ptr()),
            )
        })
    }

    /// Set the working directory inside the guest.
    pub fn set_workdir(&mut self, path: &str) -> Result<()> {
        let c_path = CString::new(path)?;
        check_ret("krun_set_workdir", unsafe {
            krun_sys::krun_set_workdir(self.id, c_path.as_ptr())
        })
    }

    /// Set the command to execute inside the guest.
    /// `exec_path`: path to the executable, relative to the root configured
    /// with `set_root()`.
    /// `argv`: arguments after the program name (argv[1..]).
    /// `envp`: environment variables as "KEY=VALUE" strings.
    /// `None` means inherit all host environment variables (passed as NULL
    /// to libkrun — beware: this serializes the entire host env into the
    /// kernel command line, which can overflow).
    pub fn set_exec(
        &mut self,
        exec_path: &str,
        argv: &[&str],
        envp: Option<&[&str]>,
    ) -> Result<()> {
        let c_exec = CString::new(exec_path)?;
        let (_c_argv, argv_ptrs) = build_c_string_array(argv)?;
        let envp_arr = build_optional_c_string_array(envp)?;

        check_ret("krun_set_exec", unsafe {
            krun_sys::krun_set_exec(self.id, c_exec.as_ptr(), argv_ptrs.as_ptr(), envp_arr.ptr)
        })
    }

    /// Set environment variables for the guest ("KEY=VALUE" strings).
    /// `None` means inherit host environment variables (NULL to libkrun).
    pub fn set_env(&mut self, env: Option<&[&str]>) -> Result<()> {
        let arr = build_optional_c_string_array(env)?;
        check_ret("krun_set_env", unsafe {
            krun_sys::krun_set_env(self.id, arr.ptr)
        })
    }

    /// Add a virtio-net device over a pre-opened Unix stream socket.
    /// `path` and `fd` are mutually exclusive — pass `fd=-1` to use path, or
    /// `path=None` to use fd.
    /// `mac`: 6-byte MAC address. `features`: virtio-net feature flags (0 = none).
    pub fn add_net_unixstream(
        &mut self,
        path: Option<&Path>,
        fd: i32,
        mac: &[u8; 6],
        features: u32,
        flags: u32,
    ) -> Result<()> {
        if !(path.is_some() && fd == -1 || path.is_none() && fd >= 0) {
            return Err(KrunError::InvalidPath(
                "exactly one of path or fd must be specified".into(),
            ));
        }
        let c_path = path.map(path_to_cstring).transpose()?;
        let mut mac_copy = *mac;
        check_ret("krun_add_net_unixstream", unsafe {
            krun_sys::krun_add_net_unixstream(
                self.id,
                c_path.as_ref().map_or(std::ptr::null(), |s| s.as_ptr()),
                fd,
                mac_copy.as_mut_ptr(),
                features,
                flags,
            )
        })
    }

    /// Add a virtio-net device over a Unix datagram socket (gvproxy/vmnet-helper).
    /// Same path/fd mutual exclusion as `add_net_unixstream`.
    pub fn add_net_unixgram(
        &mut self,
        path: Option<&Path>,
        fd: i32,
        mac: &[u8; 6],
        features: u32,
        flags: u32,
    ) -> Result<()> {
        if !(path.is_some() && fd == -1 || path.is_none() && fd >= 0) {
            return Err(KrunError::InvalidPath(
                "exactly one of path or fd must be specified".into(),
            ));
        }
        let c_path = path.map(path_to_cstring).transpose()?;
        let mut mac_copy = *mac;
        check_ret("krun_add_net_unixgram", unsafe {
            krun_sys::krun_add_net_unixgram(
                self.id,
                c_path.as_ref().map_or(std::ptr::null(), |s| s.as_ptr()),
                fd,
                mac_copy.as_mut_ptr(),
                features,
                flags,
            )
        })
    }

    /// Add a virtio-net device over a tap device.
    pub fn add_net_tap(
        &mut self,
        tap_name: &str,
        mac: &[u8; 6],
        features: u32,
        flags: u32,
    ) -> Result<()> {
        let mut c_tap = CString::new(tap_name)?.into_bytes_with_nul();
        let mut mac_copy = *mac;
        check_ret("krun_add_net_tap", unsafe {
            krun_sys::krun_add_net_tap(
                self.id,
                c_tap.as_mut_ptr() as *mut c_char,
                mac_copy.as_mut_ptr(),
                features,
                flags,
            )
        })
    }

    /// Configure networking via passt. Deprecated — use `add_net_unixstream`.
    pub fn set_passt_fd(&mut self, fd: i32) -> Result<()> {
        check_ret("krun_set_passt_fd", unsafe {
            krun_sys::krun_set_passt_fd(self.id, fd)
        })
    }

    /// Configure networking via gvproxy. Deprecated — use `add_net_unixgram`.
    pub fn set_gvproxy_path(&mut self, path: &Path) -> Result<()> {
        let c_path = path_to_cstring(path)?;
        let mut bytes = c_path.into_bytes_with_nul();
        check_ret("krun_set_gvproxy_path", unsafe {
            krun_sys::krun_set_gvproxy_path(self.id, bytes.as_mut_ptr() as *mut c_char)
        })
    }

    /// Set MAC address for the virtio-net device (passt backend).
    pub fn set_net_mac(&mut self, mac: &[u8; 6]) -> Result<()> {
        let mut mac_copy = *mac;
        check_ret("krun_set_net_mac", unsafe {
            krun_sys::krun_set_net_mac(self.id, mac_copy.as_mut_ptr())
        })
    }

    /// Set TCP port mappings ("host_port:guest_port" strings).
    /// Pass an empty slice to expose no ports. To get the default behavior
    /// (expose all listening guest ports), simply don't call this method.
    pub fn set_port_map(&mut self, ports: &[&str]) -> Result<()> {
        let (_c_strings, ptrs) = build_c_string_array(ports)?;
        check_ret("krun_set_port_map", unsafe {
            krun_sys::krun_set_port_map(self.id, ptrs.as_ptr())
        })
    }

    /// Disable the implicit vsock device. Must be called before `add_vsock()`
    /// if explicit vsock configuration is needed.
    pub fn disable_implicit_vsock(&mut self) -> Result<()> {
        check_ret("krun_disable_implicit_vsock", unsafe {
            krun_sys::krun_disable_implicit_vsock(self.id)
        })
    }

    /// Add a vsock device with the given TSI feature flags
    /// (KRUN_TSI_HIJACK_INET, KRUN_TSI_HIJACK_UNIX, or 0 for none).
    /// Call `disable_implicit_vsock()` first.
    pub fn add_vsock(&mut self, tsi_features: u32) -> Result<()> {
        check_ret("krun_add_vsock", unsafe {
            krun_sys::krun_add_vsock(self.id, tsi_features)
        })
    }

    /// Bind a vsock port to a Unix socket path (guest connects to host).
    pub fn add_vsock_port(&mut self, port: u32, path: &Path) -> Result<()> {
        let c_path = path_to_cstring(path)?;
        check_ret("krun_add_vsock_port", unsafe {
            krun_sys::krun_add_vsock_port(self.id, port, c_path.as_ptr())
        })
    }

    /// Bind a vsock port to a Unix socket path with explicit direction.
    /// `listen`: true if host initiates connections to the guest.
    pub fn add_vsock_port2(&mut self, port: u32, path: &Path, listen: bool) -> Result<()> {
        let c_path = path_to_cstring(path)?;
        check_ret("krun_add_vsock_port2", unsafe {
            krun_sys::krun_add_vsock_port2(self.id, port, c_path.as_ptr(), listen)
        })
    }

    /// Disable the implicit console device. Call before adding explicit
    /// console devices.
    pub fn disable_implicit_console(&mut self) -> Result<()> {
        check_ret("krun_disable_implicit_console", unsafe {
            krun_sys::krun_disable_implicit_console(self.id)
        })
    }

    /// Set the kernel console device string (e.g., "hvc0", "ttyS0").
    pub fn set_kernel_console(&mut self, console: &str) -> Result<()> {
        let c_console = CString::new(console)?;
        check_ret("krun_set_kernel_console", unsafe {
            krun_sys::krun_set_kernel_console(self.id, c_console.as_ptr())
        })
    }

    /// Add a default virtio-console device connected to the given fds.
    pub fn add_virtio_console_default(
        &mut self,
        input_fd: i32,
        output_fd: i32,
        err_fd: i32,
    ) -> Result<()> {
        check_ret("krun_add_virtio_console_default", unsafe {
            krun_sys::krun_add_virtio_console_default(self.id, input_fd, output_fd, err_fd)
        })
    }

    /// Add a default serial console device connected to the given fds.
    pub fn add_serial_console_default(&mut self, input_fd: i32, output_fd: i32) -> Result<()> {
        check_ret("krun_add_serial_console_default", unsafe {
            krun_sys::krun_add_serial_console_default(self.id, input_fd, output_fd)
        })
    }

    /// Add a multiport virtio-console device. Returns the console ID.
    pub fn add_virtio_console_multiport(&mut self) -> Result<u32> {
        check_id("krun_add_virtio_console_multiport", unsafe {
            krun_sys::krun_add_virtio_console_multiport(self.id)
        })
    }

    /// Add a TTY port to a multiport console.
    pub fn add_console_port_tty(&mut self, console_id: u32, name: &str, tty_fd: i32) -> Result<()> {
        let c_name = CString::new(name)?;
        check_ret("krun_add_console_port_tty", unsafe {
            krun_sys::krun_add_console_port_tty(self.id, console_id, c_name.as_ptr(), tty_fd)
        })
    }

    /// Add an input/output port to a multiport console.
    pub fn add_console_port_inout(
        &mut self,
        console_id: u32,
        name: &str,
        input_fd: i32,
        output_fd: i32,
    ) -> Result<()> {
        let c_name = CString::new(name)?;
        check_ret("krun_add_console_port_inout", unsafe {
            krun_sys::krun_add_console_port_inout(
                self.id,
                console_id,
                c_name.as_ptr(),
                input_fd,
                output_fd,
            )
        })
    }

    /// Enable virtio-gpu with virglrenderer flags.
    pub fn set_gpu_options(&mut self, virgl_flags: u32) -> Result<()> {
        check_ret("krun_set_gpu_options", unsafe {
            krun_sys::krun_set_gpu_options(self.id, virgl_flags)
        })
    }

    /// Enable virtio-gpu with virglrenderer flags and SHM window size.
    pub fn set_gpu_options2(&mut self, virgl_flags: u32, shm_size: u64) -> Result<()> {
        check_ret("krun_set_gpu_options2", unsafe {
            krun_sys::krun_set_gpu_options2(self.id, virgl_flags, shm_size)
        })
    }

    /// Add a display output. Returns the display ID (0..KRUN_MAX_DISPLAYS-1).
    pub fn add_display(&mut self, width: u32, height: u32) -> Result<u32> {
        check_id("krun_add_display", unsafe {
            krun_sys::krun_add_display(self.id, width, height)
        })
    }

    /// Set a custom EDID blob for a display. Replaces the generated EDID.
    pub fn display_set_edid(&mut self, display_id: u32, edid_blob: &[u8]) -> Result<()> {
        check_ret("krun_display_set_edid", unsafe {
            krun_sys::krun_display_set_edid(
                self.id,
                display_id,
                edid_blob.as_ptr(),
                edid_blob.len(),
            )
        })
    }

    /// Set display DPI.
    pub fn display_set_dpi(&mut self, display_id: u32, dpi: u32) -> Result<()> {
        check_ret("krun_display_set_dpi", unsafe {
            krun_sys::krun_display_set_dpi(self.id, display_id, dpi)
        })
    }

    /// Set display physical size in millimeters.
    pub fn display_set_physical_size(
        &mut self,
        display_id: u32,
        width_mm: u16,
        height_mm: u16,
    ) -> Result<()> {
        check_ret("krun_display_set_physical_size", unsafe {
            krun_sys::krun_display_set_physical_size(self.id, display_id, width_mm, height_mm)
        })
    }

    /// Set display refresh rate (Hz).
    pub fn display_set_refresh_rate(&mut self, display_id: u32, refresh_rate: u32) -> Result<()> {
        check_ret("krun_display_set_refresh_rate", unsafe {
            krun_sys::krun_display_set_refresh_rate(self.id, display_id, refresh_rate)
        })
    }

    /// Set the display backend.
    ///
    /// # Safety
    /// `backend` must point to a valid, correctly initialized
    /// `krun_display_backend` struct for `backend_size` bytes.
    pub unsafe fn set_display_backend(
        &mut self,
        backend: *const c_void,
        backend_size: usize,
    ) -> Result<()> {
        check_ret("krun_set_display_backend", unsafe {
            krun_sys::krun_set_display_backend(self.id, backend, backend_size)
        })
    }

    /// Add an input device with separate config and events objects.
    ///
    /// # Safety
    /// Both pointers must be valid for reads of their respective sizes
    /// and must point to correctly initialized structs.
    pub unsafe fn add_input_device(
        &mut self,
        config_backend: *const c_void,
        config_backend_size: usize,
        events_backend: *const c_void,
        events_backend_size: usize,
    ) -> Result<()> {
        let ret = unsafe {
            krun_sys::krun_add_input_device(
                self.id,
                config_backend,
                config_backend_size,
                events_backend,
                events_backend_size,
            )
        };
        check_ret("krun_add_input_device", ret)
    }

    /// Add a passthrough input device from a host /dev/input/* fd.
    pub fn add_input_device_fd(&mut self, input_fd: i32) -> Result<()> {
        let ret = unsafe { krun_sys::krun_add_input_device_fd(self.id, input_fd) };
        check_ret("krun_add_input_device_fd", ret)
    }

    /// Fork and start the VM. Returns the child PID to the parent.
    ///
    /// The child calls `krun_start_enter()` (never returns) after setting
    /// `PR_SET_PDEATHSIG(SIGKILL)` (Linux only) to prevent orphan VMs.
    /// The parent receives the child PID for waitpid/lifecycle management.
    ///
    /// Consumes `self` — after fork, the context belongs to the child process.
    /// In the parent, Drop runs and calls `krun_free_ctx` to clean up the
    /// parent's copy (safe — parent and child have independent address spaces).
    ///
    /// # Safety considerations
    ///
    /// This method calls `fork()`. In a multi-threaded process, only
    /// async-signal-safe operations are permitted in the child between
    /// `fork()` and `exec()`. The child calls `krun_start_enter()` which
    /// takes over the process. Callers should ensure this is called from
    /// a single-threaded context or accept the standard fork-in-multithreaded
    /// risks.
    pub fn start(self) -> Result<i32> {
        let id = self.id;
        let parent_pid = unsafe { libc::getpid() };

        let pid = unsafe { libc::fork() };
        match pid {
            -1 => Err(KrunError::Fork(std::io::Error::last_os_error())),
            0 => {
                std::mem::forget(self);

                if !crate::lease::close_in_forked_child() {
                    unsafe { libc::_exit(1) };
                }

                #[cfg(target_os = "linux")]
                {
                    if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) } != 0 {
                        unsafe { libc::_exit(1) };
                    }
                    if unsafe { libc::getppid() } != parent_pid {
                        unsafe { libc::_exit(1) };
                    }
                }

                let _ = parent_pid;

                let ret = unsafe { krun_sys::krun_start_enter(id) };
                unsafe { libc::_exit(if ret < 0 { 1 } else { 0 }) };
            }
            child_pid => Ok(child_pid),
        }
    }

    /// Call `krun_start_enter()` directly. Takes over the calling process
    /// and never returns. For internal use by code that manages its own fork.
    #[allow(dead_code)]
    pub(crate) fn start_enter(self) -> ! {
        let id = self.id;
        std::mem::forget(self);
        let ret = unsafe { krun_sys::krun_start_enter(id) };
        unsafe { libc::_exit(if ret < 0 { 1 } else { 0 }) }
    }
}

impl Drop for KrunCtx {
    fn drop(&mut self) {
        unsafe {
            krun_sys::krun_free_ctx(self.id);
        }
    }
}
