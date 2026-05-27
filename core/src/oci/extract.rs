use std::fs;
use std::io::{BufReader, Read};
use std::path::{Component, Path, PathBuf};

use super::OciError;

const OPAQUE_WHITEOUT: &str = ".wh..wh..opq";
const WHITEOUT_PREFIX: &str = ".wh.";
const MAX_SYMLINK_DEPTH: usize = 40;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LayerCompression {
    Gzip,
    Zstd,
    None,
}

/// Open a tar archive with the appropriate decompression.
fn open_tar(
    layer_path: &Path,
    compression: LayerCompression,
) -> Result<tar::Archive<Box<dyn Read>>, OciError> {
    let file = fs::File::open(layer_path)?;
    let reader: Box<dyn Read> = match compression {
        LayerCompression::Gzip => Box::new(flate2::read::GzDecoder::new(BufReader::new(file))),
        LayerCompression::Zstd => Box::new(
            zstd::stream::read::Decoder::new(BufReader::new(file))
                .map_err(|e| OciError::Extraction(format!("zstd decoder init: {e}")))?,
        ),
        LayerCompression::None => Box::new(BufReader::new(file)),
    };
    Ok(tar::Archive::new(reader))
}

/// Extract a tar layer into `dest`, handling OCI whiteout files.
///
/// Pre-scans the tar to collect whiteout entries, applies deletions to `dest`,
/// then extracts non-whiteout entries. All path operations resolve symlinks
/// within `dest` to prevent escape attacks.
pub fn extract_layer(
    layer_path: &Path,
    dest: &Path,
    compression: LayerCompression,
) -> Result<(), OciError> {
    // Pre-scan: collect whiteout markers from the tar without extracting
    let (opaque_dirs, whiteout_targets) = prescan_whiteouts(layer_path, dest, compression)?;

    // Apply whiteouts: delete targets in dest before extraction.
    // Whiteouts delete directory entries by name without following symlinks.
    for dir in &opaque_dirs {
        let parent = dir.parent().unwrap_or(Path::new(""));
        let dir_name = match dir.file_name() {
            Some(n) => n,
            None => continue,
        };
        let resolved_parent = safe_resolve(dest, parent)?;
        let dir_path = resolved_parent.join(dir_name);
        match fs::symlink_metadata(&dir_path) {
            Ok(m) if m.is_dir() && !m.is_symlink() => {
                let children: Vec<_> = fs::read_dir(&dir_path)?.filter_map(|e| e.ok()).collect();
                for child in children {
                    remove_entry_no_follow(&child.path())?;
                }
            }
            _ => continue,
        }
    }

    for target in &whiteout_targets {
        // Resolve only the parent (to handle symlinks in parent path), then
        // delete the final component without following it.
        let parent = target.parent().unwrap_or(Path::new(""));
        let file_name = match target.file_name() {
            Some(n) => n,
            None => continue,
        };
        let resolved_parent = safe_resolve(dest, parent)?;
        let entry_path = resolved_parent.join(file_name);
        remove_entry_no_follow(&entry_path)?;
    }

    // Extract: unpack all non-whiteout entries
    let mut archive = open_tar(layer_path, compression)?;

    for entry_result in archive.entries()? {
        let mut entry = entry_result?;
        let raw_path = entry
            .path()
            .map_err(|e| OciError::Extraction(format!("invalid entry path: {e}")))?
            .into_owned();

        let clean = sanitize_path(&raw_path, dest)?;
        let file_name = match clean.file_name() {
            Some(n) => n.to_string_lossy().to_string(),
            None => continue,
        };

        // Skip whiteout entries (already applied)
        if file_name == OPAQUE_WHITEOUT || file_name.starts_with(WHITEOUT_PREFIX) {
            continue;
        }

        // Skip device nodes, FIFOs, and other special entries
        let entry_type = entry.header().entry_type();
        if matches!(
            entry_type,
            tar::EntryType::Block | tar::EntryType::Char | tar::EntryType::Fifo
        ) {
            continue;
        }

        // Hardlinks: create manually relative to dest
        if entry_type == tar::EntryType::Link {
            if let Some(link) = entry.link_name()? {
                if link.is_absolute() {
                    return Err(OciError::UnsafeTarEntry(format!(
                        "hardlink has absolute target: {}",
                        link.display()
                    )));
                }
                let normalized_target =
                    normalize_path(&link).map_err(|e| OciError::UnsafeTarEntry(e.to_string()))?;

                // Resolve both paths safely through symlinks
                let resolved_target = safe_resolve(dest, &normalized_target)?;
                if !resolved_target.exists() {
                    return Err(OciError::Extraction(format!(
                        "hardlink target does not exist: {}",
                        normalized_target.display()
                    )));
                }

                let resolved_path = safe_resolve_parent(dest, &clean)?;
                fs::hard_link(&resolved_target, &resolved_path)?;
            }
            continue;
        }

        // Symlinks: creating the symlink itself is safe (doesn't follow anything).
        // Resolve only the parent to ensure the symlink is placed correctly.
        if entry_type == tar::EntryType::Symlink {
            if let Some(link) = entry.link_name()? {
                validate_symlink_target(&clean, &link)?;
            }
            let resolved_parent = safe_resolve(dest, clean.parent().unwrap_or(Path::new("")))?;
            fs::create_dir_all(&resolved_parent)?;
            let resolved_path = resolved_parent.join(clean.file_name().unwrap());
            entry.set_preserve_permissions(true);
            entry.unpack(&resolved_path)?;
            continue;
        }

        // Regular files and directories: resolve the full path safely
        let resolved_path = safe_resolve_parent(dest, &clean)?;
        entry.set_preserve_permissions(true);
        entry.unpack(&resolved_path)?;
    }

    Ok(())
}

/// Resolve an entry path within dest, following any intermediate symlinks
/// and verifying the result stays within dest. Returns the resolved absolute
/// path under dest. Does NOT require the final component to exist.
fn safe_resolve(dest: &Path, entry_path: &Path) -> Result<PathBuf, OciError> {
    let mut resolved = dest.to_path_buf();

    for component in entry_path.components() {
        let Component::Normal(c) = component else {
            continue;
        };
        resolved.push(c);
        resolved = resolve_symlinks_at(&resolved, dest, 0)?;
    }

    if !resolved.starts_with(dest) {
        return Err(OciError::UnsafeTarEntry(format!(
            "resolved path escapes destination: {}",
            entry_path.display()
        )));
    }

    Ok(resolved)
}

/// Resolve the parent directory of an entry path safely, then append the
/// final component. Creates parent directories as needed.
fn safe_resolve_parent(dest: &Path, entry_path: &Path) -> Result<PathBuf, OciError> {
    let parent = entry_path.parent().unwrap_or(Path::new(""));
    let resolved_parent = safe_resolve(dest, parent)?;
    fs::create_dir_all(&resolved_parent)?;
    let file_name = entry_path
        .file_name()
        .ok_or_else(|| OciError::Extraction("entry has no file name".into()))?;
    Ok(resolved_parent.join(file_name))
}

/// If the path at `current` is a symlink, resolve it (recursively, with
/// depth limit). Absolute symlink targets are re-rooted to dest.
fn resolve_symlinks_at(current: &Path, dest: &Path, depth: usize) -> Result<PathBuf, OciError> {
    if depth > MAX_SYMLINK_DEPTH {
        return Err(OciError::UnsafeTarEntry(format!(
            "symlink resolution depth exceeded at: {}",
            current.display()
        )));
    }

    match fs::symlink_metadata(current) {
        Ok(meta) if meta.is_symlink() => {
            let link_target = fs::read_link(current)
                .map_err(|e| OciError::Extraction(format!("readlink: {e}")))?;

            let resolved = if link_target.is_absolute() {
                // Re-root absolute symlinks to dest
                let stripped = link_target.strip_prefix("/").unwrap_or(&link_target);
                dest.join(stripped)
            } else {
                let parent = current.parent().unwrap_or(dest);
                normalize_relative(parent, &link_target)?
            };

            if !resolved.starts_with(dest) {
                return Err(OciError::UnsafeTarEntry(format!(
                    "symlink escapes destination: {} -> {}",
                    current.display(),
                    link_target.display()
                )));
            }

            // Recursively resolve in case the target is also a symlink
            resolve_symlinks_at(&resolved, dest, depth + 1)
        }
        _ => Ok(current.to_path_buf()),
    }
}

/// Resolve a relative path from a base directory, handling `..` components.
fn normalize_relative(base: &Path, rel: &Path) -> Result<PathBuf, OciError> {
    let mut result = base.to_path_buf();
    for component in rel.components() {
        match component {
            Component::Normal(c) => result.push(c),
            Component::CurDir => {}
            Component::ParentDir => {
                result.pop();
            }
            _ => {}
        }
    }
    Ok(result)
}

/// Remove a directory entry without following symlinks. Uses symlink_metadata
/// to determine entry type. Symlinks and files are removed with remove_file;
/// directories with remove_dir_all. Ignores NotFound.
fn remove_entry_no_follow(path: &Path) -> Result<(), OciError> {
    let meta = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.into()),
    };
    let result = if meta.is_dir() && !meta.is_symlink() {
        fs::remove_dir_all(path)
    } else {
        fs::remove_file(path)
    };
    match result {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

/// Pre-scan a tar layer to collect whiteout markers without extracting.
fn prescan_whiteouts(
    layer_path: &Path,
    dest: &Path,
    compression: LayerCompression,
) -> Result<(Vec<PathBuf>, Vec<PathBuf>), OciError> {
    let mut archive = open_tar(layer_path, compression)?;

    let mut opaque_dirs: Vec<PathBuf> = Vec::new();
    let mut whiteout_targets: Vec<PathBuf> = Vec::new();

    for entry_result in archive.entries()? {
        let entry = entry_result?;
        let raw_path = entry
            .path()
            .map_err(|e| OciError::Extraction(format!("invalid entry path: {e}")))?
            .into_owned();

        let clean = sanitize_path(&raw_path, dest)?;
        let file_name = match clean.file_name() {
            Some(n) => n.to_string_lossy().to_string(),
            None => continue,
        };

        if file_name == OPAQUE_WHITEOUT {
            if let Some(parent) = clean.parent() {
                opaque_dirs.push(parent.to_path_buf());
            }
        } else if let Some(target_name) = file_name.strip_prefix(WHITEOUT_PREFIX) {
            if target_name.is_empty() {
                return Err(OciError::UnsafeTarEntry(format!(
                    "whiteout with empty target: {}",
                    clean.display()
                )));
            }
            if let Some(parent) = clean.parent() {
                whiteout_targets.push(parent.join(target_name));
            }
        }
    }

    Ok((opaque_dirs, whiteout_targets))
}

/// Normalize a tar entry path: strip leading `/` and `./`, reject `..` traversal.
fn normalize_path(path: &Path) -> Result<PathBuf, OciError> {
    let mut result = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(c) => result.push(c),
            Component::CurDir => {}
            Component::RootDir | Component::Prefix(_) => {}
            Component::ParentDir => {
                return Err(OciError::UnsafeTarEntry(format!(
                    "path traversal via ..: {}",
                    path.display()
                )));
            }
        }
    }
    Ok(result)
}

/// Sanitize a tar entry path: normalize and verify it stays within dest.
fn sanitize_path(path: &Path, dest: &Path) -> Result<PathBuf, OciError> {
    let normalized = normalize_path(path)?;
    let full = dest.join(&normalized);
    if !full.starts_with(dest) {
        return Err(OciError::UnsafeTarEntry(format!(
            "path escapes destination: {}",
            path.display()
        )));
    }
    Ok(normalized)
}

/// Validate that a relative symlink target, when resolved from the link
/// location, stays within the destination directory. Absolute symlink targets
/// are allowed (they resolve within the rootfs at VM boot time, and
/// safe_resolve re-roots them during extraction).
fn validate_symlink_target(link_path: &Path, target: &Path) -> Result<(), OciError> {
    if target.is_absolute() {
        return Ok(());
    }

    let link_dir = link_path.parent().unwrap_or(Path::new(""));
    let resolved = link_dir.join(target);

    let mut clean = PathBuf::new();
    for component in resolved.components() {
        match component {
            Component::Normal(c) => clean.push(c),
            Component::CurDir => {}
            Component::ParentDir => {
                if !clean.pop() {
                    return Err(OciError::UnsafeTarEntry(format!(
                        "symlink escapes destination: {} -> {}",
                        link_path.display(),
                        target.display()
                    )));
                }
            }
            _ => {}
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn create_tar_gz(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut tar_data = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_data);
            for (path, content) in entries {
                let mut header = tar::Header::new_gnu();
                header.set_path(path).unwrap();
                header.set_size(content.len() as u64);
                header.set_mode(0o644);
                header.set_cksum();
                builder.append(&header, *content).unwrap();
            }
            builder.finish().unwrap();
        }

        let mut gz_data = Vec::new();
        let mut encoder = flate2::write::GzEncoder::new(&mut gz_data, flate2::Compression::fast());
        encoder.write_all(&tar_data).unwrap();
        encoder.finish().unwrap();
        gz_data
    }

    fn create_tar_gz_with_link(
        file_path: &str,
        file_content: &[u8],
        link_path: &str,
        link_target: &str,
    ) -> Vec<u8> {
        let mut tar_data = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_data);

            let mut header = tar::Header::new_gnu();
            header.set_path(file_path).unwrap();
            header.set_size(file_content.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append(&header, file_content).unwrap();

            let mut link_header = tar::Header::new_gnu();
            link_header.set_path(link_path).unwrap();
            link_header.set_size(0);
            link_header.set_mode(0o644);
            link_header.set_entry_type(tar::EntryType::Link);
            link_header.set_link_name(link_target).unwrap();
            link_header.set_cksum();
            builder.append(&link_header, &[][..]).unwrap();

            builder.finish().unwrap();
        }

        let mut gz_data = Vec::new();
        let mut encoder = flate2::write::GzEncoder::new(&mut gz_data, flate2::Compression::fast());
        encoder.write_all(&tar_data).unwrap();
        encoder.finish().unwrap();
        gz_data
    }

    #[test]
    fn extract_basic_files() {
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("rootfs");
        fs::create_dir_all(&dest).unwrap();

        let layer = create_tar_gz(&[
            ("hello.txt", b"hello world"),
            ("subdir/file.txt", b"nested"),
        ]);
        let layer_path = tmp.path().join("layer.tar.gz");
        fs::write(&layer_path, &layer).unwrap();

        extract_layer(&layer_path, &dest, LayerCompression::Gzip).unwrap();

        assert_eq!(
            fs::read_to_string(dest.join("hello.txt")).unwrap(),
            "hello world"
        );
        assert_eq!(
            fs::read_to_string(dest.join("subdir/file.txt")).unwrap(),
            "nested"
        );
    }

    #[test]
    fn extract_hardlink_within_dest() {
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("rootfs");
        fs::create_dir_all(&dest).unwrap();

        let layer = create_tar_gz_with_link("orig.txt", b"data", "link.txt", "orig.txt");
        let layer_path = tmp.path().join("layer.tar.gz");
        fs::write(&layer_path, &layer).unwrap();

        extract_layer(&layer_path, &dest, LayerCompression::Gzip).unwrap();

        assert_eq!(fs::read_to_string(dest.join("orig.txt")).unwrap(), "data");
        assert_eq!(fs::read_to_string(dest.join("link.txt")).unwrap(), "data");
    }

    #[test]
    fn whiteout_deletes_file() {
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("rootfs");
        fs::create_dir_all(&dest).unwrap();

        let layer1 = create_tar_gz(&[("etc/config.txt", b"original")]);
        let l1_path = tmp.path().join("layer1.tar.gz");
        fs::write(&l1_path, &layer1).unwrap();
        extract_layer(&l1_path, &dest, LayerCompression::Gzip).unwrap();
        assert!(dest.join("etc/config.txt").exists());

        let layer2 = create_tar_gz(&[("etc/.wh.config.txt", b"")]);
        let l2_path = tmp.path().join("layer2.tar.gz");
        fs::write(&l2_path, &layer2).unwrap();
        extract_layer(&l2_path, &dest, LayerCompression::Gzip).unwrap();

        assert!(!dest.join("etc/config.txt").exists());
    }

    #[test]
    fn opaque_whiteout_preserves_same_layer_entries() {
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("rootfs");
        fs::create_dir_all(&dest).unwrap();

        let layer1 = create_tar_gz(&[("etc/old1.txt", b"old1"), ("etc/old2.txt", b"old2")]);
        let l1_path = tmp.path().join("layer1.tar.gz");
        fs::write(&l1_path, &layer1).unwrap();
        extract_layer(&l1_path, &dest, LayerCompression::Gzip).unwrap();

        let layer2 = create_tar_gz(&[("etc/new.txt", b"new"), ("etc/.wh..wh..opq", b"")]);
        let l2_path = tmp.path().join("layer2.tar.gz");
        fs::write(&l2_path, &layer2).unwrap();
        extract_layer(&l2_path, &dest, LayerCompression::Gzip).unwrap();

        assert!(!dest.join("etc/old1.txt").exists());
        assert!(!dest.join("etc/old2.txt").exists());
        assert!(dest.join("etc/new.txt").exists());
        assert_eq!(fs::read_to_string(dest.join("etc/new.txt")).unwrap(), "new");
    }

    #[test]
    fn rejects_path_traversal() {
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("rootfs");
        fs::create_dir_all(&dest).unwrap();

        let path_bytes = b"../escape.txt";
        let content = b"bad";
        let mut tar_data = Vec::new();
        {
            let mut header = tar::Header::new_gnu();
            {
                let raw = header.as_mut_bytes();
                raw[..path_bytes.len()].copy_from_slice(path_bytes);
            }
            header.set_size(content.len() as u64);
            header.set_mode(0o644);
            header.set_entry_type(tar::EntryType::Regular);
            header.set_cksum();
            let mut builder = tar::Builder::new(&mut tar_data);
            builder.append(&header, &content[..]).unwrap();
            builder.finish().unwrap();
        }

        let mut gz_data = Vec::new();
        let mut encoder = flate2::write::GzEncoder::new(&mut gz_data, flate2::Compression::fast());
        encoder.write_all(&tar_data).unwrap();
        encoder.finish().unwrap();

        let layer_path = tmp.path().join("layer.tar.gz");
        fs::write(&layer_path, &gz_data).unwrap();

        let err = extract_layer(&layer_path, &dest, LayerCompression::Gzip).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("path traversal") || msg.contains("unsafe"),
            "got: {msg}"
        );
    }

    #[test]
    fn strips_leading_slash() {
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("rootfs");
        fs::create_dir_all(&dest).unwrap();

        let layer = create_tar_gz(&[("./etc/file.txt", b"content")]);
        let layer_path = tmp.path().join("layer.tar.gz");
        fs::write(&layer_path, &layer).unwrap();

        extract_layer(&layer_path, &dest, LayerCompression::Gzip).unwrap();
        assert_eq!(
            fs::read_to_string(dest.join("etc/file.txt")).unwrap(),
            "content"
        );
    }

    #[test]
    fn extract_preserves_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("rootfs");
        fs::create_dir_all(&dest).unwrap();

        let mut tar_data = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_data);
            let mut header = tar::Header::new_gnu();
            header.set_path("script.sh").unwrap();
            header.set_size(11);
            header.set_mode(0o755);
            header.set_cksum();
            builder.append(&header, b"#!/bin/bash" as &[u8]).unwrap();
            builder.finish().unwrap();
        }

        let mut gz_data = Vec::new();
        let mut encoder = flate2::write::GzEncoder::new(&mut gz_data, flate2::Compression::fast());
        encoder.write_all(&tar_data).unwrap();
        encoder.finish().unwrap();

        let layer_path = tmp.path().join("layer.tar.gz");
        fs::write(&layer_path, &gz_data).unwrap();
        extract_layer(&layer_path, &dest, LayerCompression::Gzip).unwrap();

        let meta = fs::metadata(dest.join("script.sh")).unwrap();
        assert!(meta.permissions().mode() & 0o111 != 0);
    }

    #[test]
    fn whiteout_with_same_layer_replacement() {
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("rootfs");
        fs::create_dir_all(&dest).unwrap();

        let layer1 = create_tar_gz(&[("etc/config.txt", b"old")]);
        let l1_path = tmp.path().join("layer1.tar.gz");
        fs::write(&l1_path, &layer1).unwrap();
        extract_layer(&l1_path, &dest, LayerCompression::Gzip).unwrap();

        let layer2 = create_tar_gz(&[("etc/.wh.config.txt", b""), ("etc/config.txt", b"new")]);
        let l2_path = tmp.path().join("layer2.tar.gz");
        fs::write(&l2_path, &layer2).unwrap();
        extract_layer(&l2_path, &dest, LayerCompression::Gzip).unwrap();

        assert!(dest.join("etc/config.txt").exists());
        assert_eq!(
            fs::read_to_string(dest.join("etc/config.txt")).unwrap(),
            "new"
        );
    }

    #[test]
    fn opaque_whiteout_preserves_implicit_subdirs() {
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("rootfs");
        fs::create_dir_all(&dest).unwrap();

        let layer1 = create_tar_gz(&[("etc/old.txt", b"old")]);
        let l1_path = tmp.path().join("layer1.tar.gz");
        fs::write(&l1_path, &layer1).unwrap();
        extract_layer(&l1_path, &dest, LayerCompression::Gzip).unwrap();

        let layer2 = create_tar_gz(&[("etc/subdir/new.txt", b"new"), ("etc/.wh..wh..opq", b"")]);
        let l2_path = tmp.path().join("layer2.tar.gz");
        fs::write(&l2_path, &layer2).unwrap();
        extract_layer(&l2_path, &dest, LayerCompression::Gzip).unwrap();

        assert!(!dest.join("etc/old.txt").exists());
        assert!(dest.join("etc/subdir/new.txt").exists());
        assert_eq!(
            fs::read_to_string(dest.join("etc/subdir/new.txt")).unwrap(),
            "new"
        );
    }

    #[test]
    fn absolute_symlink_stored_correctly() {
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("rootfs");
        fs::create_dir_all(&dest).unwrap();

        let mut tar_data = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_data);

            let mut dir_header = tar::Header::new_gnu();
            dir_header.set_path("usr/lib/").unwrap();
            dir_header.set_size(0);
            dir_header.set_mode(0o755);
            dir_header.set_entry_type(tar::EntryType::Directory);
            dir_header.set_cksum();
            builder.append(&dir_header, &[][..]).unwrap();

            let mut sym_header = tar::Header::new_gnu();
            sym_header.set_path("lib").unwrap();
            sym_header.set_size(0);
            sym_header.set_mode(0o777);
            sym_header.set_entry_type(tar::EntryType::Symlink);
            sym_header.set_link_name("/usr/lib").unwrap();
            sym_header.set_cksum();
            builder.append(&sym_header, &[][..]).unwrap();

            builder.finish().unwrap();
        }

        let mut gz_data = Vec::new();
        let mut encoder = flate2::write::GzEncoder::new(&mut gz_data, flate2::Compression::fast());
        encoder.write_all(&tar_data).unwrap();
        encoder.finish().unwrap();

        let layer_path = tmp.path().join("layer.tar.gz");
        fs::write(&layer_path, &gz_data).unwrap();

        extract_layer(&layer_path, &dest, LayerCompression::Gzip).unwrap();

        let meta = fs::symlink_metadata(dest.join("lib")).unwrap();
        assert!(meta.is_symlink());
        assert_eq!(
            fs::read_link(dest.join("lib")).unwrap().to_str().unwrap(),
            "/usr/lib"
        );
    }

    #[test]
    fn absolute_symlink_traversal_stays_in_dest() {
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("rootfs");
        fs::create_dir_all(&dest).unwrap();

        // Create: lib -> /usr/lib (absolute symlink), then usr/lib/foo.so and lib/foo.so
        let mut tar_data = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_data);

            // usr/lib/ directory
            let mut dir_header = tar::Header::new_gnu();
            dir_header.set_path("usr/lib/").unwrap();
            dir_header.set_size(0);
            dir_header.set_mode(0o755);
            dir_header.set_entry_type(tar::EntryType::Directory);
            dir_header.set_cksum();
            builder.append(&dir_header, &[][..]).unwrap();

            // lib -> /usr/lib
            let mut sym_header = tar::Header::new_gnu();
            sym_header.set_path("lib").unwrap();
            sym_header.set_size(0);
            sym_header.set_mode(0o777);
            sym_header.set_entry_type(tar::EntryType::Symlink);
            sym_header.set_link_name("/usr/lib").unwrap();
            sym_header.set_cksum();
            builder.append(&sym_header, &[][..]).unwrap();

            // File through the symlink: lib/foo.so
            let mut file_header = tar::Header::new_gnu();
            file_header.set_path("lib/foo.so").unwrap();
            file_header.set_size(6);
            file_header.set_mode(0o644);
            file_header.set_cksum();
            builder.append(&file_header, b"ELF..." as &[u8]).unwrap();

            builder.finish().unwrap();
        }

        let mut gz_data = Vec::new();
        let mut encoder = flate2::write::GzEncoder::new(&mut gz_data, flate2::Compression::fast());
        encoder.write_all(&tar_data).unwrap();
        encoder.finish().unwrap();

        let layer_path = tmp.path().join("layer.tar.gz");
        fs::write(&layer_path, &gz_data).unwrap();

        extract_layer(&layer_path, &dest, LayerCompression::Gzip).unwrap();

        // lib/foo.so should resolve to dest/usr/lib/foo.so (not /usr/lib/foo.so on host)
        assert!(dest.join("usr/lib/foo.so").exists());
        assert_eq!(
            fs::read_to_string(dest.join("usr/lib/foo.so")).unwrap(),
            "ELF..."
        );
    }

    #[test]
    fn absolute_symlink_escape_blocked() {
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("rootfs");
        fs::create_dir_all(&dest).unwrap();

        // Create escape -> /tmp on host, then try to write escape/file
        // First, pre-create a symlink pointing to a real absolute path outside dest
        fs::create_dir_all(dest.join("")).unwrap();
        std::os::unix::fs::symlink("/tmp", dest.join("escape")).unwrap();

        // Now try to extract a file through it
        let layer = create_tar_gz(&[("escape/evil.txt", b"pwned")]);
        let layer_path = tmp.path().join("layer.tar.gz");
        fs::write(&layer_path, &layer).unwrap();

        // safe_resolve should re-root /tmp to dest/tmp, not follow to host /tmp
        extract_layer(&layer_path, &dest, LayerCompression::Gzip).unwrap();

        // The file should NOT be at /tmp/evil.txt
        assert!(!Path::new("/tmp/evil.txt").exists());
        // It should be at dest/tmp/evil.txt (re-rooted)
        assert!(dest.join("tmp/evil.txt").exists());
    }

    #[test]
    fn relative_symlink_escape_blocked() {
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("rootfs");
        fs::create_dir_all(&dest).unwrap();

        // Pre-create a relative symlink that escapes: link -> ../../etc
        fs::create_dir_all(dest.join("subdir")).unwrap();
        std::os::unix::fs::symlink("../../etc", dest.join("subdir/link")).unwrap();

        // Try to write through it
        let layer = create_tar_gz(&[("subdir/link/passwd", b"pwned")]);
        let layer_path = tmp.path().join("layer.tar.gz");
        fs::write(&layer_path, &layer).unwrap();

        let result = extract_layer(&layer_path, &dest, LayerCompression::Gzip);
        assert!(result.is_err(), "should have blocked symlink escape");
    }

    #[test]
    fn rejects_empty_whiteout_target() {
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("rootfs");
        fs::create_dir_all(&dest).unwrap();

        let layer = create_tar_gz(&[("etc/.wh.", b"")]);
        let layer_path = tmp.path().join("layer.tar.gz");
        fs::write(&layer_path, &layer).unwrap();

        let err = extract_layer(&layer_path, &dest, LayerCompression::Gzip).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("empty target"), "got: {msg}");
    }

    fn create_plain_tar(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut tar_data = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_data);
            for (path, content) in entries {
                let mut header = tar::Header::new_gnu();
                header.set_path(path).unwrap();
                header.set_size(content.len() as u64);
                header.set_mode(0o644);
                header.set_cksum();
                builder.append(&header, *content).unwrap();
            }
            builder.finish().unwrap();
        }
        tar_data
    }

    #[test]
    fn extract_uncompressed_tar() {
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("rootfs");
        fs::create_dir_all(&dest).unwrap();

        let layer = create_plain_tar(&[("hello.txt", b"uncompressed")]);
        let layer_path = tmp.path().join("layer.tar");
        fs::write(&layer_path, &layer).unwrap();

        extract_layer(&layer_path, &dest, LayerCompression::None).unwrap();
        assert_eq!(
            fs::read_to_string(dest.join("hello.txt")).unwrap(),
            "uncompressed"
        );
    }

    #[test]
    fn extract_zstd_tar() {
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("rootfs");
        fs::create_dir_all(&dest).unwrap();

        let tar_data = create_plain_tar(&[("hello.txt", b"zstd-compressed")]);
        let zstd_data = zstd::encode_all(tar_data.as_slice(), 3).unwrap();
        let layer_path = tmp.path().join("layer.tar.zst");
        fs::write(&layer_path, &zstd_data).unwrap();

        extract_layer(&layer_path, &dest, LayerCompression::Zstd).unwrap();
        assert_eq!(
            fs::read_to_string(dest.join("hello.txt")).unwrap(),
            "zstd-compressed"
        );
    }

    #[test]
    fn whiteout_deletes_symlink_not_target() {
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("rootfs");
        fs::create_dir_all(&dest).unwrap();

        // Layer 1: create usr/lib/real.txt and a symlink link -> /usr/lib
        let mut tar_data = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_data);

            let mut dir_header = tar::Header::new_gnu();
            dir_header.set_path("usr/lib/").unwrap();
            dir_header.set_size(0);
            dir_header.set_mode(0o755);
            dir_header.set_entry_type(tar::EntryType::Directory);
            dir_header.set_cksum();
            builder.append(&dir_header, &[][..]).unwrap();

            let mut file_header = tar::Header::new_gnu();
            file_header.set_path("usr/lib/real.txt").unwrap();
            file_header.set_size(4);
            file_header.set_mode(0o644);
            file_header.set_cksum();
            builder.append(&file_header, b"data" as &[u8]).unwrap();

            let mut sym_header = tar::Header::new_gnu();
            sym_header.set_path("link").unwrap();
            sym_header.set_size(0);
            sym_header.set_mode(0o777);
            sym_header.set_entry_type(tar::EntryType::Symlink);
            sym_header.set_link_name("/usr/lib").unwrap();
            sym_header.set_cksum();
            builder.append(&sym_header, &[][..]).unwrap();

            builder.finish().unwrap();
        }
        let mut gz_data = Vec::new();
        let mut encoder = flate2::write::GzEncoder::new(&mut gz_data, flate2::Compression::fast());
        std::io::Write::write_all(&mut encoder, &tar_data).unwrap();
        encoder.finish().unwrap();

        let l1_path = tmp.path().join("layer1.tar.gz");
        fs::write(&l1_path, &gz_data).unwrap();
        extract_layer(&l1_path, &dest, LayerCompression::Gzip).unwrap();

        // Verify setup
        assert!(dest.join("usr/lib/real.txt").exists());
        assert!(
            fs::symlink_metadata(dest.join("link"))
                .unwrap()
                .is_symlink()
        );

        // Layer 2: whiteout the symlink
        let layer2 = create_tar_gz(&[(".wh.link", b"")]);
        let l2_path = tmp.path().join("layer2.tar.gz");
        fs::write(&l2_path, &layer2).unwrap();
        extract_layer(&l2_path, &dest, LayerCompression::Gzip).unwrap();

        // The symlink should be gone
        assert!(!dest.join("link").exists());
        // But the target directory and its contents should still exist
        assert!(dest.join("usr/lib/real.txt").exists());
        assert_eq!(
            fs::read_to_string(dest.join("usr/lib/real.txt")).unwrap(),
            "data"
        );
    }

    #[test]
    fn opaque_whiteout_on_symlink_dir_is_noop() {
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("rootfs");
        fs::create_dir_all(&dest).unwrap();

        // Layer 1: create usr/lib/real.txt and symlink a -> /usr/lib
        let mut tar_data = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_data);

            let mut dir_header = tar::Header::new_gnu();
            dir_header.set_path("usr/lib/").unwrap();
            dir_header.set_size(0);
            dir_header.set_mode(0o755);
            dir_header.set_entry_type(tar::EntryType::Directory);
            dir_header.set_cksum();
            builder.append(&dir_header, &[][..]).unwrap();

            let mut file_header = tar::Header::new_gnu();
            file_header.set_path("usr/lib/real.txt").unwrap();
            file_header.set_size(4);
            file_header.set_mode(0o644);
            file_header.set_cksum();
            builder.append(&file_header, b"keep" as &[u8]).unwrap();

            let mut sym_header = tar::Header::new_gnu();
            sym_header.set_path("a").unwrap();
            sym_header.set_size(0);
            sym_header.set_mode(0o777);
            sym_header.set_entry_type(tar::EntryType::Symlink);
            sym_header.set_link_name("/usr/lib").unwrap();
            sym_header.set_cksum();
            builder.append(&sym_header, &[][..]).unwrap();

            builder.finish().unwrap();
        }
        let mut gz_data = Vec::new();
        let mut encoder = flate2::write::GzEncoder::new(&mut gz_data, flate2::Compression::fast());
        std::io::Write::write_all(&mut encoder, &tar_data).unwrap();
        encoder.finish().unwrap();

        let l1_path = tmp.path().join("layer1.tar.gz");
        fs::write(&l1_path, &gz_data).unwrap();
        extract_layer(&l1_path, &dest, LayerCompression::Gzip).unwrap();

        assert!(fs::symlink_metadata(dest.join("a")).unwrap().is_symlink());
        assert!(dest.join("usr/lib/real.txt").exists());

        // Layer 2: opaque whiteout on a/ (which is a symlink)
        let layer2 = create_tar_gz(&[("a/.wh..wh..opq", b"")]);
        let l2_path = tmp.path().join("layer2.tar.gz");
        fs::write(&l2_path, &layer2).unwrap();
        extract_layer(&l2_path, &dest, LayerCompression::Gzip).unwrap();

        // Symlink a should be unchanged
        assert!(fs::symlink_metadata(dest.join("a")).unwrap().is_symlink());
        // Target contents should survive
        assert!(dest.join("usr/lib/real.txt").exists());
        assert_eq!(
            fs::read_to_string(dest.join("usr/lib/real.txt")).unwrap(),
            "keep"
        );
    }
}
