//! Resolve the real executable behind a shim.
//!
//! When a shim decides to allow a command, it must run the *real* tool, not
//! itself. We search the original `PATH` (captured before shims were injected),
//! skipping the shim directory, and return the first executable match.

use std::path::{Path, PathBuf};

/// Find the real executable named `program` on `original_path`, skipping
/// `shim_dir`. `self_exe`, if given, is the path to the running
/// `agent-quarantine` binary; any candidate that resolves to it is skipped so a
/// shim from another (e.g. nested) session cannot cause the shim to re-invoke
/// itself. Returns `None` if nothing suitable is found.
pub fn resolve_real_executable(
    program: &str,
    original_path: &str,
    shim_dir: &Path,
    self_exe: Option<&Path>,
) -> Option<PathBuf> {
    let shim_canonical = shim_dir.canonicalize().ok();
    let self_canonical = self_exe.and_then(|p| p.canonicalize().ok());
    for dir in std::env::split_paths(original_path) {
        if same_dir(&dir, shim_dir, shim_canonical.as_deref()) {
            continue;
        }
        let candidate = dir.join(program);
        if !is_executable_file(&candidate) {
            continue;
        }
        // Never resolve back to our own binary — that would be a shim symlink
        // from another session and re-entering it risks an exec loop.
        if let Some(self_c) = &self_canonical {
            if candidate.canonicalize().ok().as_deref() == Some(self_c.as_path()) {
                continue;
            }
        }
        return Some(candidate);
    }
    None
}

fn same_dir(dir: &Path, shim_dir: &Path, shim_canonical: Option<&Path>) -> bool {
    if dir == shim_dir {
        return true;
    }
    match (dir.canonicalize().ok(), shim_canonical) {
        (Some(a), Some(b)) => a == b,
        _ => false,
    }
}

#[cfg(unix)]
fn is_executable_file(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    match std::fs::metadata(path) {
        Ok(meta) => meta.is_file() && (meta.permissions().mode() & 0o111 != 0),
        Err(_) => false,
    }
}

#[cfg(not(unix))]
fn is_executable_file(path: &Path) -> bool {
    path.is_file()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[cfg(unix)]
    #[test]
    fn resolves_real_binary_and_skips_shim_dir() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let shim_dir = tmp.path().join("shims");
        let real_dir = tmp.path().join("realbin");
        fs::create_dir_all(&shim_dir).unwrap();
        fs::create_dir_all(&real_dir).unwrap();

        // A fake shim named `curl` that should be skipped.
        let shim = shim_dir.join("curl");
        fs::write(&shim, "#!/bin/sh\n").unwrap();
        fs::set_permissions(&shim, fs::Permissions::from_mode(0o755)).unwrap();

        // The "real" curl.
        let real = real_dir.join("curl");
        fs::write(&real, "#!/bin/sh\n").unwrap();
        fs::set_permissions(&real, fs::Permissions::from_mode(0o755)).unwrap();

        let path = std::env::join_paths([&shim_dir, &real_dir])
            .unwrap()
            .into_string()
            .unwrap();

        let resolved = resolve_real_executable("curl", &path, &shim_dir, None).unwrap();
        assert_eq!(resolved, real);

        // With self_exe pointing at the "real" file, it is skipped (simulating a
        // stale shim from a nested session), so nothing else matches.
        assert!(resolve_real_executable("curl", &path, &shim_dir, Some(&real)).is_none());
    }

    #[test]
    fn returns_none_when_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let shim_dir = tmp.path().join("shims");
        fs::create_dir_all(&shim_dir).unwrap();
        let path = shim_dir.to_string_lossy().into_owned();
        assert!(resolve_real_executable("definitely-not-real", &path, &shim_dir, None).is_none());
    }
}
