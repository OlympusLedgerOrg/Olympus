// SPDX-License-Identifier: Apache-2.0

//! Bounded reads for operator-provisioned trust material.
//!
//! These files are configuration inputs, not ordinary application data. Read
//! them through one already-validated handle so a size check cannot be raced
//! against a second path-based read, and reject links/reparse points and
//! non-regular files before parsing.

use std::io::Read as _;
use std::path::Path;

#[derive(Debug, thiserror::Error)]
pub(crate) enum SafeOperatorFileError {
    #[error("operator file path is a link or reparse point")]
    LinkedPath,
    #[error("operator file path is not a regular file")]
    NotRegularFile,
    #[error("operator file exceeds the {max_bytes}-byte limit")]
    TooLarge { max_bytes: usize },
    #[error("read operator file: {0}")]
    Io(#[from] std::io::Error),
}

pub(crate) fn read_bounded_regular_file(
    path: &Path,
    max_bytes: usize,
) -> Result<Vec<u8>, SafeOperatorFileError> {
    let path_metadata = std::fs::symlink_metadata(path)?;
    if is_link_or_reparse_point(&path_metadata) {
        return Err(SafeOperatorFileError::LinkedPath);
    }
    if !path_metadata.is_file() {
        return Err(SafeOperatorFileError::NotRegularFile);
    }

    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    configure_no_follow(&mut options);
    let file = options.open(path).map_err(|error| {
        if is_link_open_error(&error) {
            SafeOperatorFileError::LinkedPath
        } else {
            SafeOperatorFileError::Io(error)
        }
    })?;

    // From here onward every property and byte comes from this exact handle.
    let metadata = file.metadata()?;
    if is_link_or_reparse_point(&metadata) {
        return Err(SafeOperatorFileError::LinkedPath);
    }
    if !metadata.is_file() {
        return Err(SafeOperatorFileError::NotRegularFile);
    }
    if metadata.len() > max_bytes as u64 {
        return Err(SafeOperatorFileError::TooLarge { max_bytes });
    }

    let mut bytes = Vec::with_capacity(
        usize::try_from(metadata.len())
            .unwrap_or(max_bytes)
            .min(max_bytes),
    );
    let mut bounded = file.take(max_bytes as u64 + 1);
    bounded.read_to_end(&mut bytes)?;
    if bytes.len() > max_bytes {
        return Err(SafeOperatorFileError::TooLarge { max_bytes });
    }
    Ok(bytes)
}

fn is_link_or_reparse_point(metadata: &std::fs::Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }

    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;

        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return true;
        }
    }

    false
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn configure_no_follow(options: &mut std::fs::OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt as _;

    // Linux UAPI O_NOFOLLOW. Avoiding a libc dependency keeps this helper out
    // of the runtime dependency graph.
    const O_NOFOLLOW: i32 = 0x0002_0000;
    options.custom_flags(O_NOFOLLOW);
}

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly"
))]
fn configure_no_follow(options: &mut std::fs::OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt as _;

    const O_NOFOLLOW: i32 = 0x0000_0100;
    options.custom_flags(O_NOFOLLOW);
}

#[cfg(windows)]
fn configure_no_follow(options: &mut std::fs::OpenOptions) {
    use std::os::windows::fs::OpenOptionsExt as _;

    // Open the reparse point itself, if one is raced into place, so the
    // handle-metadata check rejects it rather than reading its target.
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly",
    windows
)))]
fn configure_no_follow(_options: &mut std::fs::OpenOptions) {}

fn is_link_open_error(_error: &std::io::Error) -> bool {
    #[cfg(unix)]
    {
        // ELOOP is returned when O_NOFOLLOW encounters a symlink.
        if _error.raw_os_error() == Some(40) {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    #[test]
    fn reads_exactly_bounded_regular_file() {
        let mut file = tempfile::NamedTempFile::new().expect("temp file");
        file.write_all(b"trusted").expect("write");
        file.flush().expect("flush");
        assert_eq!(
            read_bounded_regular_file(file.path(), 7).expect("bounded read"),
            b"trusted"
        );
    }

    #[test]
    fn rejects_oversized_and_non_regular_inputs() {
        let mut file = tempfile::NamedTempFile::new().expect("temp file");
        file.write_all(b"12345678").expect("write");
        file.flush().expect("flush");
        assert!(matches!(
            read_bounded_regular_file(file.path(), 7),
            Err(SafeOperatorFileError::TooLarge { max_bytes: 7 })
        ));

        let directory = tempfile::tempdir().expect("temp dir");
        assert!(matches!(
            read_bounded_regular_file(directory.path(), 7),
            Err(SafeOperatorFileError::NotRegularFile)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlink_without_reading_target() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().expect("temp dir");
        let target = directory.path().join("target");
        let link = directory.path().join("link");
        std::fs::write(&target, b"secret").expect("target");
        symlink(&target, &link).expect("symlink");
        assert!(matches!(
            read_bounded_regular_file(&link, 64),
            Err(SafeOperatorFileError::LinkedPath)
        ));
    }

    #[cfg(windows)]
    #[test]
    fn rejects_windows_file_symlink_or_skips_when_creation_is_not_permitted() {
        use std::os::windows::fs::symlink_file;

        let directory = tempfile::tempdir().expect("temp dir");
        let target = directory.path().join("target");
        let link = directory.path().join("link");
        std::fs::write(&target, b"secret").expect("target");
        if symlink_file(&target, &link).is_err() {
            // Windows requires Developer Mode or SeCreateSymbolicLinkPrivilege
            // on older hosts. Reparse-point rejection is still compiled.
            return;
        }
        assert!(matches!(
            read_bounded_regular_file(&link, 64),
            Err(SafeOperatorFileError::LinkedPath)
        ));
    }
}
