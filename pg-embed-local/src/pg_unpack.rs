//! Unpacks the PostgreSQL binaries JAR into the binary cache.
//!
//! The JAR (a ZIP archive) distributed by
//! [zonkyio/embedded-postgres-binaries](https://github.com/zonkyio/embedded-postgres-binaries)
//! contains a single `.txz`-compressed tarball (a tar archive compressed with
//! XZ/LZMA2, sometimes also named `.tar.xz`).  [`unpack_postgres`] locates
//! that entry, decompresses it with [`lzma_rs`], and extracts the resulting
//! tar archive into `cache_dir`.
//!
//! All I/O runs inside [`tokio::task::spawn_blocking`] so it does not block
//! the async executor.

use std::fs;
use std::io::{Cursor, Read};
use std::path::Path;
use std::sync::Arc;

use sha2::{Digest, Sha256};
use tar::Archive;
use zip::ZipArchive;

use crate::pg_errors::{Error, Result};

/// Unpacks the PostgreSQL binaries ZIP/JAR into `cache_dir`.
///
/// Spawns a blocking task that opens `zip_file_path`, finds the `.txz` entry
/// (XZ-compressed tarball), decompresses it, and extracts the tar archive into
/// `cache_dir`.
///
/// # Arguments
///
/// * `zip_file_path` — Path to the downloaded JAR file.
/// * `cache_dir` — Destination directory for the extracted binaries.
///
/// # Errors
///
/// Returns [`Error::ReadFileError`] if the ZIP file cannot be opened.
/// Returns [`Error::InvalidPgPackage`] if the archive is malformed or an
/// entry cannot be read.
/// Returns [`Error::UnpackFailure`] if XZ decompression or tar extraction
/// fails.
/// Returns [`Error::PgError`] if the blocking task panics or cannot be joined.
pub async fn unpack_postgres(zip_file_path: &Path, cache_dir: &Path) -> Result<()> {
    let zip_file_path = zip_file_path.to_path_buf();
    let cache_dir = cache_dir.to_path_buf();
    tokio::task::spawn_blocking(move || unpack_postgres_blocking(&zip_file_path, &cache_dir))
        .await
        .map_err(|e| Error::PgError(e.to_string(), "spawn_blocking join error".into()))?
}

/// Unpack the exact archive byte snapshot that was authenticated by the
/// caller. Keeping verification and decompression on the same owned bytes
/// prevents a pathname replacement between those two operations.
pub(crate) async fn unpack_postgres_snapshot(
    archive_snapshot: Arc<[u8]>,
    cache_dir: &Path,
) -> Result<()> {
    let cache_dir = cache_dir.to_path_buf();
    tokio::task::spawn_blocking(move || {
        unpack_postgres_snapshot_blocking(&archive_snapshot, &cache_dir)
    })
    .await
    .map_err(|e| Error::PgError(e.to_string(), "spawn_blocking join error".into()))?
}

/// Blocking implementation of the unpack logic.
fn unpack_postgres_blocking(zip_file_path: &Path, cache_dir: &Path) -> Result<()> {
    let tar_content = read_postgres_tar(zip_file_path)?;
    unpack_postgres_tar(tar_content, cache_dir)
}

fn unpack_postgres_snapshot_blocking(archive_snapshot: &[u8], cache_dir: &Path) -> Result<()> {
    let tar_content = read_postgres_tar_snapshot(archive_snapshot)?;
    unpack_postgres_tar(tar_content, cache_dir)
}

fn unpack_postgres_tar(tar_content: Vec<u8>, cache_dir: &Path) -> Result<()> {
    Archive::new(Cursor::new(tar_content))
        .unpack(cache_dir)
        .map_err(|e| {
            log::error!("Tar unpack to {} failed: {e}", cache_dir.display());
            Error::UnpackFailure
        })
}

/// Immutable executable identities from an authenticated PostgreSQL archive
/// snapshot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ArchiveExecutableDigests {
    pub(crate) initdb_sha256: [u8; 32],
    pub(crate) pg_ctl_sha256: [u8; 32],
    pub(crate) sha256: [u8; 32],
}

/// Compare extracted `initdb`, `pg_ctl`, and `postgres` bytes with the exact
/// package-digest-authenticated archive snapshot. The returned PostgreSQL
/// digest is derived from the archive entry, never from reopening the mutable
/// extracted pathname.
pub(crate) async fn authenticate_executables_from_archive_snapshot(
    archive_snapshot: Arc<[u8]>,
    init_db_exe: &Path,
    pg_ctl_exe: &Path,
    postgres_exe: &Path,
) -> Result<Option<ArchiveExecutableDigests>> {
    let init_db_exe = init_db_exe.to_path_buf();
    let pg_ctl_exe = pg_ctl_exe.to_path_buf();
    let postgres_exe = postgres_exe.to_path_buf();
    tokio::task::spawn_blocking(move || {
        authenticate_executables_from_archive_snapshot_blocking(
            &archive_snapshot,
            &init_db_exe,
            &pg_ctl_exe,
            &postgres_exe,
        )
    })
    .await
    .map_err(|e| Error::PgError(e.to_string(), "spawn_blocking join error".into()))?
}

fn authenticate_executables_from_archive_snapshot_blocking(
    archive_snapshot: &[u8],
    init_db_exe: &Path,
    pg_ctl_exe: &Path,
    postgres_exe: &Path,
) -> Result<Option<ArchiveExecutableDigests>> {
    let tar_content = read_postgres_tar_snapshot(archive_snapshot)?;
    let init_name = init_db_exe.file_name().ok_or(Error::InvalidPgPackage)?;
    let pg_ctl_name = pg_ctl_exe.file_name().ok_or(Error::InvalidPgPackage)?;
    let postgres_name = postgres_exe.file_name().ok_or(Error::InvalidPgPackage)?;
    let init_path = Path::new("bin").join(init_name);
    let pg_ctl_path = Path::new("bin").join(pg_ctl_name);
    let postgres_path = Path::new("bin").join(postgres_name);
    let mut init_digest = None;
    let mut pg_ctl_digest = None;
    let mut postgres_digest = None;

    let mut archive = Archive::new(Cursor::new(tar_content));
    let entries = archive.entries().map_err(|_| Error::InvalidPgPackage)?;
    for entry in entries {
        let mut entry = entry.map_err(|_| Error::InvalidPgPackage)?;
        let path = normalize_archive_entry_path(
            &entry
                .path()
                .map_err(|_| Error::InvalidPgPackage)?
                .into_owned(),
        )?;
        if path == init_path {
            if init_digest.is_some() {
                return Err(Error::InvalidPgPackage);
            }
            if !entry.header().entry_type().is_file() {
                return Err(Error::InvalidPgPackage);
            }
            init_digest = Some(hash_reader(&mut entry)?);
        } else if path == pg_ctl_path {
            if pg_ctl_digest.is_some() {
                return Err(Error::InvalidPgPackage);
            }
            if !entry.header().entry_type().is_file() {
                return Err(Error::InvalidPgPackage);
            }
            pg_ctl_digest = Some(hash_reader(&mut entry)?);
        } else if path == postgres_path {
            if postgres_digest.is_some() {
                return Err(Error::InvalidPgPackage);
            }
            if !entry.header().entry_type().is_file() {
                return Err(Error::InvalidPgPackage);
            }
            postgres_digest = Some(hash_reader(&mut entry)?);
        }
    }

    let init_digest = init_digest.ok_or(Error::InvalidPgPackage)?;
    let pg_ctl_digest = pg_ctl_digest.ok_or(Error::InvalidPgPackage)?;
    let postgres_digest = postgres_digest.ok_or(Error::InvalidPgPackage)?;
    let matches = init_digest == hash_file(init_db_exe)?
        && pg_ctl_digest == hash_file(pg_ctl_exe)?
        && postgres_digest == hash_file(postgres_exe)?;
    Ok(matches.then_some(ArchiveExecutableDigests {
        initdb_sha256: init_digest,
        pg_ctl_sha256: pg_ctl_digest,
        sha256: postgres_digest,
    }))
}

/// Normalize the extraction-equivalent path used by `tar::Archive::unpack`.
///
/// Source-pinned PostgreSQL packages may spell safe relative entries as either
/// `bin/postgres` or `./bin/postgres`. Authentication must bind the same file
/// that extraction publishes, while still rejecting absolute paths, platform
/// prefixes, and parent traversal before any executable digest is accepted.
fn normalize_archive_entry_path(path: &Path) -> Result<std::path::PathBuf> {
    use std::path::Component;

    let mut normalized = std::path::PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::Normal(segment) => normalized.push(segment),
            Component::Prefix(_) | Component::RootDir | Component::ParentDir => {
                return Err(Error::InvalidPgPackage);
            }
        }
    }
    if normalized.as_os_str().is_empty() {
        return Err(Error::InvalidPgPackage);
    }
    Ok(normalized)
}

fn read_postgres_tar(zip_file_path: &Path) -> Result<Vec<u8>> {
    let archive_snapshot =
        fs::read(zip_file_path).map_err(|e| Error::ReadFileError(e.to_string()))?;
    read_postgres_tar_snapshot(&archive_snapshot)
}

fn read_postgres_tar_snapshot(archive_snapshot: &[u8]) -> Result<Vec<u8>> {
    let mut jar_archive =
        ZipArchive::new(Cursor::new(archive_snapshot)).map_err(|_| Error::InvalidPgPackage)?;

    for i in 0..jar_archive.len() {
        let mut file = jar_archive
            .by_index(i)
            .map_err(|_| Error::InvalidPgPackage)?;

        if file.name().ends_with(".txz") || file.name().ends_with(".xz") {
            let mut xz_content = Vec::with_capacity(file.compressed_size() as usize);
            file.read_to_end(&mut xz_content)
                .map_err(|e| Error::ReadFileError(e.to_string()))?;

            let mut tar_content = Vec::new();
            lzma_rs::xz_decompress(&mut Cursor::new(&xz_content), &mut tar_content).map_err(
                |e| {
                    log::error!("XZ decompress failed: {e:?}");
                    Error::UnpackFailure
                },
            )?;
            return Ok(tar_content);
        }
    }

    Err(Error::InvalidPgPackage)
}

fn hash_reader(reader: &mut impl Read) -> Result<[u8; 32]> {
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(|e| Error::ReadFileError(e.to_string()))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher.finalize().into())
}

fn hash_file(path: &Path) -> Result<[u8; 32]> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let mut file = options
        .open(path)
        .map_err(|e| Error::ReadFileError(e.to_string()))?;
    let metadata = file
        .metadata()
        .map_err(|e| Error::ReadFileError(e.to_string()))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(Error::InvalidPgPackage);
    }
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(Error::InvalidPgPackage);
        }
    }
    // Hash through the already-opened no-follow handle. A replacement of the
    // pathname after this point cannot change the bytes being authenticated.
    hash_reader(&mut file)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;
    use tempfile::tempdir;
    use zip::write::{SimpleFileOptions, ZipWriter};

    #[tokio::test]
    async fn test_unpack_postgres() -> Result<()> {
        let temp_dir = tempdir().expect("Failed to create temp dir");
        let cache_dir = temp_dir.path().join("cache");
        let zip_file_path = temp_dir.path().join("test_archive.zip");

        // Build a zip containing an xz-compressed tarball
        {
            let tar_content = create_dummy_tar_content();
            let xz_content = compress_with_xz(&tar_content);

            let zip_file = File::create(&zip_file_path).expect("Failed to create zip file");
            let mut zip_writer = ZipWriter::new(zip_file);

            zip_writer
                .start_file("postgres-test.txz", SimpleFileOptions::default())
                .expect("Failed to start zip entry");

            zip_writer
                .write_all(&xz_content)
                .expect("Failed to write compressed content to zip file");

            zip_writer.finish().expect("Failed to finish zip file");
        }

        let result = unpack_postgres(&zip_file_path, &cache_dir).await;
        assert!(
            result.is_ok(),
            "unpack_postgres should succeed: {:?}",
            result
        );

        let unpacked_files: Vec<_> = std::fs::read_dir(&cache_dir)
            .expect("Failed to read unpacked directory")
            .collect();

        assert!(
            !unpacked_files.is_empty(),
            "cache_dir should contain the unpacked files"
        );

        Ok(())
    }

    /// Create a minimal tar archive containing a single dummy file
    fn create_dummy_tar_content() -> Vec<u8> {
        let mut tar_data = Vec::new();
        {
            let mut ar = tar::Builder::new(&mut tar_data);
            let content = b"Hello, Postgres!";
            let mut header = tar::Header::new_gnu();
            header.set_size(content.len() as u64);
            header.set_cksum();
            ar.append_data(&mut header, "dummy_file.txt", &content[..])
                .expect("Failed to add file to tar");
        }
        tar_data
    }

    /// Compress `data` using XZ (LZMA2) via lzma-rs
    fn compress_with_xz(data: &[u8]) -> Vec<u8> {
        let mut compressed = Vec::new();
        lzma_rs::xz_compress(&mut Cursor::new(data), &mut compressed)
            .expect("Failed to compress data with xz");
        compressed
    }

    #[test]
    fn archive_entry_normalization_matches_safe_extraction_paths() {
        assert_eq!(
            normalize_archive_entry_path(Path::new("./bin/postgres")).unwrap(),
            Path::new("bin/postgres")
        );
        assert_eq!(
            normalize_archive_entry_path(Path::new("bin/initdb")).unwrap(),
            Path::new("bin/initdb")
        );
    }

    #[test]
    fn archive_entry_normalization_rejects_escape_paths() {
        assert!(matches!(
            normalize_archive_entry_path(Path::new("../bin/postgres")),
            Err(Error::InvalidPgPackage)
        ));
        assert!(matches!(
            normalize_archive_entry_path(Path::new("/bin/postgres")),
            Err(Error::InvalidPgPackage)
        ));
    }
}
