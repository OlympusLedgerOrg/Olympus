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

/// Blocking implementation of the unpack logic.
fn unpack_postgres_blocking(zip_file_path: &Path, cache_dir: &Path) -> Result<()> {
    let tar_content = read_postgres_tar(zip_file_path)?;
    Archive::new(Cursor::new(tar_content))
        .unpack(cache_dir)
        .map_err(|e| {
            log::error!("Tar unpack to {} failed: {e}", cache_dir.display());
            Error::UnpackFailure
        })
}

/// Compare the extracted `initdb` and `pg_ctl` bytes with the copies in the
/// retained archive.
pub(crate) async fn postgres_executables_match_archive(
    zip_file_path: &Path,
    init_db_exe: &Path,
    pg_ctl_exe: &Path,
) -> Result<bool> {
    let zip_file_path = zip_file_path.to_path_buf();
    let init_db_exe = init_db_exe.to_path_buf();
    let pg_ctl_exe = pg_ctl_exe.to_path_buf();
    tokio::task::spawn_blocking(move || {
        postgres_executables_match_archive_blocking(&zip_file_path, &init_db_exe, &pg_ctl_exe)
    })
    .await
    .map_err(|e| Error::PgError(e.to_string(), "spawn_blocking join error".into()))?
}

fn postgres_executables_match_archive_blocking(
    zip_file_path: &Path,
    init_db_exe: &Path,
    pg_ctl_exe: &Path,
) -> Result<bool> {
    let tar_content = read_postgres_tar(zip_file_path)?;
    let init_name = init_db_exe.file_name().ok_or(Error::InvalidPgPackage)?;
    let pg_ctl_name = pg_ctl_exe.file_name().ok_or(Error::InvalidPgPackage)?;
    let init_path = Path::new("bin").join(init_name);
    let pg_ctl_path = Path::new("bin").join(pg_ctl_name);
    let mut init_digest = None;
    let mut pg_ctl_digest = None;

    let mut archive = Archive::new(Cursor::new(tar_content));
    let entries = archive.entries().map_err(|_| Error::InvalidPgPackage)?;
    for entry in entries {
        let mut entry = entry.map_err(|_| Error::InvalidPgPackage)?;
        let path = entry
            .path()
            .map_err(|_| Error::InvalidPgPackage)?
            .into_owned();
        if path == init_path {
            init_digest = Some(hash_reader(&mut entry)?);
        } else if path == pg_ctl_path {
            pg_ctl_digest = Some(hash_reader(&mut entry)?);
        }
    }

    let init_digest = init_digest.ok_or(Error::InvalidPgPackage)?;
    let pg_ctl_digest = pg_ctl_digest.ok_or(Error::InvalidPgPackage)?;
    Ok(init_digest == hash_file(init_db_exe)? && pg_ctl_digest == hash_file(pg_ctl_exe)?)
}

fn read_postgres_tar(zip_file_path: &Path) -> Result<Vec<u8>> {
    let zip_file =
        fs::File::open(zip_file_path).map_err(|e| Error::ReadFileError(e.to_string()))?;
    let mut jar_archive = ZipArchive::new(zip_file).map_err(|_| Error::InvalidPgPackage)?;

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
    let mut file = fs::File::open(path).map_err(|e| Error::ReadFileError(e.to_string()))?;
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
}
