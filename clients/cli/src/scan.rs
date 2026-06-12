//! Local shard scanning: walk a directory, BLAKE3-hash each file, and assemble
//! a [`RecordIndex`]. Zero-dependency recursive walk (no `walkdir`).

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use olympus_manifest::{RecordEntry, RecordIndex, ShardRecords};

/// How records are assigned to shards while scanning.
pub enum ShardMode {
    /// All files land in a single named shard.
    Single(String),
    /// The first path component under the data root is the shard id (files
    /// directly under the root use `fallback`).
    BySubdir { fallback: String },
}

/// BLAKE3-hash a file in streaming fashion, returning `(hex_hash, byte_len)`.
pub fn hash_file(path: &Path) -> io::Result<(String, u64)> {
    let mut f = fs::File::open(path)?;
    let mut hasher = blake3::Hasher::new();
    let mut buf = vec![0u8; 1 << 16];
    let mut len: u64 = 0;
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        len += n as u64;
    }
    Ok((hasher.finalize().to_hex().to_string(), len))
}

/// Recursively collect files under `root`, sorted for determinism.
fn collect_files(root: &Path) -> io::Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let mut entries: Vec<PathBuf> = fs::read_dir(&dir)?
            .map(|e| e.map(|e| e.path()))
            .collect::<io::Result<_>>()?;
        entries.sort();
        for p in entries {
            // Use symlink_metadata (lstat) so symlinks are never followed: a
            // symlinked directory could loop or escape `root`, and a symlinked
            // file would commit bytes from outside the dataset. Skip both.
            let ft = p.symlink_metadata()?.file_type();
            if ft.is_symlink() {
                continue;
            } else if ft.is_dir() {
                stack.push(p);
            } else if ft.is_file() {
                out.push(p);
            }
        }
    }
    out.sort();
    Ok(out)
}

/// POSIX-style relative path from `root` to `path`, used as the record id.
///
/// Fails on a non-UTF-8 path component rather than lossily replacing it: a
/// committed record id must be unambiguous (two distinct non-UTF-8 names must
/// not collapse to the same id).
fn rel_record_id(root: &Path, path: &Path) -> io::Result<String> {
    let rel = path.strip_prefix(root).unwrap_or(path);
    let mut parts = Vec::new();
    for c in rel.components() {
        match c.as_os_str().to_str() {
            Some(s) => parts.push(s.to_string()),
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("non-UTF-8 path component in {}", path.display()),
                ))
            }
        }
    }
    Ok(parts.join("/"))
}

/// Scan `root` into a [`RecordIndex`], assigning shards per `mode`. Returns the
/// index and the total byte size hashed.
pub fn scan(root: &Path, mode: &ShardMode) -> io::Result<(RecordIndex, u64)> {
    let files = collect_files(root)?;
    let mut shards: BTreeMap<String, Vec<RecordEntry>> = BTreeMap::new();
    let mut total_bytes = 0u64;

    for path in &files {
        let record_id = rel_record_id(root, path)?;
        let (content_hash, byte_size) = hash_file(path)?;
        total_bytes += byte_size;
        let shard_id = match mode {
            ShardMode::Single(s) => s.clone(),
            ShardMode::BySubdir { fallback } => record_id
                .split_once('/')
                .map(|(head, _)| head.to_string())
                .unwrap_or_else(|| fallback.clone()),
        };
        shards.entry(shard_id).or_default().push(RecordEntry {
            record_id,
            content_hash,
            version: 1,
            byte_size: Some(byte_size),
        });
    }

    let index = RecordIndex {
        shards: shards
            .into_iter()
            .map(|(shard_id, records)| ShardRecords { shard_id, records })
            .collect(),
    };
    Ok((index, total_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn scan_single_shard_hashes_all_files() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), b"hello").unwrap();
        fs::create_dir(dir.path().join("sub")).unwrap();
        fs::write(dir.path().join("sub/b.txt"), b"world").unwrap();

        let (idx, bytes) = scan(dir.path(), &ShardMode::Single("files".into())).unwrap();
        assert_eq!(idx.shards.len(), 1);
        assert_eq!(idx.shards[0].shard_id, "files");
        assert_eq!(idx.record_count(), 2);
        assert_eq!(bytes, 10);
        // record_ids are POSIX relative paths.
        let ids: Vec<_> = idx.shards[0].records.iter().map(|r| &r.record_id).collect();
        assert!(ids.iter().any(|i| *i == "a.txt"));
        assert!(ids.iter().any(|i| *i == "sub/b.txt"));
        // content hash matches direct BLAKE3.
        let want = blake3::hash(b"hello").to_hex().to_string();
        let got = &idx.shards[0]
            .records
            .iter()
            .find(|r| r.record_id == "a.txt")
            .unwrap()
            .content_hash;
        assert_eq!(got, &want);
    }

    #[test]
    fn scan_by_subdir_splits_shards() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join("train")).unwrap();
        fs::create_dir(dir.path().join("eval")).unwrap();
        fs::write(dir.path().join("train/x").as_path(), b"x").unwrap();
        fs::write(dir.path().join("eval/y").as_path(), b"y").unwrap();
        fs::write(dir.path().join("top"), b"t").unwrap();

        let (idx, _) = scan(
            dir.path(),
            &ShardMode::BySubdir {
                fallback: "_root".into(),
            },
        )
        .unwrap();
        let shard_ids: Vec<_> = idx.shards.iter().map(|s| s.shard_id.clone()).collect();
        assert!(shard_ids.contains(&"train".to_string()));
        assert!(shard_ids.contains(&"eval".to_string()));
        assert!(shard_ids.contains(&"_root".to_string()));
    }

    #[cfg(unix)]
    #[test]
    fn scan_skips_symlinks() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("real.txt"), b"real").unwrap();
        // A symlink to a file outside the tree, and a symlink to a sibling: both
        // must be skipped so we never hash through a link.
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("secret"), b"secret").unwrap();
        symlink(outside.path().join("secret"), dir.path().join("link.txt")).unwrap();
        symlink(dir.path().join("real.txt"), dir.path().join("alias.txt")).unwrap();

        let (idx, _) = scan(dir.path(), &ShardMode::Single("files".into())).unwrap();
        let ids: Vec<_> = idx.shards[0]
            .records
            .iter()
            .map(|r| r.record_id.clone())
            .collect();
        assert_eq!(
            ids,
            vec!["real.txt".to_string()],
            "symlinks must be skipped"
        );
    }
}
