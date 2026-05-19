//! Load arkworks-serialized Groth16 proving keys.
//!
//! Round 1 design: snarkjs produces `.zkey` files at setup time (trusted ceremony
//! / dev contribution). A small Rust binary (`src/bin/export_ark_zkey.rs`) parses
//! the snarkjs `.zkey` once and re-serializes it via `ark-serialize` into
//! `<circuit>_final.ark.zkey`. This module loads that arkworks-native format —
//! `ProvingKey::deserialize_uncompressed` is dramatically faster than the
//! snarkjs `.zkey` parser, which matters because proving keys for our circuits
//! run 30–200 MiB.
//!
//! We chose `deserialize_uncompressed` over `deserialize_compressed`: uncompressed
//! is ~2–4× faster to load (no subgroup checks during decompression) at the cost
//! of larger files. Build artifacts aren't size-constrained for our deployment.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use ark_bn254::Bn254;
use ark_groth16::ProvingKey;
use ark_serialize::CanonicalDeserialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ZkeyError {
    #[error("Failed to open .ark.zkey at {path}: {source}")]
    Open {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("Failed to deserialize ProvingKey from {path}: {source}")]
    Deserialize {
        path: PathBuf,
        #[source]
        source: ark_serialize::SerializationError,
    },
}

/// Cache loaded proving keys by canonical path so repeated proofs don't re-read
/// the (large) key file from disk. Keys are held forever — once loaded the
/// process is committed to keeping them resident; this matches how the verifier
/// caches `PreparedVerifyingKey` in `verify.rs`.
fn cache() -> &'static Mutex<HashMap<PathBuf, &'static ProvingKey<Bn254>>> {
    static CACHE: OnceLock<Mutex<HashMap<PathBuf, &'static ProvingKey<Bn254>>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Load and cache an arkworks-serialized proving key from disk.
///
/// On a cache hit, returns the same `&'static ProvingKey` reference without
/// touching the filesystem. On a miss, reads the file, deserializes it
/// (uncompressed format, no subgroup checks), boxes it, and leaks it for a
/// `'static` reference — see [`Box::leak`]. This is intentional: proving keys
/// are loaded a handful of times per process and never freed.
pub fn load_proving_key(path: impl AsRef<Path>) -> Result<&'static ProvingKey<Bn254>, ZkeyError> {
    let path = path.as_ref().to_path_buf();
    let key = path.clone();

    {
        let guard = cache().lock().expect("zkey cache mutex poisoned");
        if let Some(pk) = guard.get(&key) {
            return Ok(*pk);
        }
    }

    let file = std::fs::File::open(&path).map_err(|source| ZkeyError::Open {
        path: path.clone(),
        source,
    })?;
    let mut reader = std::io::BufReader::new(file);
    let pk = ProvingKey::<Bn254>::deserialize_uncompressed_unchecked(&mut reader).map_err(
        |source| ZkeyError::Deserialize {
            path: path.clone(),
            source,
        },
    )?;
    let leaked: &'static ProvingKey<Bn254> = Box::leak(Box::new(pk));

    let mut guard = cache().lock().expect("zkey cache mutex poisoned");
    guard.insert(key, leaked);
    Ok(leaked)
}
