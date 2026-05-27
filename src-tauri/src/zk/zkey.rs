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

/// Newtype wrapper around a snarkjs-derived `ProvingKey<Bn254>`.
///
/// Audit M-5: any `ProvingKey<Bn254>` round-tripped through
/// `export_ark_zkey` + [`load_proving_key`] must be proved with
/// `Groth16::<Bn254, CircomReduction>::prove`. The default-generic
/// `Groth16::<Bn254>::prove` uses `LibsnarkReduction` and silently produces
/// proofs that no vk can verify (#1011). The `clippy::disallowed_methods`
/// lint catches direct misuse, but a contributor can disable it locally.
///
/// This newtype makes the protection load-bearing at the type level:
/// the inner `ProvingKey` is private. The only construction site is
/// [`load_proving_key`] (sealed via [`Sealed`]); the only readout is
/// [`CircomProvingKey::as_inner`], whose visibility (`pub(crate)`) is
/// restricted to `crate::zk::prove`, where the `prove_circom` wrapper
/// is the unique consumer. New code outside `crate::zk::prove` cannot
/// extract the bare `ProvingKey` without adding a fresh API surface
/// that would necessarily route through this module.
#[derive(Debug)]
pub struct CircomProvingKey {
    inner: ProvingKey<Bn254>,
}

/// Sealed trait — exists only to prevent any external impl of
/// [`CircomProvingKey`] construction.
mod sealed {
    pub trait Sealed {}
}
impl sealed::Sealed for CircomProvingKey {}

impl CircomProvingKey {
    /// Internal-only accessor for the inner `ProvingKey`. Crate-private so
    /// only `super::prove::prove_circom` can reach it — and that wrapper
    /// pins `CircomReduction` via its generic parameter, making the wrong
    /// reduction unreachable without writing fresh code in this module.
    pub(crate) fn as_inner(&self) -> &ProvingKey<Bn254> {
        &self.inner
    }

    /// Public read-only access to the embedded verifying key. Safe to
    /// expose because `VerifyingKey<Bn254>` cannot be used to forge
    /// proofs — only to verify them — and consumers (notably the
    /// integration-test parity check between our `.ark.zkey` round-trip
    /// and ark-circom's direct `read_zkey`) need it.
    pub fn vk(&self) -> &ark_groth16::VerifyingKey<Bn254> {
        &self.inner.vk
    }

    /// Test/diagnostic constructor: wrap an already-loaded `ProvingKey`
    /// without going through [`load_proving_key`]. The integration test
    /// `tests/zk_prove_existence.rs::side_by_side_pk_load_parity` reads
    /// a snarkjs `.zkey` via `ark_circom::read_zkey` directly, then
    /// drives it through `prove_circom` for parity comparison; that test
    /// needs to wrap the bare key. Production callers must use
    /// `load_proving_key` so the M-5 type-level guarantee holds.
    pub fn from_proving_key_for_tests(pk: ProvingKey<Bn254>) -> Self {
        Self { inner: pk }
    }

    /// Escape hatch: read-only access to the embedded `ProvingKey<Bn254>`
    /// for integration tests and diagnostics. Production proving code
    /// MUST NOT use this — call [`super::prove::prove_circom`] instead,
    /// which pins `CircomReduction` and is the only sanctioned proof path
    /// (#1011, audit M-5). The `clippy::disallowed_methods` lint catches
    /// direct `Groth16::prove` invocations even when callers extract the
    /// inner key here.
    pub fn proving_key_for_tests(&self) -> &ProvingKey<Bn254> {
        &self.inner
    }
}

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
fn cache() -> &'static Mutex<HashMap<PathBuf, &'static CircomProvingKey>> {
    static CACHE: OnceLock<Mutex<HashMap<PathBuf, &'static CircomProvingKey>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Load and cache an arkworks-serialized proving key from disk.
///
/// On a cache hit, returns the same `&'static ProvingKey` reference without
/// touching the filesystem. On a miss, reads the file, deserializes it
/// (uncompressed format, no subgroup checks), boxes it, and leaks it for a
/// `'static` reference — see [`Box::leak`]. This is intentional: proving keys
/// are loaded a handful of times per process and never freed.
pub fn load_proving_key(path: impl AsRef<Path>) -> Result<&'static CircomProvingKey, ZkeyError> {
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
    let leaked: &'static CircomProvingKey =
        Box::leak(Box::new(CircomProvingKey { inner: pk }));

    let mut guard = cache().lock().expect("zkey cache mutex poisoned");
    guard.insert(key, leaked);
    Ok(leaked)
}
