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
    ///
    /// Gated behind `cfg(any(test, feature = "zk-test-utils"))` so the
    /// audit-M-5 newtype seal cannot be peeled off in production builds.
    /// CodeRabbit feedback on PR #1076.
    #[cfg(any(test, feature = "zk-test-utils"))]
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
    ///
    /// Same gating as [`Self::from_proving_key_for_tests`].
    #[cfg(any(test, feature = "zk-test-utils"))]
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
    #[error(
        "audit CEREMONY_INTEGRITY.md #2: .ark.zkey at {path} fails manifest blake3 check.\n  \
         expected: {expected}\n  computed: {computed}\n\n\
         The on-disk .ark.zkey does not match the manifest embedded into this build. \
         Either rebuild after running `setup_circuits.sh` so the manifest is regenerated, \
         or restore the original .ark.zkey."
    )]
    ManifestMismatch {
        path: PathBuf,
        expected: String,
        computed: String,
    },
    #[error("audit CEREMONY_INTEGRITY.md: failed to parse embedded manifest: {0}")]
    ManifestParse(#[from] crate::zk::manifest::ManifestError),
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
    let pk =
        ProvingKey::<Bn254>::deserialize_uncompressed_unchecked(&mut reader).map_err(|source| {
            ZkeyError::Deserialize {
                path: path.clone(),
                source,
            }
        })?;
    let leaked: &'static CircomProvingKey = Box::leak(Box::new(CircomProvingKey { inner: pk }));

    let mut guard = cache().lock().expect("zkey cache mutex poisoned");
    guard.insert(key, leaked);
    Ok(leaked)
}

/// Manifest-checked variant of [`load_proving_key`] — audit
/// CEREMONY_INTEGRITY.md #2.
///
/// Reads the file at `path` into memory, asserts
/// `blake3(file_bytes) == manifest_json.artifacts.ark_zkey.blake3`,
/// then deserialises. Returns `ZkeyError::ManifestMismatch` if the
/// digests differ — the on-disk file did not come from the ceremony
/// the binary was built against.
///
/// `manifest_json` is the raw JSON string typically obtained via
/// `include_str!` (e.g. `crate::zk::verify::EXISTENCE_MANIFEST_JSON`).
/// A placeholder manifest (fresh checkout, pre-setup) is detected via
/// [`crate::zk::manifest::CeremonyManifest::is_placeholder`] and
/// silently falls through to the unchecked load — the production
/// startup gate in `main.rs` is what refuses to start under
/// `OLYMPUS_ENV=production` when the manifest is still a stub.
///
/// Caching: separate from `load_proving_key`'s cache so a manifest
/// change (which would otherwise hit a stale cached entry) forces a
/// fresh blake3 check on the next call. Key is `(path, expected_blake3)`.
pub fn load_proving_key_with_manifest(
    path: impl AsRef<Path>,
    manifest_json: &str,
) -> Result<&'static CircomProvingKey, ZkeyError> {
    if crate::zk::manifest::CeremonyManifest::is_placeholder(manifest_json) {
        return load_proving_key(path);
    }
    let manifest = crate::zk::manifest::CeremonyManifest::parse(manifest_json)?;
    let path = path.as_ref().to_path_buf();
    let expected_blake3 = manifest.artifacts.ark_zkey.blake3.clone();

    let cache_key = (path.clone(), expected_blake3.clone());
    {
        let guard = checked_cache()
            .lock()
            .expect("checked zkey cache mutex poisoned");
        if let Some(pk) = guard.get(&cache_key) {
            return Ok(*pk);
        }
    }

    let bytes = std::fs::read(&path).map_err(|source| ZkeyError::Open {
        path: path.clone(),
        source,
    })?;
    let computed_blake3 = blake3::hash(&bytes).to_hex().to_string();
    if computed_blake3 != expected_blake3 {
        return Err(ZkeyError::ManifestMismatch {
            path: path.clone(),
            expected: expected_blake3,
            computed: computed_blake3,
        });
    }

    let mut reader = std::io::Cursor::new(&bytes);
    let pk =
        ProvingKey::<Bn254>::deserialize_uncompressed_unchecked(&mut reader).map_err(|source| {
            ZkeyError::Deserialize {
                path: path.clone(),
                source,
            }
        })?;
    let boxed = Box::new(CircomProvingKey { inner: pk });

    // Double-checked: re-acquire the cache lock and re-check before leaking.
    // Without this, two concurrent first-hit requests for the same
    // (path, expected_blake3) each `Box::leak` a 30–200 MiB key; only one wins
    // the map insert but both stay resident forever. The fresh `get` here lets
    // the loser drop its allocation and return the winner's static reference.
    let mut guard = checked_cache()
        .lock()
        .expect("checked zkey cache mutex poisoned");
    if let Some(existing) = guard.get(&cache_key) {
        drop(boxed);
        return Ok(*existing);
    }
    let leaked: &'static CircomProvingKey = Box::leak(boxed);
    guard.insert(cache_key, leaked);
    Ok(leaked)
}

/// Separate cache for [`load_proving_key_with_manifest`] keyed on
/// `(path, expected_blake3)` so a manifest rotation invalidates the
/// stale entry naturally rather than serving the previous load.
fn checked_cache() -> &'static Mutex<HashMap<(PathBuf, String), &'static CircomProvingKey>> {
    static CACHE: OnceLock<Mutex<HashMap<(PathBuf, String), &'static CircomProvingKey>>> =
        OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}
