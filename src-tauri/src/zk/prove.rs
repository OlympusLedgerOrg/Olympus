//! Native Rust Groth16 prover for Olympus circuits.
//!
//! Pipeline (same for every circuit, only inputs differ):
//!
//!   1. Load circom-emitted `circuit.wasm` + `circuit.r1cs` via ark-circom
//!      (`CircomConfig`).  Witness generation runs in-process under wasmer.
//!   2. Push named inputs into `CircomBuilder`.
//!   3. `builder.build()` → `CircomCircuit` with the full witness in R1CS
//!      variable order, plus the public-inputs slice in snarkjs order
//!      (outputs first, then declared public inputs).
//!   4. Load arkworks-serialized proving key via `zkey::load_proving_key`.
//!   5. `prove_circom(pk, circuit, &mut rng)` — the only sanctioned wrapper
//!      around `ark-groth16`'s Groth16 prover for snarkjs-derived keys. See
//!      the doc comment on `prove_circom` for why it must not be bypassed.
//!
//! No Node.js, no snarkjs subprocess.  The `.wasm` + `.r1cs` + `.ark.zkey`
//! artifacts are produced at setup time by `proofs/setup_circuits.sh` and
//! aren't part of the runtime trust boundary — they're outputs of the
//! trusted-setup ceremony, which the verifier independently bounds by
//! checking against an embedded vkey fingerprint.
//!
//! # Edge case 2 — multi-threaded witness de-synchronization
//!
//! Each `prove_with_inputs` call constructs a fresh `CircomConfig` (new wasmer
//! Store + Module) and a fresh `CircomBuilder`, so witness generation is fully
//! isolated per call.  Concurrent calls on different threads operate on
//! independent WASM instances and share no mutable state.  The only shared
//! data structure is `zkey::load_proving_key`'s `Mutex<HashMap>`, which
//! serialises key-cache writes — reads after the first load are lock-free
//! (the value is `'static`).
//!
//! # Edge case 3 — ptau20 constraint budget
//!
//! The Phase 1 ceremony parameters (`pot20_*.ptau`) support a maximum of
//! 2^20 = 1,048,576 constraints.  Any circuit expansion that pushes the
//! total past this limit will fail to compile against the existing `.zkey`.
//! The next tier (ptau21, 2^21 constraints) requires proving keys roughly
//! double in size (~600–800 MiB), which may exceed RAM on edge-proving
//! hardware.  Before adding nested loops, additional public-key fields, or
//! extra hash rounds to a circuit, count constraints with:
//!   `snarkjs r1cs info <circuit>.r1cs`
//! and ensure the total stays below [`PTAU20_MAX_CONSTRAINTS`].
//!
//! # Edge case 6 — under-constrained Circom signals
//!
//! A signal assigned with `-->` instead of `<==`/`===` is unconstrained: the
//! WASM witness generator fills it with any value, arkworks generates a valid
//! proof, but a malicious node can forge different inputs that pass
//! verification.  The Rust host cannot detect this — unconstrained signals
//! look like any other witness variable at the R1CS level.  Auditing for `-->`
//! usage must be part of every circuit code-review checklist.
//!
//! # Edge case 8 — front-running via witness replay
//!
//! The `document_existence` and `non_existence` circuits do not bind a
//! per-call nonce or node identity to their public signals.  A proof
//! `(A, B, C)` for `(root, leafIndex, treeSize)` is replayable: an
//! eavesdropper can wrap the same proof coordinates in a new Protobuf packet
//! addressed to themselves.  Replay protection must be enforced at the
//! application layer (e.g. record proof hashes in the database and reject
//! duplicates, or bind the caller's Ed25519 identity to the outer request
//! envelope).

use std::path::Path;
use std::sync::{Condvar, Mutex};
use std::time::Duration;

use ark_bn254::{Bn254, Fr};
use ark_circom::{CircomBuilder, CircomConfig, CircomReduction};
use ark_groth16::{Groth16, Proof};
use ark_relations::gr1cs::ConstraintSynthesizer;
use ark_snark::SNARK;
use num_bigint::BigInt;
use rand::{CryptoRng, RngCore};
use thiserror::Error;

#[cfg(feature = "quorum-circuit")]
use super::witness::QuorumProofWitness;
use super::witness::{ExistenceWitness, NonExistenceWitness, UnifiedWitness};
use super::zkey::{load_proving_key_with_manifest, CircomProvingKey, ZkeyError};

/// Maximum number of WASM witness-generator instances that may run in parallel.
///
/// Edge case 9 — WASM witness allocation OOM.
///
/// Each active `prove_*` call instantiates a wasmer WASM runtime.  For the
/// ptau20 circuits the resident set peaks at ~300–500 MiB per instance.  On a
/// machine with 4 GiB of RAM, more than ~4 concurrent instances risk triggering
/// an OOM kill that takes the entire federation node offline.  Callers that
/// exceed this limit block until a slot is released rather than spawning an
/// unbounded number of instances.  Tune this constant based on available RAM
/// and expected circuit size before deploying to memory-constrained hardware.
pub const MAX_CONCURRENT_WASM: usize = 4;

/// ptau20 maximum constraints (2^20 = 1,048,576).
/// Circuits must stay strictly below this ceiling.  See edge case 3 in the
/// module-level docs for the implications of exceeding this budget.
pub const PTAU20_MAX_CONSTRAINTS: usize = 1 << 20;

/// Counting semaphore that limits concurrent WASM witness-generator instances.
///
/// Uses a `Mutex<usize>` (available slots) + `Condvar` (wake on release).
/// This is the std-only equivalent of `tokio::sync::Semaphore` for use in
/// synchronous proving code that may be called from a Rayon / Tokio
/// spawn_blocking context.
struct WasmSemaphore {
    available: Mutex<usize>,
    condvar: Condvar,
}

impl WasmSemaphore {
    const fn new(slots: usize) -> Self {
        Self {
            available: Mutex::new(slots),
            condvar: Condvar::new(),
        }
    }

    /// Acquire a slot, blocking until one is available or `timeout` expires.
    ///
    /// Returns `Err(())` on timeout. The timeout is set to 120 s — longer than
    /// the worst-case ptau20 witness-generation time — so a return of `Err`
    /// reliably indicates stuck WASM rather than normal latency (finding 2).
    fn acquire(&self) -> Result<(), ()> {
        const TIMEOUT: Duration = Duration::from_secs(120);
        let mut slots = self
            .available
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        loop {
            if *slots > 0 {
                *slots -= 1;
                return Ok(());
            }
            let (guard, timed_out) = self
                .condvar
                .wait_timeout(slots, TIMEOUT)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            slots = guard;
            if timed_out.timed_out() {
                return Err(());
            }
        }
    }

    fn release(&self) {
        let mut slots = self
            .available
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // Guard against accidental double-release in future refactors.
        debug_assert!(
            *slots < MAX_CONCURRENT_WASM,
            "WasmSemaphore released more times than acquired"
        );
        *slots += 1;
        self.condvar.notify_one();
    }
}

static WASM_SEM: WasmSemaphore = WasmSemaphore::new(MAX_CONCURRENT_WASM);

/// RAII guard that acquires a WASM slot on construction and releases it on drop.
struct WasmSlot;

impl WasmSlot {
    fn acquire() -> Result<Self, ProveError> {
        WASM_SEM
            .acquire()
            .map_err(|()| ProveError::WasmConcurrencyTimeout)?;
        Ok(Self)
    }
}

impl Drop for WasmSlot {
    fn drop(&mut self) {
        WASM_SEM.release();
    }
}

#[derive(Debug, Error)]
pub enum ProveError {
    #[error("Witness pre-check failed: {0}")]
    WitnessInvalid(String),
    #[error(
        "WASM concurrency slot timeout: all {MAX_CONCURRENT_WASM} witness-generator slots are \
         held; this likely indicates stuck WASM instances (OOM / infinite loop). \
         Tune MAX_CONCURRENT_WASM or investigate circuit input validity."
    )]
    WasmConcurrencyTimeout,
    #[error("Failed to load CircomConfig from wasm={wasm}, r1cs={r1cs}: {source}")]
    CircomConfig {
        wasm: String,
        r1cs: String,
        #[source]
        source: color_eyre::Report,
    },
    #[error("Witness generation failed: {0}")]
    WitnessGen(color_eyre::Report),
    #[error("Zkey load error: {0}")]
    Zkey(#[from] ZkeyError),
    #[error("ark-groth16 prover error: {0}")]
    Ark(String),
    #[error("CircomCircuit produced no public inputs slot")]
    NoPublicInputs,
}

/// Prove a Groth16 proof against a snarkjs-derived ProvingKey.
///
/// **This is the only sanctioned entry point to `ark_groth16::Groth16::prove`
/// in the Olympus codebase** — `clippy.toml` at the workspace root bans
/// direct calls so any new callsite trips the lint.
///
/// Why the wrapper exists: `ark-groth16`'s `Groth16<E>` defaults its
/// `R1CSToQAP` type parameter to `LibsnarkReduction`, which uses a different
/// evaluation-domain shift than snarkjs. Snarkjs `.zkey` files — whether
/// loaded via `ark_circom::read_zkey` directly or round-tripped through our
/// `export_ark_zkey` + `zkey::load_proving_key` path — require
/// `CircomReduction`. The wrong reduction silently produces a proof that
/// fails verification *even under `pk.vk` from the same ProvingKey*: the
/// R1CS satisfiability check stays `true`, only the pairing check breaks.
/// This was the root cause of #1011.
///
/// References: <https://github.com/arkworks-rs/circom-compat/issues/35>
/// and ark-circom 0.6's own zkey round-trip test at `src/zkey.rs:862`.
///
/// Audit M-5: the proving key argument is the sealed
/// [`CircomProvingKey`] newtype, not a bare `ProvingKey<Bn254>`. The inner
/// `ProvingKey` is private and only constructible via
/// [`load_proving_key`], and only this function (in this module) can
/// reach the inner reference via the crate-private `as_inner` accessor.
/// New callers therefore cannot accidentally route a Circom-derived
/// proving key through the default `Groth16<Bn254>::prove`
/// (LibsnarkReduction) — they have nowhere to extract a `&ProvingKey`
/// from. The previous clippy-only guard remains as a belt-and-suspenders
/// lint inside this wrapper.
pub fn prove_circom<C, R>(
    pk: &CircomProvingKey,
    circuit: C,
    rng: &mut R,
) -> Result<Proof<Bn254>, ProveError>
where
    C: ConstraintSynthesizer<Fr>,
    R: RngCore + CryptoRng,
{
    // The one place in the codebase allowed to call Groth16::prove directly.
    // Don't peel this `#[allow]` off without reading the doc comment above.
    #[allow(clippy::disallowed_methods)]
    Groth16::<Bn254, CircomReduction>::prove(pk.as_inner(), circuit, rng)
        .map_err(|e| ProveError::Ark(e.to_string()))
}

/// Run the shared prove pipeline. Generic over inputs so each circuit's
/// prover stays a thin three-line wrapper. The caller is responsible for
/// running circuit-specific pre-checks (e.g. Merkle-root re-derivation)
/// before invoking this helper.
///
/// `manifest_json` is the embedded ceremony manifest covering the
/// `.ark.zkey` at `zkey_path` (audit CEREMONY_INTEGRITY.md #2). Pass
/// one of the `*_MANIFEST_JSON` constants from
/// `crate::zk::verify`. The manifest's `artifacts.ark_zkey.blake3` is
/// checked against the file before deserialise — a tampered `.ark.zkey`
/// surfaces as `ProveError::Zkey(ZkeyError::ManifestMismatch{..})`
/// instead of producing a proof that fails verification.
fn prove_with_inputs(
    inputs: Vec<(String, Vec<BigInt>)>,
    wasm_path: &Path,
    r1cs_path: &Path,
    zkey_path: &Path,
    manifest_json: &str,
) -> Result<(Proof<Bn254>, Vec<Fr>), ProveError> {
    // Validate the proving key + manifest BEFORE acquiring the scarce WASM
    // slot. `load_proving_key_with_manifest` does the blake3 check against
    // the embedded manifest (CEREMONY_INTEGRITY.md #2) and is cached after
    // first call. A `ManifestMismatch` here must not consume a slot —
    // otherwise 4 concurrent bad-zkey requests would lock the semaphore
    // for the full witness-gen time on the way to a fail-closed error.
    let pk = load_proving_key_with_manifest(zkey_path, manifest_json)?;

    // Edge case 9: acquire a WASM concurrency slot before instantiating the
    // wasmer runtime.  At peak throughput this blocks callers beyond
    // MAX_CONCURRENT_WASM rather than spawning unbounded instances that
    // exhaust the host's RAM and trigger an OOM kill.  The slot is released
    // automatically when `_slot` is dropped at the end of this function.
    // If all slots are stuck for > 120 s, returns WasmConcurrencyTimeout.
    let _slot = WasmSlot::acquire()?;

    // Step 1+2: build the circom configuration and push inputs.
    // CircomConfig is generic over the scalar field (`PrimeField`), not the
    // pairing engine — pass BN254's `Fr`, not `Bn254`.
    let cfg = CircomConfig::<Fr>::new(wasm_path, r1cs_path).map_err(|source| {
        ProveError::CircomConfig {
            wasm: wasm_path.display().to_string(),
            r1cs: r1cs_path.display().to_string(),
            source,
        }
    })?;
    let mut builder = CircomBuilder::new(cfg);
    for (name, values) in inputs {
        for v in values {
            builder.push_input(&name, v);
        }
    }

    // Step 3: run the WASM witness generator.
    let circuit = builder.build().map_err(ProveError::WitnessGen)?;
    let public_inputs = circuit
        .get_public_inputs()
        .ok_or(ProveError::NoPublicInputs)?;

    // #1011 diagnostic: synthesize the CircomCircuit into a fresh CS and check
    // satisfiability before handing the witness to Groth16::prove. ark-groth16
    // does not validate satisfiability internally — an unsatisfying witness
    // silently produces a proof that no vk can verify. Mirrors ark-circom's
    // own `satisfied` test at circuit.rs:95.
    #[cfg(feature = "zk-debug")]
    {
        use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystem};
        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit
            .clone()
            .generate_constraints(cs.clone())
            .map_err(|e| ProveError::Ark(format!("zk-debug generate_constraints: {e}")))?;
        cs.finalize();
        let satisfied = cs
            .is_satisfied()
            .map_err(|e| ProveError::Ark(format!("zk-debug is_satisfied: {e}")))?;
        eprintln!(
            "[zk-debug] num_constraints           = {}",
            cs.num_constraints()
        );
        eprintln!(
            "[zk-debug] num_instance_variables    = {}",
            cs.num_instance_variables()
        );
        eprintln!(
            "[zk-debug] num_witness_variables     = {}",
            cs.num_witness_variables()
        );
        eprintln!(
            "[zk-debug] public_inputs.len()       = {}",
            public_inputs.len()
        );
        eprintln!("[zk-debug] cs.is_satisfied()         = {satisfied}");
        if !satisfied {
            let which = cs
                .which_is_unsatisfied()
                .map_err(|e| ProveError::Ark(format!("zk-debug which_is_unsatisfied: {e}")))?;
            eprintln!("[zk-debug] which_is_unsatisfied()    = {which:?}");
        }
    }

    // Step 4: `pk` was already loaded + manifest-checked above the WASM
    // slot acquisition (CEREMONY_INTEGRITY.md #2). Cached, so this is the
    // same `&'static CircomProvingKey` reference.

    // Step 5: Groth16 prove. The (r, s) randomness must be fresh per proof.
    // Routed through `prove_circom` to guarantee CircomReduction is used.
    let mut rng = rand::thread_rng();
    let proof = prove_circom(pk, circuit, &mut rng)?;

    Ok((proof, public_inputs))
}

/// Prove `document_existence` — Poseidon Merkle inclusion at a given index.
///
/// Public signal order returned: `[root, leafIndex, treeSize]`.
pub fn prove_existence(
    witness: &ExistenceWitness,
    wasm_path: &Path,
    r1cs_path: &Path,
    zkey_path: &Path,
) -> Result<(Proof<Bn254>, Vec<Fr>), ProveError> {
    // Fast pre-check: re-derive the Merkle root from private inputs.
    witness
        .verify_merkle_root()
        .map_err(|e| ProveError::WitnessInvalid(e.to_string()))?;
    prove_with_inputs(
        witness.circom_inputs(),
        wasm_path,
        r1cs_path,
        zkey_path,
        super::verify::EXISTENCE_MANIFEST_JSON,
    )
}

/// Prove `non_existence` — SMT keyed non-membership.
///
/// Public signal order returned: `[root]`. The circuit declares no output
/// signals.
pub fn prove_non_existence(
    witness: &NonExistenceWitness,
    wasm_path: &Path,
    r1cs_path: &Path,
    zkey_path: &Path,
) -> Result<(Proof<Bn254>, Vec<Fr>), ProveError> {
    witness
        .verify_merkle_root()
        .map_err(|e| ProveError::WitnessInvalid(e.to_string()))?;
    prove_with_inputs(
        witness.circom_inputs(),
        wasm_path,
        r1cs_path,
        zkey_path,
        super::verify::NON_EXISTENCE_MANIFEST_JSON,
    )
}

/// Prove `unified_canonicalization_inclusion_root_sign` — three-in-one
/// proof of (canonicalization | Merkle inclusion | SMT root commitment).
///
/// **Despite the `_root_sign` suffix in the circuit name, there is NO
/// in-circuit signature verification.** The circuit's own docstring
/// (`proofs/circuits/...:42`) is explicit: checkpoint integrity, including
/// the BJJ authority signature, is verified at the Rust/federation layer
/// via `federation::verify::verify_checkpoint_signature`. An earlier
/// roadmap planned an in-circuit `EdDSAPoseidonVerifier`; that template
/// was never wired in. Audit C-1.
///
/// Public signal order returned: `[canonicalHash, merkleRoot, ledgerRoot,
/// treeSize]` — matching `component main {public [...]}` exactly. The
/// unified circuit declares no `signal output`, so no synthetic public
/// signals precede these.
///
/// Audit M-Z1: native pre-check via [`UnifiedWitness::verify_inputs`]
/// re-derives the Merkle and SMT roots before acquiring the WASM slot.
/// A malformed witness fails in microseconds with a precise error
/// instead of waiting for full WASM witness generation to surface an
/// opaque failure — closes the DoS window where 4 bad concurrent
/// witnesses could lock [`WASM_SEM`] for the 120s semaphore timeout.
/// EdDSA-Poseidon pre-verification stays deferred (heavy enough to be
/// wasteful when the circuit will run it anyway).
pub fn prove_unified(
    witness: &UnifiedWitness,
    wasm_path: &Path,
    r1cs_path: &Path,
    zkey_path: &Path,
) -> Result<(Proof<Bn254>, Vec<Fr>), ProveError> {
    witness
        .verify_inputs()
        .map_err(|e| ProveError::WitnessInvalid(e.to_string()))?;
    prove_with_inputs(
        witness.circom_inputs(),
        wasm_path,
        r1cs_path,
        zkey_path,
        super::verify::UNIFIED_MANIFEST_JSON,
    )
}

/// Prove `federation_quorum` — ≥ M of N pinned federation signers co-signed
/// the quorum message, without revealing which subset.
///
/// Public signal order returned: `[msg, signerAx[0..N], signerAy[0..N],
/// threshold]` (the circuit declares no `signal output`). Requires the
/// circuit's trusted-setup artifacts to be staged; with a placeholder
/// `.ark.zkey` the load fails closed. Gated behind `quorum-circuit`.
#[cfg(feature = "quorum-circuit")]
pub fn prove_quorum(
    witness: &QuorumProofWitness,
    wasm_path: &Path,
    r1cs_path: &Path,
    zkey_path: &Path,
) -> Result<(Proof<Bn254>, Vec<Fr>), ProveError> {
    witness
        .verify_inputs()
        .map_err(|e| ProveError::WitnessInvalid(e.to_string()))?;
    prove_with_inputs(
        witness.circom_inputs(),
        wasm_path,
        r1cs_path,
        zkey_path,
        super::verify::FEDERATION_QUORUM_MANIFEST_JSON,
    )
}

#[cfg(all(test, feature = "quorum-circuit"))]
mod quorum_prove_tests {
    use super::{prove_quorum, ProveError};
    use crate::quorum::FEDERATION_QUORUM_N;
    use crate::zk::witness::quorum::QuorumProofWitness;
    use ark_bn254::Fr;
    use std::path::Path;

    /// `prove_quorum` runs `verify_inputs` (a native pre-check) before it
    /// loads any circuit artifact, so an invalid witness must surface as
    /// `WitnessInvalid` even when the proving key is absent. This kills the
    /// "replace prove_quorum body with `Ok((default proof, …))`" mutant
    /// without needing the (ceremony-pending) federation_quorum `.ark.zkey`:
    /// the real fn returns `Err`, the mutant returns `Ok`.
    #[test]
    fn prove_quorum_rejects_invalid_witness_before_touching_artifacts() {
        const N: usize = FEDERATION_QUORUM_N;
        // Slot 0 is enabled but carries a non-verifying signature (zero R8/S
        // under an off-curve pubkey), so `verify_inputs` rejects it.
        let mut enabled = [0u8; N];
        enabled[0] = 1;
        let witness = QuorumProofWitness {
            msg: Fr::from(1u64),
            signer_ax: [Fr::from(1u64); N],
            signer_ay: [Fr::from(2u64); N],
            threshold: 1,
            enabled,
            r8x: [Fr::from(0u64); N],
            r8y: [Fr::from(0u64); N],
            s: [Fr::from(0u64); N],
        };
        let err = prove_quorum(
            &witness,
            Path::new("/nonexistent/federation_quorum.wasm"),
            Path::new("/nonexistent/federation_quorum.r1cs"),
            Path::new("/nonexistent/federation_quorum.ark.zkey"),
        )
        .expect_err("invalid witness must be rejected before artifact load");
        assert!(matches!(err, ProveError::WitnessInvalid(_)), "got: {err:?}");
    }
}
