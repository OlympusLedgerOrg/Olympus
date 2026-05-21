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
//!   5. `ark-groth16::Groth16::<Bn254>::prove(pk, circuit, &mut rng)`.
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
//! envelope).  The `redaction_validity` circuit already mitigates this via
//! the `nullifier = Poseidon(originalRoot, redactedCommitment, recipientId)`
//! output signal — extend the same pattern to existence circuits when the
//! next circuit recompilation is scheduled.

use std::path::Path;
use std::sync::{Condvar, Mutex};
use std::time::Duration;

use ark_bn254::{Bn254, Fr};
use ark_circom::{CircomBuilder, CircomConfig};
use ark_groth16::{Groth16, Proof};
use ark_snark::SNARK;
use num_bigint::BigInt;
use thiserror::Error;

use super::witness::{ExistenceWitness, NonExistenceWitness, RedactionWitness, UnifiedWitness};
use super::zkey::{load_proving_key, ZkeyError};

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
        WASM_SEM.acquire().map_err(|()| ProveError::WasmConcurrencyTimeout)?;
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

/// Run the shared prove pipeline. Generic over inputs so each circuit's
/// prover stays a thin three-line wrapper. The caller is responsible for
/// running circuit-specific pre-checks (e.g. Merkle-root re-derivation)
/// before invoking this helper.
fn prove_with_inputs(
    inputs: Vec<(String, Vec<BigInt>)>,
    wasm_path: &Path,
    r1cs_path: &Path,
    zkey_path: &Path,
) -> Result<(Proof<Bn254>, Vec<Fr>), ProveError> {
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

    // Step 4: load the arkworks-serialized proving key (cached).
    let pk = load_proving_key(zkey_path)?;

    // Step 5: Groth16 prove. The (r, s) randomness must be fresh per proof.
    let mut rng = rand::thread_rng();
    let proof = Groth16::<Bn254>::prove(pk, circuit, &mut rng)
        .map_err(|e| ProveError::Ark(e.to_string()))?;

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
    prove_with_inputs(witness.circom_inputs(), wasm_path, r1cs_path, zkey_path)
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
    prove_with_inputs(witness.circom_inputs(), wasm_path, r1cs_path, zkey_path)
}

/// Prove `redaction_validity` — selective disclosure with domain-3 commitment.
///
/// Public signal order returned: `[nullifier, originalRoot,
/// redactedCommitment, revealedCount]`.  The leading `nullifier` is a
/// circuit-output signal — in circom 2 outputs precede declared public
/// inputs in the snarkjs publicSignals vector.
pub fn prove_redaction(
    witness: &RedactionWitness,
    wasm_path: &Path,
    r1cs_path: &Path,
    zkey_path: &Path,
) -> Result<(Proof<Bn254>, Vec<Fr>), ProveError> {
    witness
        .verify_all_paths()
        .map_err(|e| ProveError::WitnessInvalid(e.to_string()))?;
    prove_with_inputs(witness.circom_inputs(), wasm_path, r1cs_path, zkey_path)
}

/// Prove `unified_canonicalization_inclusion_root_sign` — three-in-one
/// proof of (canonicalization | Merkle inclusion | SMT commitment) plus
/// an in-circuit EdDSA-Poseidon checkpoint signature verification.
///
/// Public signal order returned: `[canonicalHash, merkleRoot, ledgerRoot,
/// treeSize, checkpointTimestamp, authorityPubKeyHash]`.  The unified
/// circuit declares no `signal output`, so no synthetic public signals
/// precede these.
///
/// No pre-check is run here — adding native Rust mirrors of the
/// canonicalization Poseidon chain, the Merkle re-derivation, the SMT
/// re-derivation, AND the EdDSA-Poseidon signature check is a separate
/// piece of work.  An invalid witness will surface as a witness-
/// generation failure inside ark-circom instead of a fast pre-check
/// here.  TODO: port the pre-check helpers to mirror `prove_existence` /
/// `prove_redaction`.
pub fn prove_unified(
    witness: &UnifiedWitness,
    wasm_path: &Path,
    r1cs_path: &Path,
    zkey_path: &Path,
) -> Result<(Proof<Bn254>, Vec<Fr>), ProveError> {
    prove_with_inputs(witness.circom_inputs(), wasm_path, r1cs_path, zkey_path)
}
