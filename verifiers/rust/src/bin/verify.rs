//! `olympus-verifier verify` — independent Groth16 verifier CLI.
//!
//! Red-team C1: `docs/court-evidence.md` §2 documents this binary so a court
//! / opposing counsel can independently verify a snarkjs proof against the
//! published `*_vkey.json` without trusting Olympus's runtime.
//!
//! Invocation (matches court-evidence.md):
//!
//! ```text
//! cargo run --release -- verify \
//!     --circuit document_existence \
//!     --vkey ../../proofs/keys/verification_keys/document_existence_vkey.json \
//!     --proof <proof.json> \
//!     --public-signals <signals.json>
//! ```
//!
//! Exits 0 on accept, 1 on clean reject, 2 on malformed inputs / parse error.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};

use olympus_verifier::groth16::{self, VerifyError};

#[derive(Parser)]
#[command(
    name = "olympus-verifier",
    about = "Independent Olympus verifier (Groth16 + offline SMT)",
    version
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Verify a Groth16 proof against a snarkjs verification key + public signals.
    Verify(VerifyArgs),
}

#[derive(Parser)]
struct VerifyArgs {
    /// Logical circuit name — used only for human-readable output. The vkey is
    /// the actual authority; pass the matching `*_vkey.json` via `--vkey`.
    #[arg(long, value_enum)]
    circuit: Circuit,

    /// Path to the snarkjs verification-key JSON.
    #[arg(long)]
    vkey: PathBuf,

    /// Path to the snarkjs proof JSON (pi_a / pi_b / pi_c).
    #[arg(long)]
    proof: PathBuf,

    /// Path to the public-signals JSON (array of decimal strings).
    #[arg(long = "public-signals")]
    public_signals: PathBuf,
}

// `rename_all = "snake_case"` pins the accepted CLI spellings to the
// snake_case names documented in court-evidence.md §3 (e.g.
// `--circuit document_existence`). Without this clap defaults to
// kebab-case and `--circuit document_existence` would reject.
#[derive(Clone, Copy, ValueEnum)]
#[value(rename_all = "snake_case")]
enum Circuit {
    DocumentExistence,
    NonExistence,
    // `redaction_validity` was removed by ADR-0030 §4 (the Groth16 redaction
    // circuit was replaced by the signed-Merkle fold; see
    // `verifiers/rust/src/redaction.rs`), so there is no arm for it here.
    // `rename_all = "snake_case"` would map this to `unified`, but the
    // canonical circuit name `as_str()` returns is the full
    // `unified_canonicalization_inclusion_root_sign`. Override here so
    // CLI and `as_str()` stay in lockstep (court-evidence audit trail
    // expects the full canonical name everywhere).
    #[value(name = "unified_canonicalization_inclusion_root_sign")]
    Unified,
}

impl Circuit {
    fn as_str(self) -> &'static str {
        match self {
            Circuit::DocumentExistence => "document_existence",
            Circuit::NonExistence => "non_existence",
            Circuit::Unified => "unified_canonicalization_inclusion_root_sign",
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Verify(args) => run_verify(args),
    }
}

fn run_verify(args: VerifyArgs) -> ExitCode {
    // Read the vkey bytes ourselves so we can publish a BLAKE3 digest
    // alongside the human-readable accept/reject line. `--circuit` is
    // a cosmetic label; the cryptographic authority is the vkey file,
    // and surfacing its identifying hash lets a court / opposing
    // counsel pin "verified with THIS vkey" without trusting the
    // operator's choice of circuit name.
    let vkey_bytes = match std::fs::read(&args.vkey) {
        Ok(b) => b,
        Err(e) => {
            eprintln!(
                "ERROR: failed to load vkey from {}: {e}",
                args.vkey.display()
            );
            return ExitCode::from(2);
        }
    };
    let vkey_blake3 = blake3::hash(&vkey_bytes).to_hex().to_string();
    let vkey_str = match std::str::from_utf8(&vkey_bytes) {
        Ok(s) => s,
        Err(e) => {
            eprintln!(
                "ERROR: vkey {} is not valid UTF-8: {e}",
                args.vkey.display()
            );
            return ExitCode::from(2);
        }
    };
    let vk = match groth16::parse_vkey_json(vkey_str) {
        Ok(v) => v,
        Err(e) => return fail_parse("vkey", &args.vkey, &e),
    };
    let proof = match groth16::load_proof(&args.proof) {
        Ok(p) => p,
        Err(e) => return fail_parse("proof", &args.proof, &e),
    };
    let signals = match groth16::load_public_signals(&args.public_signals) {
        Ok(s) => s,
        Err(e) => return fail_parse("public-signals", &args.public_signals, &e),
    };

    match groth16::verify(&vk, &proof, &signals) {
        Ok(()) => {
            println!(
                "OK: Groth16 proof accepted for circuit `{}` ({} public signals)\n     vkey:        {}\n     vkey blake3: {}",
                args.circuit.as_str(),
                signals.len(),
                args.vkey.display(),
                vkey_blake3,
            );
            ExitCode::SUCCESS
        }
        Err(VerifyError::Rejected) => {
            eprintln!(
                "REJECT: Groth16 pairing check failed for circuit `{}`\n     vkey:        {}\n     vkey blake3: {}",
                args.circuit.as_str(),
                args.vkey.display(),
                vkey_blake3,
            );
            ExitCode::from(1)
        }
        Err(e) => {
            eprintln!("ERROR: verify failed: {e}");
            ExitCode::from(2)
        }
    }
}

fn fail_parse(label: &str, path: &PathBuf, e: &VerifyError) -> ExitCode {
    eprintln!("ERROR: failed to load {label} from {}: {e}", path.display());
    ExitCode::from(2)
}
