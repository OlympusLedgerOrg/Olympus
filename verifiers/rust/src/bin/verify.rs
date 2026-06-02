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

#[derive(Clone, Copy, ValueEnum)]
enum Circuit {
    DocumentExistence,
    NonExistence,
    RedactionValidity,
    Unified,
}

impl Circuit {
    fn as_str(self) -> &'static str {
        match self {
            Circuit::DocumentExistence => "document_existence",
            Circuit::NonExistence => "non_existence",
            Circuit::RedactionValidity => "redaction_validity",
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
    let vk = match groth16::load_vkey(&args.vkey) {
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
                "OK: Groth16 proof accepted for circuit `{}` ({} public signals)",
                args.circuit.as_str(),
                signals.len()
            );
            ExitCode::SUCCESS
        }
        Err(VerifyError::Rejected) => {
            eprintln!(
                "REJECT: Groth16 pairing check failed for circuit `{}`",
                args.circuit.as_str()
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
