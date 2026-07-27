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

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};

use olympus_verifier::canonicalization::{self, CanonicalizationError};
use olympus_verifier::empty_root;
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
    /// Verify a RISC Zero canonicalization receipt bound to a unified Groth16 proof.
    VerifyCanonicalization(VerifyCanonicalizationArgs),
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

#[derive(Parser)]
struct VerifyCanonicalizationArgs {
    /// Path to the historical unified-circuit snarkjs verification-key JSON.
    #[arg(long)]
    vkey: PathBuf,

    /// Path to the snarkjs proof JSON (pi_a / pi_b / pi_c).
    #[arg(long)]
    proof: PathBuf,

    /// Path to exactly five public signals in unified-circuit order.
    #[arg(long = "public-signals")]
    public_signals: PathBuf,

    /// Path containing canonical base64(JSON(RISC Zero Receipt)) with no whitespace.
    #[arg(long = "canonicalization-receipt-file")]
    canonicalization_receipt_file: PathBuf,

    /// Expected source commitment as exactly 64 lowercase hexadecimal characters.
    #[arg(long = "source-commitment")]
    source_commitment: String,
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
    // The honest logical name describes the live R1CS. The misleading
    // historical public identifier is retired rather than accepted as an
    // alias: raw Groth16 verification proves neither canonicalization nor a
    // signature.
    #[value(name = "unified_section_commitment_inclusion_root")]
    UnifiedSectionCommitment,
}

impl Circuit {
    fn as_str(self) -> &'static str {
        match self {
            Circuit::DocumentExistence => "document_existence",
            Circuit::NonExistence => "non_existence",
            Circuit::UnifiedSectionCommitment => "unified_section_commitment_inclusion_root",
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Verify(args) => run_verify(args),
        Cmd::VerifyCanonicalization(args) => run_verify_canonicalization(args),
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
            // A valid pairing is NOT sufficient. Both the document-existence
            // and unified circuits switch off their `leafIndex < treeSize`
            // bounds check when `treeSize == 0`, delegating it to the
            // verifier: an honest proof over a privately built tree can
            // otherwise be replayed as `[arbitrary_root, leafIndex, 0]`
            // (audit H-2 / OLY-H3). `--circuit` is a cosmetic label
            // everywhere else in this binary, but it is what identifies the
            // public-signal layout, so the invariant is keyed off it here.
            if let Err(error) =
                empty_root::enforce_empty_tree_invariant(args.circuit.as_str(), &signals)
            {
                eprintln!(
                    "REJECT: {error}\n     circuit:     {}\n     vkey:        {}\n     vkey blake3: {}",
                    args.circuit.as_str(),
                    args.vkey.display(),
                    vkey_blake3,
                );
                return ExitCode::from(1);
            }
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

fn run_verify_canonicalization(args: VerifyCanonicalizationArgs) -> ExitCode {
    let signals = match groth16::load_public_signals(&args.public_signals) {
        Ok(signals) => signals,
        Err(error) => return fail_parse("public-signals", &args.public_signals, &error),
    };
    let encoded_receipt = match read_bounded_utf8(
        &args.canonicalization_receipt_file,
        canonicalization::MAX_RECEIPT_BASE64_BYTES,
    ) {
        Ok(receipt) => receipt,
        Err(error) => {
            eprintln!(
                "ERROR: failed to load canonicalization receipt from {}: {error}",
                args.canonicalization_receipt_file.display()
            );
            return ExitCode::from(2);
        }
    };
    let canonicalization = match canonicalization::verify_receipt_binding(
        &encoded_receipt,
        &args.source_commitment,
        &signals,
    ) {
        Ok(verified) => verified,
        Err(error) if error.is_rejection() => {
            eprintln!("REJECT: canonicalization receipt binding failed: {error}");
            return ExitCode::from(1);
        }
        Err(error) => return fail_canonicalization(error),
    };

    // Only parse and verify the Groth16 artifacts after the authenticated
    // receipt has been bound to the exact public-signal vector.
    let vkey_bytes = match std::fs::read(&args.vkey) {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!(
                "ERROR: failed to load vkey from {}: {error}",
                args.vkey.display()
            );
            return ExitCode::from(2);
        }
    };
    let vkey_blake3 = blake3::hash(&vkey_bytes).to_hex().to_string();
    let vkey_str = match std::str::from_utf8(&vkey_bytes) {
        Ok(value) => value,
        Err(error) => {
            eprintln!(
                "ERROR: vkey {} is not valid UTF-8: {error}",
                args.vkey.display()
            );
            return ExitCode::from(2);
        }
    };
    let vkey = match groth16::parse_vkey_json(vkey_str) {
        Ok(vkey) => vkey,
        Err(error) => return fail_parse("vkey", &args.vkey, &error),
    };
    let proof = match groth16::load_proof(&args.proof) {
        Ok(proof) => proof,
        Err(error) => return fail_parse("proof", &args.proof, &error),
    };

    match groth16::verify(&vkey, &proof, &signals) {
        Ok(()) => {
            println!(
                "OK: canonicalization receipt and unified Groth16 proof accepted \
                 (5 public signals)\n     guest image id:   {}\n     source commitment: {}\n     \
                 vkey:             {}\n     vkey blake3:      {}",
                canonicalization.image_id,
                hex::encode(canonicalization.source_commitment),
                args.vkey.display(),
                vkey_blake3,
            );
            ExitCode::SUCCESS
        }
        Err(VerifyError::Rejected) => {
            eprintln!(
                "REJECT: Groth16 pairing check failed after canonicalization receipt acceptance\n     \
                 guest image id: {}\n     vkey:           {}\n     vkey blake3:    {}",
                canonicalization.image_id,
                args.vkey.display(),
                vkey_blake3,
            );
            ExitCode::from(1)
        }
        Err(error) => {
            eprintln!("ERROR: Groth16 verify failed: {error}");
            ExitCode::from(2)
        }
    }
}

fn read_bounded_utf8(path: &Path, max_bytes: usize) -> Result<String, String> {
    let file = std::fs::File::open(path).map_err(|error| error.to_string())?;
    let mut bytes = Vec::new();
    file.take((max_bytes + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() > max_bytes {
        return Err(format!("file exceeds the {max_bytes}-byte encoded limit"));
    }
    String::from_utf8(bytes).map_err(|error| format!("receipt is not UTF-8: {error}"))
}

fn fail_canonicalization(error: CanonicalizationError) -> ExitCode {
    eprintln!("ERROR: canonicalization receipt is malformed or unavailable: {error}");
    ExitCode::from(2)
}

fn fail_parse(label: &str, path: &PathBuf, e: &VerifyError) -> ExitCode {
    eprintln!("ERROR: failed to load {label} from {}: {e}", path.display());
    ExitCode::from(2)
}
