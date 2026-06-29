//! Convert a snarkjs `.zkey` file to an arkworks-serialized `.ark.zkey`.
//!
//! Run once at setup time, after `snarkjs zkey contribute`. The output is what
//! `zk::zkey::load_proving_key` expects at runtime — letting the Tauri binary
//! avoid the slow snarkjs `.zkey` parser on every prove call (and removing the
//! need for `node` to be installed on the user's machine).
//!
//! Usage:  export_ark_zkey <input.zkey> <output.ark.zkey>
//!
//! Exit codes:
//!   0  success
//!   1  argument error
//!   2  read/parse error on input .zkey
//!   3  serialize/write error on output .ark.zkey

use std::fs::File;
use std::io::{BufReader, BufWriter};
use std::path::PathBuf;
use std::process::ExitCode;

use ark_circom::read_zkey;
use ark_serialize::CanonicalSerialize;

fn main() -> ExitCode {
    let args: Vec<_> = std::env::args_os().collect(); // nosemgrep: rust.lang.security.args-os.args-os
    if args.len() != 3 {
        eprintln!("usage: export_ark_zkey <input.zkey> <output.ark.zkey>");
        return ExitCode::from(1);
    }
    let input: PathBuf = PathBuf::from(args[1].clone());
    let output: PathBuf = PathBuf::from(args[2].clone());

    // Parse snarkjs .zkey. `read_zkey` returns (ProvingKey, ConstraintMatrices);
    // we only need the proving key — the constraint matrices are reconstructed
    // at prove time from the `.r1cs` file via ark-circom.
    let file = match File::open(&input) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("error: opening {}: {e}", input.display());
            return ExitCode::from(2);
        }
    };
    let mut reader = BufReader::new(file);
    let (pk, _matrices) = match read_zkey(&mut reader) {
        Ok(parsed) => parsed,
        Err(e) => {
            eprintln!("error: parsing snarkjs .zkey at {}: {e}", input.display());
            return ExitCode::from(2);
        }
    };

    // Serialize uncompressed: faster to read back, larger on disk. Build
    // artifacts aren't space-constrained for our deployment, and `load_proving_key`
    // calls `deserialize_uncompressed_unchecked` to skip subgroup checks during
    // load — that path requires the uncompressed encoding.
    let out_file = match File::create(&output) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("error: creating {}: {e}", output.display());
            return ExitCode::from(3);
        }
    };
    let mut writer = BufWriter::new(out_file);
    if let Err(e) = pk.serialize_uncompressed(&mut writer) {
        eprintln!("error: serializing ProvingKey to {}: {e}", output.display());
        return ExitCode::from(3);
    }

    println!("Converted {} -> {}", input.display(), output.display());
    ExitCode::from(0)
}
