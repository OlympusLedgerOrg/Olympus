// SPDX-License-Identifier: Apache-2.0

use std::{
    env, fs,
    panic::{catch_unwind, AssertUnwindSafe},
    path::{Path, PathBuf},
};

use anyhow::{bail, ensure, Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use olympus_crypto::{
    canonical::canonicalize_bytes,
    canonical_proof::{
        canonicalization_claim, MAX_CANONICALIZATION_USER_CYCLES, MAX_CANONICAL_RECEIPT_BYTES,
        MAX_CANONICAL_SOURCE_BYTES,
    },
};
use risc0_zkvm::{
    compute_image_id, ExecutorEnv, ExecutorImpl, InnerReceipt, LocalProver, Prover as _,
    ProverOpts, VerifierContext,
};
use serde::Serialize;

const FIXTURE_SOURCE: &[u8] = br#"{ "z":1.2300e+3, "name":"e\u0301", "a":true }"#;

fn main() -> Result<()> {
    reject_development_mode()?;

    let mut args = env::args_os();
    let program = args.next().unwrap_or_default();
    let command = args
        .next()
        .context("expected `measure` or `fixture` command")?;
    let elf_path = PathBuf::from(args.next().context("expected guest ELF path")?);
    let image_id_path = PathBuf::from(args.next().context("expected guest image-ID path")?);
    let output_path = PathBuf::from(args.next().context("expected output JSON path")?);
    let extra = args.next();
    ensure!(
        args.next().is_none(),
        "too many arguments; usage: {} <measure|fixture> <elf> <image-id> <output-json> [measure-cycle-limit]",
        PathBuf::from(program).display()
    );

    let guest = load_guest(&elf_path, &image_id_path)?;
    match command.to_string_lossy().as_ref() {
        "measure" => {
            let cycle_limit = extra
                .map(|value| {
                    value
                        .to_string_lossy()
                        .parse::<u64>()
                        .context("measure-cycle-limit must be a positive u64")
                })
                .transpose()?
                .unwrap_or(MAX_CANONICALIZATION_USER_CYCLES);
            ensure!(cycle_limit > 0, "measure-cycle-limit must be positive");
            measure(&guest, &output_path, cycle_limit)
        }
        "fixture" => {
            ensure!(extra.is_none(), "fixture does not accept extra arguments");
            fixture(&guest, &output_path)
        }
        other => bail!("unknown command {other:?}; expected `measure` or `fixture`"),
    }
}

struct Guest {
    elf: Vec<u8>,
    image_id: risc0_zkvm::sha::Digest,
    image_id_hex: String,
}

fn load_guest(elf_path: &Path, image_id_path: &Path) -> Result<Guest> {
    let elf = fs::read(elf_path)
        .with_context(|| format!("failed to read guest ELF {}", elf_path.display()))?;
    ensure!(
        !elf.starts_with(b"PLACEHOLDER"),
        "guest ELF is a placeholder"
    );

    let pinned = fs::read_to_string(image_id_path)
        .with_context(|| format!("failed to read image ID {}", image_id_path.display()))?;
    let pinned = pinned.strip_suffix('\n').unwrap_or(&pinned);
    ensure!(
        pinned.len() == 64
            && pinned
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "image ID must contain exactly 64 lowercase hexadecimal characters and one optional newline"
    );
    let image_id = compute_image_id(&elf).context("failed to compute guest image ID")?;
    ensure!(
        image_id.to_string() == pinned,
        "guest ELF image ID does not match the pinned ID"
    );
    Ok(Guest {
        elf,
        image_id,
        image_id_hex: pinned.to_owned(),
    })
}

#[derive(Serialize)]
struct MeasurementReport {
    format: &'static str,
    version: u32,
    image_id: String,
    per_case_user_cycle_limit: u64,
    cases: Vec<MeasurementCase>,
}

#[derive(Serialize)]
struct MeasurementCase {
    name: &'static str,
    source_bytes: usize,
    canonical_bytes: usize,
    status: &'static str,
    user_cycles: Option<u64>,
    paging_cycles: Option<u64>,
    reserved_cycles: Option<u64>,
    total_cycles: Option<u64>,
    error: Option<String>,
}

fn measure(guest: &Guest, output_path: &Path, cycle_limit: u64) -> Result<()> {
    let mut report = MeasurementReport {
        format: "olympus-canonicalization-cycle-report",
        version: 1,
        image_id: guest.image_id_hex.clone(),
        per_case_user_cycle_limit: cycle_limit,
        cases: Vec::new(),
    };
    write_json(output_path, &report)?;

    let mut failures = 0usize;
    for (name, source) in measurement_sources() {
        let canonical = canonicalize_bytes(&source)
            .with_context(|| format!("host canonicalizer rejected deterministic case {name}"))?;
        let expected_journal = canonicalization_claim(&source)
            .with_context(|| format!("failed to derive host claim for {name}"))?
            .encode();
        let mut record = MeasurementCase {
            name,
            source_bytes: source.len(),
            canonical_bytes: canonical.len(),
            status: "error",
            user_cycles: None,
            paging_cycles: None,
            reserved_cycles: None,
            total_cycles: None,
            error: None,
        };

        let execution = catch_unwind(AssertUnwindSafe(|| {
            let mut builder = ExecutorEnv::builder();
            builder
                .write(&source.to_vec())?
                .session_limit(Some(cycle_limit));
            let env = builder.build()?;
            ExecutorImpl::from_elf(env, &guest.elf)?.run()
        }));
        match execution {
            Ok(Ok(session)) => {
                record.user_cycles = Some(session.user_cycles);
                record.paging_cycles = Some(session.paging_cycles);
                record.reserved_cycles = Some(session.reserved_cycles);
                record.total_cycles = Some(session.total_cycles);
                let actual_journal = session
                    .journal
                    .as_ref()
                    .map(|journal| journal.bytes.as_slice());
                if actual_journal == Some(expected_journal.as_slice()) {
                    record.status = "ok";
                } else {
                    failures += 1;
                    record.error = Some(format!(
                        "guest did not halt with the expected journal (exit code: {:?})",
                        session.exit_code
                    ));
                }
            }
            Ok(Err(error)) => {
                failures += 1;
                record.error = Some(error.to_string());
            }
            Err(payload) => {
                failures += 1;
                record.error = Some(format!("executor panicked: {}", panic_message(payload)));
            }
        }
        report.cases.push(record);
        // Persist after every independently bounded case so a later failure
        // cannot discard successful measurements.
        write_json(output_path, &report)?;
    }

    if failures != 0 {
        bail!("{failures} measurement case(s) failed; partial report was preserved")
    }
    Ok(())
}

fn measurement_sources() -> Vec<(&'static str, Vec<u8>)> {
    let max = MAX_CANONICAL_SOURCE_BYTES;
    vec![
        ("representative-object", FIXTURE_SOURCE.to_vec()),
        ("max-wide-object-reverse-keys", wide_object(max)),
        ("max-flat-array", flat_array(max)),
        ("max-ascii-string", quoted_repetition(b"a", max)),
        ("max-combining-unicode-string", combining_string(max)),
        ("depth-64-max-string", nested_string(max, 64)),
        (
            "max-escaped-control-string",
            quoted_repetition(br"\u0000", max),
        ),
        ("max-decimal-literal", max_decimal(max)),
    ]
}

fn wide_object(max: usize) -> Vec<u8> {
    // Each fixed-width entry is 13 bytes plus one comma, except the first.
    let count = (max - 1) / 14;
    let mut out = String::with_capacity(count * 14 + 1);
    out.push('{');
    for index in (0..count).rev() {
        if out.len() != 1 {
            out.push(',');
        }
        out.push_str(&format!(r#""k{index:08}":0"#));
    }
    out.push('}');
    debug_assert!(out.len() <= max);
    out.into_bytes()
}

fn flat_array(max: usize) -> Vec<u8> {
    let count = (max - 1) / 2;
    let mut out = Vec::with_capacity(count * 2 + 1);
    out.push(b'[');
    for index in 0..count {
        if index != 0 {
            out.push(b',');
        }
        out.push(b'0');
    }
    out.push(b']');
    debug_assert!(out.len() <= max);
    out
}

fn quoted_repetition(unit: &[u8], max: usize) -> Vec<u8> {
    let count = (max - 2) / unit.len();
    let mut out = Vec::with_capacity(count * unit.len() + 2);
    out.push(b'"');
    for _ in 0..count {
        out.extend_from_slice(unit);
    }
    out.push(b'"');
    debug_assert!(out.len() <= max);
    out
}

fn combining_string(max: usize) -> Vec<u8> {
    quoted_repetition("e\u{0301}".as_bytes(), max)
}

fn nested_string(max: usize, depth: usize) -> Vec<u8> {
    let payload_len = max - (depth * 2) - 2;
    let mut out = Vec::with_capacity(max);
    out.extend(std::iter::repeat_n(b'[', depth));
    out.push(b'"');
    out.extend(std::iter::repeat_n(b'a', payload_len));
    out.push(b'"');
    out.extend(std::iter::repeat_n(b']', depth));
    debug_assert_eq!(out.len(), max);
    out
}

fn max_decimal(max: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(max);
    out.push(b'1');
    out.extend(std::iter::repeat_n(b'0', max - 1));
    out
}

#[derive(Serialize)]
struct ReceiptFixture {
    format: &'static str,
    version: u32,
    image_id: String,
    source_hex: String,
    journal_hex: String,
    receipt: String,
}

fn fixture(guest: &Guest, output_path: &Path) -> Result<()> {
    let source = FIXTURE_SOURCE.to_vec();
    let expected_journal = canonicalization_claim(&source)?.encode();
    let mut builder = ExecutorEnv::builder();
    builder
        .write(&source.to_vec())?
        .session_limit(Some(MAX_CANONICALIZATION_USER_CYCLES));
    let env = builder.build()?;
    let opts = catch_unwind(ProverOpts::succinct).map_err(|_| {
        anyhow::anyhow!("RISC0_DEV_MODE must be unset when disable-dev-mode is enabled")
    })?;
    let receipt = LocalProver::new("olympus-canonicalization-fixture")
        .prove_with_ctx(env, &strict_verifier_context(), &guest.elf, &opts)
        .context("failed to generate succinct receipt")?
        .receipt;
    ensure!(
        matches!(&receipt.inner, InnerReceipt::Succinct(_)),
        "local prover returned a non-succinct receipt"
    );
    ensure!(
        receipt.journal.bytes.as_slice() == expected_journal.as_slice(),
        "receipt journal does not match the host canonicalization claim"
    );
    receipt
        .verify_with_context(&strict_verifier_context(), guest.image_id)
        .context("generated receipt did not verify against the pinned image ID")?;

    let receipt_json = serde_json::to_vec(&receipt)?;
    ensure!(
        receipt_json.len() <= MAX_CANONICAL_RECEIPT_BYTES,
        "serialized receipt exceeds the Olympus 16 MiB verifier limit"
    );
    write_json(
        output_path,
        &ReceiptFixture {
            format: "olympus-canonicalization-receipt-fixture",
            version: 1,
            image_id: guest.image_id_hex.clone(),
            source_hex: hex::encode(source),
            journal_hex: hex::encode(expected_journal),
            receipt: BASE64.encode(receipt_json),
        },
    )
}

fn strict_verifier_context() -> VerifierContext {
    VerifierContext::empty()
        .with_suites(VerifierContext::default_hash_suites())
        .with_segment_verifier_parameters(Default::default())
        .with_succinct_verifier_parameters(Default::default())
        .with_groth16_verifier_parameters(Default::default())
}

fn reject_development_mode() -> Result<()> {
    if env::var("RISC0_DEV_MODE")
        .ok()
        .is_some_and(|value| matches!(value.to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
    {
        bail!("RISC0_DEV_MODE must be unset when disable-dev-mode is enabled")
    }
    Ok(())
}

fn write_json(path: &Path, value: &impl Serialize) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create output directory {}", parent.display()))?;
    }
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    fs::write(path, bytes).with_context(|| format!("failed to write {}", path.display()))
}

fn panic_message(payload: Box<dyn std::any::Any + Send>) -> String {
    if let Some(message) = payload.downcast_ref::<&str>() {
        (*message).to_owned()
    } else if let Some(message) = payload.downcast_ref::<String>() {
        message.clone()
    } else {
        "non-string panic payload".to_owned()
    }
}
