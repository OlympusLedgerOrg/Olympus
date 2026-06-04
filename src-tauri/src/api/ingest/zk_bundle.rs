//! `GET /ingest/records/hash/{hash}/zk_bundle` — lazy Groth16 existence-proof
//! issuance with a cached result. Split out of the ingest module.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};

use super::*;
use crate::api::middleware::auth::{AuthenticatedKey, RateLimit};
use crate::state::AppState;

// ── Route: GET /ingest/records/hash/{hash}/zk_bundle ─────────────────────────
//
// Lazy ZK existence-proof issuance.  Returns the Groth16 proof bundle for a
// committed record, generating it on the first request and caching the
// result back to `ingest_records.zk_bundle` so subsequent requests are
// instant.  Requires the snapshot columns added by migration 0029 — older
// records (or JSON-record commits) without `snapshot_root` return 503.
//
// Auth: `verify`, `read`, or `admin` scope, same gate as `/zk/verify`.
// Since the API key is BLAKE3-derived from the BJJ private key (PR #945),
// "holder of API key" == "holder of BJJ private key" — the natural
// re-download path for the original committer.

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ZkBundleResponse {
    circuit: String,
    proof_json: serde_json::Value,
    public_signals: Vec<String>,
    content_hash: String,
    original_root: String,
    snapshot_root: String,
    snapshot_index: i64,
    snapshot_size: i64,
    snapshot_sig: String,
}

#[derive(sqlx::FromRow)]
struct ZkBundleRow {
    proof_id: String,
    content_hash: String,
    original_root: Option<String>,
    snapshot_root: Option<String>,
    snapshot_index: Option<i64>,
    snapshot_size: Option<i64>,
    snapshot_path: Option<serde_json::Value>,
    snapshot_sig: Option<String>,
    zk_bundle: Option<serde_json::Value>,
}

pub(super) async fn issue_zk_bundle(
    State(state): State<AppState>,
    auth: AuthenticatedKey,
    _rl: RateLimit,
    Path(hash): Path<String>,
) -> Result<Json<ZkBundleResponse>, ApiError> {
    if !auth.has_scope("verify") && !auth.has_scope("read") && !auth.has_scope("admin") {
        return Err(err(
            StatusCode::FORBIDDEN,
            "API key lacks required scope: one of 'verify', 'read', or 'admin'",
        ));
    }

    let hash = hash.trim().to_lowercase();
    if hash.len() != 64 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(err(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Hash must be a 64-character hex string.",
        ));
    }

    let pool = state
        .pool
        .as_ref()
        .ok_or_else(|| err(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable."))?;

    let row: ZkBundleRow = sqlx::query_as::<_, ZkBundleRow>(
        // Audit A1: earliest-wins — content_hash is per-shard unique only.
        "SELECT proof_id, content_hash, original_root, snapshot_root, snapshot_index, \
                snapshot_size, snapshot_path, snapshot_sig, zk_bundle \
         FROM ingest_records WHERE content_hash = $1 \
         ORDER BY ts ASC, proof_id ASC LIMIT 1",
    )
    .bind(&hash)
    .fetch_optional(pool)
    .await
    .map_err(db_err)?
    .ok_or_else(|| err(StatusCode::NOT_FOUND, "Hash not found in ledger."))?;

    // Cache hit: return the previously-generated bundle verbatim.
    if let Some(cached) = row.zk_bundle.as_ref() {
        if let Ok(resp) = serde_json::from_value::<ZkBundleResponse>(cached.clone()) {
            return Ok(Json(resp));
        }
        // Fall through and regenerate if the cached blob is malformed.
        tracing::warn!("zk_bundle cache for {hash} is malformed; regenerating");
    }

    // Snapshot must be populated to generate a proof. After the atomic-ingest
    // refactor, every new commit through /ingest/files writes the snapshot in
    // the same transaction as the row INSERT — so a NULL `original_root` can
    // only mean a legacy row predating migration 0029 (or the removed
    // /ingest/records JSON path under audit H-5). Those rows aren't
    // re-snapshottable without their original bytes, which the server does
    // not retain; the only remedy is to re-upload the file through
    // /ingest/files, which will dedupe by content_hash and back-fill the
    // snapshot columns on insert.
    let original_root = row.original_root.ok_or_else(|| {
        err(
            StatusCode::SERVICE_UNAVAILABLE,
            "Record has no Poseidon snapshot — legacy row (pre-migration-0029 or \
             pre-audit-H-5 JSON commit). Re-upload the original bytes through \
             /ingest/files to back-fill the snapshot.",
        )
    })?;
    let snapshot_root = row.snapshot_root.ok_or_else(|| {
        err(
            StatusCode::SERVICE_UNAVAILABLE,
            "Record is missing snapshot_root.",
        )
    })?;
    let snapshot_index = row.snapshot_index.ok_or_else(|| {
        err(
            StatusCode::SERVICE_UNAVAILABLE,
            "Record is missing snapshot_index.",
        )
    })?;
    let snapshot_size = row.snapshot_size.ok_or_else(|| {
        err(
            StatusCode::SERVICE_UNAVAILABLE,
            "Record is missing snapshot_size.",
        )
    })?;
    let snapshot_path = row.snapshot_path.ok_or_else(|| {
        err(
            StatusCode::SERVICE_UNAVAILABLE,
            "Record is missing snapshot_path.",
        )
    })?;
    let snapshot_sig = row.snapshot_sig.ok_or_else(|| {
        err(
            StatusCode::SERVICE_UNAVAILABLE,
            "Record is missing snapshot_sig.",
        )
    })?;

    let (proof_json, public_signals) = generate_existence_bundle(
        state.proofs_dir.clone(),
        &original_root,
        &snapshot_root,
        snapshot_index as u64,
        snapshot_size as u64,
        &snapshot_path,
    )
    .await?;

    let response = ZkBundleResponse {
        circuit: "document_existence".to_string(),
        proof_json,
        public_signals,
        content_hash: row.content_hash.clone(),
        original_root,
        snapshot_root,
        snapshot_index,
        snapshot_size,
        snapshot_sig,
    };

    // Cache the generated bundle so subsequent requests are instant.
    // Failure to cache is non-fatal — the bundle is already constructed.
    let cache_value = match serde_json::to_value(&response) {
        Ok(v) => Some(v),
        Err(e) => {
            tracing::warn!("zk_bundle cache serialise: {e}");
            None
        }
    };
    if let Some(v) = cache_value {
        if let Err(e) = sqlx::query("UPDATE ingest_records SET zk_bundle = $1 WHERE proof_id = $2")
            .bind(&v)
            .bind(&row.proof_id)
            .execute(pool)
            .await
        {
            tracing::warn!("zk_bundle cache write: {e}");
        }
    }

    Ok(Json(response))
}

/// Build the `ExistenceWitness` from the stored snapshot, run
/// `prove_existence` on a blocking task, and return the snarkjs-shape
/// proof JSON + decimal public signals.
async fn generate_existence_bundle(
    proofs_dir: Option<std::path::PathBuf>,
    original_root_hex: &str,
    snapshot_root_hex: &str,
    snapshot_index: u64,
    snapshot_size: u64,
    snapshot_path: &serde_json::Value,
) -> Result<(serde_json::Value, Vec<String>), ApiError> {
    use ark_bn254::Fr;
    use ark_ff::PrimeField;

    fn hex_to_fr(h: &str) -> Result<Fr, ApiError> {
        let mut bytes = [0u8; 32];
        let decoded = hex::decode(h).map_err(|e| {
            err(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("hex decode: {e}"),
            )
        })?;
        if decoded.len() > 32 {
            return Err(err(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("hex value too long: {} bytes (max 32)", decoded.len()),
            ));
        }
        let off = 32usize.saturating_sub(decoded.len());
        bytes[off..off + decoded.len()].copy_from_slice(&decoded);
        Ok(Fr::from_be_bytes_mod_order(&bytes))
    }

    let root = hex_to_fr(snapshot_root_hex)?;
    let leaf = hex_to_fr(original_root_hex)?;

    let path_obj = snapshot_path.as_object().ok_or_else(|| {
        err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "snapshot_path is not an object",
        )
    })?;
    let path_elements_arr = path_obj
        .get("path_elements")
        .and_then(|v| v.as_array())
        .ok_or_else(|| {
            err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "snapshot_path.path_elements missing",
            )
        })?;
    let path_indices_arr = path_obj
        .get("path_indices")
        .and_then(|v| v.as_array())
        .ok_or_else(|| {
            err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "snapshot_path.path_indices missing",
            )
        })?;

    let mut path_elements: Vec<Fr> = Vec::with_capacity(path_elements_arr.len());
    for (i, v) in path_elements_arr.iter().enumerate() {
        let s = v.as_str().ok_or_else(|| {
            err(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("path_elements[{}] is not a string", i),
            )
        })?;
        path_elements.push(hex_to_fr(s)?);
    }
    let mut path_indices: Vec<u8> = Vec::with_capacity(path_indices_arr.len());
    for (i, v) in path_indices_arr.iter().enumerate() {
        let n = v.as_u64().ok_or_else(|| {
            err(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("path_indices[{}] is not a number", i),
            )
        })?;
        // Fallible conversion: a value > 255 must surface as an error rather
        // than silently truncating via `as u8` (ExistenceWitness::new further
        // rejects any index > 1, but the truncation would mask the corruption).
        let idx = u8::try_from(n).map_err(|_| {
            err(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("path_indices[{}] value {} exceeds u8 range", i, n),
            )
        })?;
        path_indices.push(idx);
    }

    let witness = crate::zk::witness::ExistenceWitness::new(
        root,
        snapshot_index,
        snapshot_size,
        leaf,
        path_elements,
        path_indices,
    )
    .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &format!("witness: {e}")))?;

    let keys_dir = proofs_dir.unwrap_or_else(|| std::path::PathBuf::from("proofs/keys"));

    #[cfg(feature = "prover")]
    {
        use crate::zk::Circuit;
        let circuit = Circuit::DocumentExistence;
        let wasm = circuit.wasm_path(&keys_dir);
        let r1cs = circuit.r1cs_path(&keys_dir);
        let zkey = circuit.ark_zkey_path(&keys_dir);
        for (label, path) in [("wasm", &wasm), ("r1cs", &r1cs), ("zkey", &zkey)] {
            if !path.exists() {
                return Err(err(
                    StatusCode::SERVICE_UNAVAILABLE,
                    &format!("circuit artifact missing: {label} at {}", path.display()),
                ));
            }
        }

        let (proof, public_signals) = tokio::task::spawn_blocking(move || {
            crate::zk::prove::prove_existence(&witness, &wasm, &r1cs, &zkey)
        })
        .await
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &format!("join: {e}")))?
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &format!("prove: {e}")))?;

        let proof_json = groth16_proof_to_json(&proof);
        let public_signals_dec: Vec<String> = public_signals.iter().map(fr_to_decimal).collect();
        Ok((proof_json, public_signals_dec))
    }
    #[cfg(not(feature = "prover"))]
    {
        let _ = (keys_dir, witness);
        Err(err(
            StatusCode::SERVICE_UNAVAILABLE,
            "ZK prover feature not compiled in this build",
        ))
    }
}

#[cfg(feature = "prover")]
fn fr_to_decimal(f: &ark_bn254::Fr) -> String {
    use ark_ff::{BigInteger, PrimeField};
    let bytes = f.into_bigint().to_bytes_be();
    num_bigint::BigUint::from_bytes_be(&bytes).to_string()
}

#[cfg(feature = "prover")]
fn groth16_proof_to_json(proof: &ark_groth16::Proof<ark_bn254::Bn254>) -> serde_json::Value {
    // Read each coordinate directly from its base-field element. Do NOT slice
    // `serialize_uncompressed` output: arkworks packs point flags (infinity /
    // y-sign) into the spare high bits of each coordinate's most-significant
    // byte, so `from_bytes_le(&buf[32..64])` would yield `y + 2^255`, which
    // exceeds the BN254 base-field modulus and makes every snarkjs/`/zk/verify`
    // consumer reject the proof with a "field element exceeds modulus" parse
    // error. Extracting the `Fq` coordinate and reducing via `into_bigint`
    // produces the canonical, fully-reduced integer.
    fn fq_to_decimal(f: &ark_bn254::Fq) -> String {
        use ark_ff::{BigInteger, PrimeField};
        num_bigint::BigUint::from_bytes_be(&f.into_bigint().to_bytes_be()).to_string()
    }
    fn g1(p: &ark_bn254::G1Affine) -> Vec<String> {
        vec![fq_to_decimal(&p.x), fq_to_decimal(&p.y), "1".into()]
    }
    fn g2(p: &ark_bn254::G2Affine) -> Vec<Vec<String>> {
        vec![
            vec![fq_to_decimal(&p.x.c0), fq_to_decimal(&p.x.c1)],
            vec![fq_to_decimal(&p.y.c0), fq_to_decimal(&p.y.c1)],
            vec!["1".into(), "0".into()],
        ]
    }
    serde_json::json!({
        "pi_a": g1(&proof.a),
        "pi_b": g2(&proof.b),
        "pi_c": g1(&proof.c),
        "protocol": "groth16",
        "curve": "bn128",
    })
}
