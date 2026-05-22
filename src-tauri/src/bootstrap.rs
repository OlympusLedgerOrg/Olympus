//! First-boot bootstrap: ensures a system user, API key, BJJ authority key,
//! and SBT credential exist so the app is functional out of the box.

use sqlx::PgPool;
use uuid::Uuid;

use crate::api::middleware::auth::blake3_key_hash;
use crate::zk::witness::baby_jubjub::BabyJubJubPubKey;

const SYSTEM_USER_ID: &str = "00000000-0000-0000-0000-000000000001";
const SYSTEM_EMAIL: &str = "system@olympus.local";

pub struct BootstrapResult {
    pub bjj_authority_key: [u8; 32],
    pub bjj_authority_pubkey: BabyJubJubPubKey,
}

pub async fn run(pool: &PgPool) -> Option<BootstrapResult> {
    if let Err(e) = ensure_system_user(pool).await {
        tracing::warn!("bootstrap: system user: {e}");
    }
    if let Err(e) = ensure_system_api_key(pool).await {
        tracing::warn!("bootstrap: system API key: {e}");
    }

    let bjj = match ensure_bjj_authority(pool).await {
        Ok(result) => Some(result),
        Err(e) => {
            tracing::warn!("bootstrap: BJJ authority: {e}");
            None
        }
    };

    if let Some(ref b) = bjj {
        if let Err(e) = ensure_system_sbt(pool, &b.bjj_authority_pubkey).await {
            tracing::warn!("bootstrap: SBT mint: {e}");
        }
    }

    bjj
}

async fn ensure_system_user(pool: &PgPool) -> Result<(), sqlx::Error> {
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM users WHERE id = $1)",
    )
    .bind(SYSTEM_USER_ID)
    .fetch_one(pool)
    .await?;

    if !exists {
        sqlx::query(
            "INSERT INTO users (id, email, password_hash, role, created_at)
             VALUES ($1, $2, '', 'system', NOW())",
        )
        .bind(SYSTEM_USER_ID)
        .bind(SYSTEM_EMAIL)
        .execute(pool)
        .await?;
        tracing::info!("bootstrap: created system user {SYSTEM_USER_ID}");
    }
    Ok(())
}

async fn ensure_system_api_key(pool: &PgPool) -> Result<(), sqlx::Error> {
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM api_keys WHERE user_id = $1 AND name = 'system-bootstrap')",
    )
    .bind(SYSTEM_USER_ID)
    .fetch_one(pool)
    .await?;

    if !exists {
        let raw_key = format!("oly_{}", Uuid::new_v4().as_simple());
        let key_hash = blake3_key_hash(&raw_key);
        let key_id = Uuid::new_v4().to_string();
        let scopes = serde_json::json!(["read", "write", "admin"]).to_string();

        sqlx::query(
            "INSERT INTO api_keys (id, user_id, key_hash, name, scopes, created_at)
             VALUES ($1, $2, $3, 'system-bootstrap', $4, NOW())",
        )
        .bind(&key_id)
        .bind(SYSTEM_USER_ID)
        .bind(&key_hash)
        .bind(&scopes)
        .execute(pool)
        .await?;
        tracing::info!("bootstrap: system API key created");
        eprintln!("[bootstrap] system API key (will NOT appear in logs): {raw_key}");
    }
    Ok(())
}

async fn ensure_bjj_authority(pool: &PgPool) -> Result<BootstrapResult, String> {
    // If env var is set, use it directly.
    if let Ok(hex_str) = std::env::var("OLYMPUS_BJJ_AUTHORITY_KEY") {
        let bytes = hex::decode(hex_str.trim()).map_err(|e| format!("bad hex: {e}"))?;
        if bytes.len() != 32 {
            return Err(format!("OLYMPUS_BJJ_AUTHORITY_KEY must be 32 bytes, got {}", bytes.len()));
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes);
        let pubkey = BabyJubJubPubKey::from_private(&key)
            .map_err(|e| format!("BJJ key derivation: {e}"))?;
        persist_bjj_pubkey(pool, &pubkey).await;
        tracing::info!("bootstrap: BJJ authority loaded from env");
        return Ok(BootstrapResult { bjj_authority_key: key, bjj_authority_pubkey: pubkey });
    }

    // Check if we already generated one (stored in account_signing_keys).
    let existing: Option<(String, String)> = sqlx::query_as(
        "SELECT bjj_pubkey_x, bjj_pubkey_y FROM account_signing_keys
         WHERE user_id = $1 AND purpose = 'authority' AND revoked_at IS NULL
           AND bjj_pubkey_x IS NOT NULL
         LIMIT 1",
    )
    .bind(SYSTEM_USER_ID)
    .fetch_optional(pool)
    .await
    .map_err(|e| format!("DB error checking BJJ key: {e}"))?;

    if existing.is_some() {
        tracing::info!("bootstrap: BJJ authority pubkey already in DB (private key needed from env for signing)");
        return Err("BJJ pubkey exists in DB but OLYMPUS_BJJ_AUTHORITY_KEY env var is required for signing".into());
    }

    // Dev auto-generate: create a new BJJ keypair.
    let mut key = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut key);

    let pubkey = BabyJubJubPubKey::from_private(&key)
        .map_err(|e| format!("BJJ key derivation: {e}"))?;

    let key_hex = hex::encode(key);
    eprintln!("[bootstrap] generated new BJJ authority key (will NOT appear in logs):");
    eprintln!("[bootstrap]   OLYMPUS_BJJ_AUTHORITY_KEY={key_hex}");
    tracing::warn!("bootstrap: new BJJ authority key generated — set OLYMPUS_BJJ_AUTHORITY_KEY env var to persist");

    // Store the signing key row with BJJ pubkey.
    let key_id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO account_signing_keys
             (key_id, user_id, public_key, label, purpose, created_at, bjj_pubkey_x, bjj_pubkey_y)
         VALUES ($1, $2, '', 'bjj-authority', 'authority', NOW(), $3, $4)",
    )
    .bind(&key_id)
    .bind(SYSTEM_USER_ID)
    .bind(fr_to_decimal(&pubkey.x))
    .bind(fr_to_decimal(&pubkey.y))
    .execute(pool)
    .await
    .map_err(|e| format!("insert signing key: {e}"))?;

    persist_bjj_pubkey(pool, &pubkey).await;

    Ok(BootstrapResult { bjj_authority_key: key, bjj_authority_pubkey: pubkey })
}

async fn persist_bjj_pubkey(pool: &PgPool, pubkey: &BabyJubJubPubKey) {
    let x = fr_to_decimal(&pubkey.x);
    let y = fr_to_decimal(&pubkey.y);

    // Update existing authority row if pubkey columns are null.
    let _ = sqlx::query(
        "UPDATE account_signing_keys
         SET bjj_pubkey_x = $1, bjj_pubkey_y = $2
         WHERE user_id = $3 AND purpose = 'authority' AND bjj_pubkey_x IS NULL",
    )
    .bind(&x)
    .bind(&y)
    .bind(SYSTEM_USER_ID)
    .execute(pool)
    .await;
}

async fn ensure_system_sbt(pool: &PgPool, bjj_pubkey: &BabyJubJubPubKey) -> Result<(), sqlx::Error> {
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM key_credentials
         WHERE issuer = 'olympus:system' AND credential_type = 'authority_sbt'
           AND sbt_nontransferable = true AND revoked_at IS NULL)",
    )
    .fetch_one(pool)
    .await?;

    if exists {
        tracing::info!("bootstrap: authority SBT already exists");
        return Ok(());
    }

    let cred_id = Uuid::new_v4().to_string();
    let holder_key = format!(
        "bjj:{}:{}",
        fr_to_decimal(&bjj_pubkey.x),
        fr_to_decimal(&bjj_pubkey.y),
    );
    let commit_id = format!("bootstrap:{}", Uuid::new_v4().as_simple());

    sqlx::query(
        "INSERT INTO key_credentials
             (id, holder_key, credential_type, issued_at, issuer, sbt_nontransferable, commit_id)
         VALUES ($1, $2, 'authority_sbt', NOW(), 'olympus:system', true, $3)",
    )
    .bind(&cred_id)
    .bind(&holder_key)
    .bind(&commit_id)
    .execute(pool)
    .await?;

    tracing::info!("bootstrap: minted authority SBT {cred_id} with BJJ pubkey");
    Ok(())
}

fn fr_to_decimal(f: &ark_bn254::Fr) -> String {
    use ark_ff::{BigInteger, PrimeField};
    let bytes = f.into_bigint().to_bytes_be();
    num_bigint::BigUint::from_bytes_be(&bytes).to_string()
}
