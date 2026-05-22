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
    /// Secrets that this bootstrap *freshly created* and that the operator
    /// has no other way to recover (the raw API key is only the hash in DB;
    /// the BJJ private key is never persisted). Set only when the
    /// respective secret was generated *this run*; `None` otherwise so the
    /// frontend modal doesn't pop up on every restart.
    ///
    /// Consumed once via the `take_initial_secrets` Tauri command — see
    /// `main.rs`. Always `None` if both secrets were either pre-existing
    /// in the DB or supplied via env vars.
    pub freshly_generated: FreshlyGenerated,
}

/// Bundle of secrets to surface to the operator on first launch.
#[derive(Default)]
pub struct FreshlyGenerated {
    /// Raw `oly_…` admin API key — created if the `system-bootstrap` row
    /// didn't yet exist in `api_keys`.
    pub system_api_key: Option<String>,
    /// 64-char hex BJJ authority private key — created if neither
    /// `OLYMPUS_BJJ_AUTHORITY_KEY` env var nor an `account_signing_keys`
    /// row already provided one.
    pub bjj_authority_key_hex: Option<String>,
}

impl FreshlyGenerated {
    pub fn is_empty(&self) -> bool {
        self.system_api_key.is_none() && self.bjj_authority_key_hex.is_none()
    }
}

pub async fn run(pool: &PgPool) -> Option<BootstrapResult> {
    if let Err(e) = ensure_system_user(pool).await {
        tracing::warn!("bootstrap: system user: {e}");
    }

    // Order matters: the system API key is now DERIVED from the BJJ
    // authority private key (see api/middleware/auth.rs::
    // derive_api_key_from_bjj). So the BJJ key has to be loaded or
    // generated first.
    let bjj = match ensure_bjj_authority(pool).await {
        Ok(result) => Some(result),
        Err(e) => {
            tracing::warn!("bootstrap: BJJ authority: {e}");
            None
        }
    };

    let freshly_minted_api = if let Some(ref b) = bjj {
        match ensure_system_api_key(pool, &b.bjj_authority_key, &b.bjj_authority_pubkey).await {
            Ok(maybe_key) => maybe_key,
            Err(e) => {
                tracing::warn!("bootstrap: system API key: {e}");
                None
            }
        }
    } else {
        // No BJJ key available — we can't derive the API key.
        // Existing rows still authenticate via stored hash, but no
        // new key can be created here. Operators must set
        // OLYMPUS_BJJ_AUTHORITY_KEY to recover.
        None
    };

    if let Some(ref b) = bjj {
        if let Err(e) = ensure_system_sbt(pool, &b.bjj_authority_pubkey).await {
            tracing::warn!("bootstrap: SBT mint: {e}");
        }
    }

    bjj.map(|mut br| {
        // Attach the API key (if freshly minted *this run*) to the same
        // bundle the caller will inspect, so a single state read covers
        // both secrets.
        if let Some(k) = freshly_minted_api {
            br.freshly_generated.system_api_key = Some(k);
        }
        br
    })
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

async fn ensure_system_api_key(
    pool: &PgPool,
    bjj_priv: &[u8; 32],
    bjj_pubkey: &BabyJubJubPubKey,
) -> Result<Option<String>, sqlx::Error> {
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM api_keys WHERE user_id = $1 AND name = 'system-bootstrap')",
    )
    .bind(SYSTEM_USER_ID)
    .fetch_one(pool)
    .await?;

    if exists {
        return Ok(None);
    }
    // v0.9 "one master key" unification: the system API key is now a
    // deterministic derivation of the BJJ authority private key —
    // operators only need to keep the BJJ key safe, the API key can
    // always be re-derived client-side.
    let raw_key = crate::api::middleware::auth::derive_api_key_from_bjj(bjj_priv);
    let key_hash = blake3_key_hash(&raw_key);
    let key_id = Uuid::new_v4().to_string();
    let scopes = serde_json::json!(["read", "write", "admin"]).to_string();
    let pubkey_x = fr_to_decimal(&bjj_pubkey.x);
    let pubkey_y = fr_to_decimal(&bjj_pubkey.y);

    sqlx::query(
        "INSERT INTO api_keys
             (id, user_id, key_hash, name, scopes, created_at,
              bjj_pubkey_x, bjj_pubkey_y)
         VALUES ($1, $2, $3, 'system-bootstrap', $4, NOW(), $5, $6)",
    )
    .bind(&key_id)
    .bind(SYSTEM_USER_ID)
    .bind(&key_hash)
    .bind(&scopes)
    .bind(&pubkey_x)
    .bind(&pubkey_y)
    .execute(pool)
    .await?;
    tracing::info!("bootstrap: system API key created (derived from BJJ key)");
    // Stderr breadcrumb retained for headless / non-Tauri operators who
    // can't see the in-app modal. The Tauri path (main.rs ->
    // FreshlyGenerated.system_api_key) surfaces the same value to the GUI.
    eprintln!("[bootstrap] system API key (will NOT appear in logs): {raw_key}");
    Ok(Some(raw_key))
}

async fn ensure_bjj_authority(pool: &PgPool) -> Result<BootstrapResult, String> {
    // If env var is set, use it directly — never expose it to the GUI
    // surface (operator already has it; surfacing it would broaden the
    // attack surface for no UX gain).
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
        return Ok(BootstrapResult {
            bjj_authority_key: key,
            bjj_authority_pubkey: pubkey,
            freshly_generated: FreshlyGenerated::default(),
        });
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

    Ok(BootstrapResult {
        bjj_authority_key: key,
        bjj_authority_pubkey: pubkey,
        // Freshly-generated this run — surface to the GUI via
        // `take_initial_secrets` so the operator can copy + persist it
        // (set OLYMPUS_BJJ_AUTHORITY_KEY on the next start).
        freshly_generated: FreshlyGenerated {
            system_api_key: None, // attached by run() if applicable
            bjj_authority_key_hex: Some(key_hex),
        },
    })
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
