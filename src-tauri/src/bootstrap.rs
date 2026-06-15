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
        if let Err(e) = ensure_system_sbt(pool, &b.bjj_authority_key, &b.bjj_authority_pubkey).await
        {
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
    let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE id = $1)")
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
    // v0.9 "one master key" unification: the system API key is now a
    // deterministic derivation of the BJJ authority private key —
    // operators only need to keep the BJJ key safe, the API key can
    // always be re-derived client-side.
    let raw_key = crate::api::middleware::auth::derive_api_key_from_bjj(bjj_priv);
    let expected_hash = blake3_key_hash(&raw_key);

    let existing: Option<(String, String)> = sqlx::query_as(
        "SELECT id, key_hash FROM api_keys
         WHERE user_id = $1 AND name = 'system-bootstrap'
         LIMIT 1",
    )
    .bind(SYSTEM_USER_ID)
    .fetch_optional(pool)
    .await?;

    if let Some((row_id, stored_hash)) = existing {
        if stored_hash == expected_hash {
            // Healthy — row matches the current derivation. Nothing to do.
            return Ok(None);
        }
        // Self-heal: the stored hash was written under a previous (buggy)
        // `blake3_key_hash` that did NOT strip the `oly_` prefix before
        // hashing, while the frontend's `normalizeApiKey` always strips it
        // before sending. The two hashes could never match and the
        // bootstrap-printed key never authenticated. Update the row in
        // place to the prefix-stripped form so the key the user already
        // copied from the original InitialSecretsModal starts working,
        // and re-surface the value so the modal pops again for anyone
        // who lost the original copy.
        sqlx::query("UPDATE api_keys SET key_hash = $1 WHERE id = $2")
            .bind(&expected_hash)
            .bind(&row_id)
            .execute(pool)
            .await?;
        tracing::warn!(
            "bootstrap: repaired system-bootstrap key_hash (stored hash was under pre-normalization scheme — see api/middleware/auth.rs::blake3_key_hash); InitialSecretsModal will resurface the BJJ-derived API key"
        );
        // Red-team C-1: removed `eprintln!` of `raw_key`. The previous
        // "(will NOT appear in logs)" caveat was wrong on every real
        // operating environment — stderr is captured by systemd-journald
        // (Linux deb/rpm/AppImage), launchd's `StandardErrorPath`, Tauri's
        // own logging plugin, any shell `2>&1`, and CI runners. The
        // InitialSecretsModal (fed via `FreshlyGenerated.system_api_key` in
        // `run()`) is the sanctioned channel.
        return Ok(Some(raw_key));
    }

    // Fresh install path — INSERT the new row.
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
    .bind(&expected_hash)
    .bind(&scopes)
    .bind(&pubkey_x)
    .bind(&pubkey_y)
    .execute(pool)
    .await?;
    tracing::info!("bootstrap: system API key created (derived from BJJ key)");
    // Red-team C-1: removed the stderr breadcrumb of `raw_key`. Olympus
    // ships only as a Tauri GUI binary, so the "headless / non-Tauri
    // operator" caveat the prior comment cited never applies. The Tauri
    // path (`main.rs` -> `FreshlyGenerated.system_api_key` ->
    // `take_initial_secrets` -> InitialSecretsModal) is the sole channel.
    Ok(Some(raw_key))
}

async fn ensure_bjj_authority(pool: &PgPool) -> Result<BootstrapResult, String> {
    // Audit M-7 (BJJ authority key persistence policy — v0.9 decision:
    // env-only): `OLYMPUS_BJJ_AUTHORITY_KEY` is the single persistence
    // surface for the federation/SBT signing identity. The decision
    // documented for v0.9 is env-only — no encrypted-in-DB storage, no
    // KMS integration. Operators are responsible for:
    //   • generating the key on first launch and copying it from the
    //     in-app `InitialSecretsModal` (the sole sanctioned surface —
    //     the stderr breadcrumb described in earlier revisions was
    //     removed under red-team C-1 because it leaked the key to
    //     systemd-journald / launchd / Tauri logging / CI runners);
    //   • storing it in a secret manager (HashiCorp Vault, AWS Secrets
    //     Manager, etc.) or per-host secret file;
    //   • re-providing it via the env var on every subsequent launch.
    // Losing the key is unrecoverable: every SBT and federation
    // checkpoint signed under it stops verifying for relying parties.
    // KMS / hardware-token integration is tracked for a future major.
    //
    // If env var is set, use it directly — never expose it to the GUI
    // surface (operator already has it; surfacing it would broaden the
    // attack surface for no UX gain).
    if let Ok(hex_str) = std::env::var("OLYMPUS_BJJ_AUTHORITY_KEY") {
        let bytes = hex::decode(hex_str.trim()).map_err(|e| format!("bad hex: {e}"))?;
        if bytes.len() != 32 {
            return Err(format!(
                "OLYMPUS_BJJ_AUTHORITY_KEY must be 32 bytes, got {}",
                bytes.len()
            ));
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes);
        let pubkey =
            BabyJubJubPubKey::from_private(&key).map_err(|e| format!("BJJ key derivation: {e}"))?;
        persist_bjj_pubkey(pool, &pubkey).await;
        tracing::info!("bootstrap: BJJ authority loaded from env");
        return Ok(BootstrapResult {
            bjj_authority_key: key,
            bjj_authority_pubkey: pubkey,
            freshly_generated: FreshlyGenerated::default(),
        });
    }

    // OS keychain (phase-B addition): try before the DB fallback so the
    // operator doesn't need OLYMPUS_BJJ_AUTHORITY_KEY on every restart.
    // Highest-priority for desktop installs; silently skipped if the keychain
    // daemon is unavailable (e.g. headless CI).
    match bjj_keychain_get().await {
        Ok(Some(hex_str)) => match hex::decode(hex_str.trim()) {
            Ok(bytes) if bytes.len() == 32 => {
                let mut key = [0u8; 32];
                key.copy_from_slice(&bytes);
                match BabyJubJubPubKey::from_private(&key) {
                    Ok(pubkey) => {
                        persist_bjj_pubkey(pool, &pubkey).await;
                        tracing::info!("bootstrap: BJJ authority loaded from OS keychain");
                        return Ok(BootstrapResult {
                            bjj_authority_key: key,
                            bjj_authority_pubkey: pubkey,
                            freshly_generated: FreshlyGenerated::default(),
                        });
                    }
                    Err(e) => tracing::warn!("bootstrap: keychain BJJ key derivation failed: {e}"),
                }
            }
            _ => tracing::warn!("bootstrap: keychain BJJ key has unexpected format — ignoring"),
        },
        Ok(None) => {} // not yet stored
        Err(e) => tracing::debug!("bootstrap: keychain unavailable: {e}"),
    }

    let is_production = std::env::var("OLYMPUS_ENV")
        .map(|v| v.eq_ignore_ascii_case("production"))
        .unwrap_or(false);

    // Check existing row — and in dev, opportunistically load the persisted
    // secret so restarts don't lose signing capability. Production never
    // reads `bjj_private_dev`; the env var is the only persistence surface.
    let existing: Option<(String, String, Option<Vec<u8>>)> = sqlx::query_as(
        "SELECT bjj_pubkey_x, bjj_pubkey_y, bjj_private_dev FROM account_signing_keys
         WHERE user_id = $1 AND purpose = 'authority' AND revoked_at IS NULL
           AND bjj_pubkey_x IS NOT NULL
         LIMIT 1",
    )
    .bind(SYSTEM_USER_ID)
    .fetch_optional(pool)
    .await
    .map_err(|e| format!("DB error checking BJJ key: {e}"))?;

    if let Some((stored_pubkey_x, stored_pubkey_y, secret_blob)) = &existing {
        if !is_production {
            if let Some(blob) = secret_blob {
                if blob.len() == 32 {
                    let mut key = [0u8; 32];
                    key.copy_from_slice(blob);
                    let derived = BabyJubJubPubKey::from_private(&key).map_err(|e| {
                        format!("BJJ key derivation from persisted dev secret: {e}")
                    })?;
                    // Fail fast if the persisted secret doesn't derive to the
                    // pubkey stored alongside it. Without this check, a row
                    // tampered with after generation would silently switch the
                    // signing authority while the rest of the system kept
                    // verifying against the old pubkey — a hard-to-spot trust
                    // anchor swap. Decimal-string compare matches the format
                    // used by `persist_bjj_pubkey` / `fr_to_decimal`.
                    let derived_x = fr_to_decimal(&derived.x);
                    let derived_y = fr_to_decimal(&derived.y);
                    if &derived_x != stored_pubkey_x || &derived_y != stored_pubkey_y {
                        tracing::error!(
                            "bootstrap: persisted BJJ dev secret derives to a different \
                             pubkey than the one stored in account_signing_keys — refusing \
                             to use it. Manually drop the row or unset bjj_private_dev to \
                             let bootstrap regenerate."
                        );
                        return Err("BJJ dev-secret/pubkey mismatch in account_signing_keys: \
                             derived pubkey does not match the persisted (x, y)."
                            .into());
                    }
                    tracing::info!("bootstrap: BJJ authority loaded from persisted dev secret");
                    return Ok(BootstrapResult {
                        bjj_authority_key: key,
                        bjj_authority_pubkey: derived,
                        freshly_generated: FreshlyGenerated::default(),
                    });
                }
            }
        }
        tracing::info!("bootstrap: BJJ authority pubkey already in DB (private key needed from env for signing)");
        return Err(
            "BJJ pubkey exists in DB but OLYMPUS_BJJ_AUTHORITY_KEY env var is required for signing"
                .into(),
        );
    }

    // Auto-generate a new BJJ keypair. In dev we also persist the secret;
    // in production we only ever surface it to the GUI once.
    let mut key = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut key);

    let pubkey =
        BabyJubJubPubKey::from_private(&key).map_err(|e| format!("BJJ key derivation: {e}"))?;

    let key_hex = hex::encode(key);
    // Red-team C-1: removed the stderr print of the BJJ private key hex.
    // The InitialSecretsModal (`FreshlyGenerated.bjj_authority_key_hex`
    // below) is the GUI surface for this value; in production the operator
    // also sees a `tracing::warn!` instructing them to set
    // `OLYMPUS_BJJ_AUTHORITY_KEY` after copying it from the modal.
    if is_production {
        tracing::warn!("bootstrap: new BJJ authority key generated — set OLYMPUS_BJJ_AUTHORITY_KEY env var to persist");
    } else {
        tracing::info!(
            "bootstrap: new BJJ authority key generated and persisted to dev-mode DB column"
        );
    }

    // Insert authority row. In dev, store the secret so subsequent runs
    // self-bootstrap; in production, leave bjj_private_dev NULL.
    let key_id = Uuid::new_v4().to_string();
    let secret_for_insert: Option<&[u8]> = if is_production { None } else { Some(&key) };
    sqlx::query(
        "INSERT INTO account_signing_keys
             (key_id, user_id, public_key, label, purpose, created_at, bjj_pubkey_x, bjj_pubkey_y, bjj_private_dev)
         VALUES ($1, $2, '', 'bjj-authority', 'authority', NOW(), $3, $4, $5)",
    )
    .bind(&key_id)
    .bind(SYSTEM_USER_ID)
    .bind(fr_to_decimal(&pubkey.x))
    .bind(fr_to_decimal(&pubkey.y))
    .bind(secret_for_insert)
    .execute(pool)
    .await
    .map_err(|e| format!("insert signing key: {e}"))?;

    persist_bjj_pubkey(pool, &pubkey).await;

    // Persist to keychain so the next launch doesn't need to auto-generate
    // again. Failure is non-fatal: the key is still surfaced via the GUI.
    if let Err(e) = bjj_keychain_set(&key_hex).await {
        tracing::warn!("bootstrap: could not save BJJ key to OS keychain: {e}");
    }

    Ok(BootstrapResult {
        bjj_authority_key: key,
        bjj_authority_pubkey: pubkey,
        // Freshly-generated this run — surface to the GUI via
        // `take_initial_secrets` so the operator can copy + persist it.
        // With keychain wired, subsequent restarts load from there instead
        // of re-generating, so the modal only appears once.
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

/// Mint the system authority SBT on first launch (idempotent).
///
/// Audit H-8: previously inserted with NULL signature columns — a
/// DB-tier compromise could insert a forged `authority_sbt` row and
/// instantly gain admin scope via `resolve_sbt_scopes` (audit H-7).
/// Now self-signed with the BJJ authority key: the same commit_id the
/// runtime verifier (`api::credentials::compute_commit_id`) recomputes,
/// signed via `baby_jubjub::sign`. The issuer pubkey is also stored on
/// the row so `resolve_sbt_scopes` can match against the trusted-issuer
/// set at runtime (`olympus:system` → this pubkey).
async fn ensure_system_sbt(
    pool: &PgPool,
    bjj_priv: &[u8; 32],
    bjj_pubkey: &BabyJubJubPubKey,
) -> Result<(), sqlx::Error> {
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

    // Match the credentials.rs runtime contract exactly. We mint with
    // `details = {}` — an empty canonical object — because the authority
    // SBT carries no claims beyond "holder is this BJJ pubkey, type is
    // authority_sbt, issued at this moment." `details = {}` JCS-encodes
    // to `"{}"` deterministically, so the runtime verifier will
    // recompute the same commit_id.
    let details = serde_json::json!({});
    let issued_at = chrono::Utc::now();
    let issued_at_unix = issued_at.timestamp();
    let commit_id_bytes = crate::api::credentials::compute_commit_id(
        &holder_key,
        "authority_sbt",
        issued_at_unix,
        &details,
    );
    let commit_id_hex = hex::encode(commit_id_bytes);

    // Sign the digest with the BJJ authority key. The verifier in
    // `api::middleware::auth::resolve_sbt_scopes` (audit H-7) recomputes
    // commit_id from the row, parses commit_id_hex back to bytes, runs
    // the same `digest_to_fr`, and verifies with this same pubkey.
    let msg = {
        use ark_bn254::Fr;
        use ark_ff::PrimeField;
        Fr::from_le_bytes_mod_order(&commit_id_bytes)
    };
    let sig = crate::zk::witness::baby_jubjub::sign(bjj_priv, msg)
        .map_err(|e| sqlx::Error::Protocol(format!("BJJ sign failed: {e}")))?;

    let issuer_x = fr_to_decimal(&bjj_pubkey.x);
    let issuer_y = fr_to_decimal(&bjj_pubkey.y);
    let sig_r8x = fr_to_decimal(&sig.r8x);
    let sig_r8y = fr_to_decimal(&sig.r8y);
    let sig_s = fr_to_decimal(&sig.s);

    sqlx::query(
        "INSERT INTO key_credentials (
             id, holder_key, credential_type, issued_at, issuer,
             sbt_nontransferable, commit_id, details,
             issuer_pubkey_x, issuer_pubkey_y,
             issued_sig_r8x, issued_sig_r8y, issued_sig_s
         ) VALUES (
             $1, $2, 'authority_sbt', $3, 'olympus:system',
             true, $4, $5,
             $6, $7,
             $8, $9, $10
         )",
    )
    .bind(&cred_id)
    .bind(&holder_key)
    .bind(issued_at.naive_utc())
    .bind(&commit_id_hex)
    .bind(&details)
    .bind(&issuer_x)
    .bind(&issuer_y)
    .bind(&sig_r8x)
    .bind(&sig_r8y)
    .bind(&sig_s)
    .execute(pool)
    .await?;

    tracing::info!(
        "bootstrap: minted self-signed authority SBT {cred_id} (commit_id={commit_id_hex})"
    );
    Ok(())
}

use crate::zk::proof::fr_to_decimal;

// ─── Keychain helpers (bootstrap-internal) ──────────────────────────────────
// `keyring` uses blocking OS calls; wrap in spawn_blocking so we don't stall
// the Tokio runtime. Failures are always non-fatal: the caller falls through
// to the next persistence tier (env var → keychain → DB dev column → generate).

const BJJ_KEYCHAIN_ACCOUNT: &str = "bjj_authority_key";
const KEYCHAIN_SERVICE: &str = "olympus-desktop";

async fn bjj_keychain_get() -> Result<Option<String>, String> {
    tokio::task::spawn_blocking(|| {
        let entry = keyring::Entry::new(KEYCHAIN_SERVICE, BJJ_KEYCHAIN_ACCOUNT)
            .map_err(|e| e.to_string())?;
        match entry.get_password() {
            Ok(val) => Ok(Some(val)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(e.to_string()),
        }
    })
    .await
    .unwrap_or_else(|e| Err(format!("spawn_blocking: {e}")))
}

async fn bjj_keychain_set(hex_key: &str) -> Result<(), String> {
    let hex_key = hex_key.to_owned();
    tokio::task::spawn_blocking(move || {
        let entry = keyring::Entry::new(KEYCHAIN_SERVICE, BJJ_KEYCHAIN_ACCOUNT)
            .map_err(|e| e.to_string())?;
        entry.set_password(&hex_key).map_err(|e| e.to_string())
    })
    .await
    .unwrap_or_else(|e| Err(format!("spawn_blocking: {e}")))?;
    Ok(())
}
