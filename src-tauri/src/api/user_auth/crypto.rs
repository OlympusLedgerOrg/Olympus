//! Password hashing (scrypt, Python-compatible) and raw API-key generation.
//!
//! Split out of the user_auth module so the scrypt round-trip, the
//! constant-time verify, and the password-length bounds can be unit-tested in
//! isolation. `check_password_len` returns an `ApiError`, reusing the parent
//! module's `err` helper via `super::`.

use axum::http::StatusCode;
use rand::RngCore;
use subtle::ConstantTimeEq;

use super::{err, ApiError};

const SCRYPT_LOG_N: u8 = 14; // N = 2^14 = 16 384 — matches Python _SCRYPT_N
const SCRYPT_R: u32 = 8;
const SCRYPT_P: u32 = 1;
const SCRYPT_DK_LEN: usize = 64; // Python hashlib.scrypt default
const SCRYPT_SALT_LEN: usize = 32;

/// Minimum / maximum accepted password length (bytes). The upper bound caps
/// the PBKDF2-HMAC input so an attacker can't drive scrypt CPU cost with a
/// multi-megabyte password (audit hardening).
const MIN_PASSWORD_BYTES: usize = 12;
const MAX_PASSWORD_BYTES: usize = 1024;

// ── Password helpers ──────────────────────────────────────────────────────────

/// Hash `password` with scrypt using the same parameters as Python:
/// N=2^14, r=8, p=1, output=64 bytes, format `scrypt$N$r$p$salt_hex$dk_hex`.
pub(super) fn hash_password(password: &str) -> String {
    let mut salt = [0u8; SCRYPT_SALT_LEN];
    rand::thread_rng().fill_bytes(&mut salt);

    // scrypt 0.12 dropped dk_len from Params; output length is now determined
    // by the slice passed to scrypt::scrypt() below.
    let params = scrypt::Params::new(SCRYPT_LOG_N, SCRYPT_R, SCRYPT_P)
        .expect("scrypt params are valid compile-time constants");

    let mut dk = [0u8; SCRYPT_DK_LEN];
    scrypt::scrypt(password.as_bytes(), &salt, &params, &mut dk)
        .expect("scrypt output length matches DK_LEN constant");

    format!(
        "scrypt${}${}${}${}${}",
        1u32 << SCRYPT_LOG_N,
        SCRYPT_R,
        SCRYPT_P,
        hex::encode(salt),
        hex::encode(dk),
    )
}

/// Verify `password` against a stored hash in `scrypt$N$r$p$salt_hex$dk_hex`
/// format.  Uses constant-time comparison to prevent timing oracles.
/// Returns `false` on any parse error (rather than panicking).
pub(super) fn verify_password(password: &str, stored: &str) -> bool {
    let parts: Vec<&str> = stored.splitn(6, '$').collect();
    if parts.len() != 6 || parts[0] != "scrypt" {
        return false;
    }
    let Ok(n) = parts[1].parse::<u64>() else {
        return false;
    };
    let Ok(r) = parts[2].parse::<u32>() else {
        return false;
    };
    let Ok(p) = parts[3].parse::<u32>() else {
        return false;
    };
    let Ok(salt) = hex::decode(parts[4]) else {
        return false;
    };
    let Ok(expected) = hex::decode(parts[5]) else {
        return false;
    };
    if n == 0 || !n.is_power_of_two() || n > (1u64 << 30) {
        return false;
    }
    let log_n = n.trailing_zeros() as u8;
    let Ok(params) = scrypt::Params::new(log_n, r, p) else {
        return false;
    };
    let mut dk = vec![0u8; expected.len()];
    if scrypt::scrypt(password.as_bytes(), &salt, &params, &mut dk).is_err() {
        return false;
    }
    // Constant-time comparison — prevents timing oracles on the derived key.
    bool::from(dk.as_slice().ct_eq(&expected))
}

/// Validate a candidate password's byte length against the configured bounds.
pub(super) fn check_password_len(password: &str) -> Result<(), ApiError> {
    if password.len() < MIN_PASSWORD_BYTES {
        return Err(err(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Password must be at least 12 characters.",
        ));
    }
    if password.len() > MAX_PASSWORD_BYTES {
        return Err(err(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Password must be at most 1024 bytes.",
        ));
    }
    Ok(())
}

/// Dummy hash string for timing-safe login when user is not found.
/// Must have the same structure as a real hash so `verify_password` runs to
/// completion and takes a similar wall-clock time.
fn dummy_hash() -> String {
    format!(
        "scrypt${}${}${}${}${}",
        1u32 << SCRYPT_LOG_N,
        SCRYPT_R,
        SCRYPT_P,
        "00".repeat(SCRYPT_SALT_LEN),
        "00".repeat(SCRYPT_DK_LEN),
    )
}

/// Process-wide cached dummy hash for the user-not-found timing path.
///
/// Audit (memory-leak DoS): the previous `Box::leak(dummy_hash().into_boxed_str())`
/// permanently leaked ~200 bytes on every failed login/reissue/delete for an
/// unknown email — an unauthenticated, rate-limited-but-unbounded memory growth
/// vector. The constant is now computed once and shared.
pub(super) fn dummy_hash_ref() -> &'static str {
    static H: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    H.get_or_init(dummy_hash).as_str()
}

// ── Key helpers ───────────────────────────────────────────────────────────────

/// Generate a CSPRNG raw API key (32 bytes = 64 hex chars), matching
/// `secrets.token_hex(32)` from Python.
pub(super) fn generate_raw_key() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_verify_roundtrip() {
        // Random runtime password (not a hard-coded literal) — exercises the
        // scrypt round-trip without tripping the hard-coded-credential scanner.
        let pw = generate_raw_key();
        let hash = hash_password(&pw);
        assert!(
            verify_password(&pw, &hash),
            "correct password should verify"
        );
        let wrong = generate_raw_key();
        assert!(
            !verify_password(&wrong, &hash),
            "wrong password must not verify"
        );
    }

    #[test]
    fn verify_rejects_malformed_hash() {
        assert!(!verify_password("pw", "not-a-hash"));
        assert!(!verify_password("pw", "scrypt$bad$0$0$$"));
    }

    #[test]
    fn hash_format_matches_python() {
        // scrypt$16384$8$1$<64-hex-salt>$<128-hex-dk>
        let h = hash_password(&generate_raw_key());
        let parts: Vec<&str> = h.splitn(6, '$').collect();
        assert_eq!(parts.len(), 6);
        assert_eq!(parts[0], "scrypt");
        assert_eq!(parts[1], "16384");
        assert_eq!(parts[2], "8");
        assert_eq!(parts[3], "1");
        assert_eq!(parts[4].len(), SCRYPT_SALT_LEN * 2, "salt hex length");
        assert_eq!(parts[5].len(), SCRYPT_DK_LEN * 2, "dk hex length");
    }

    #[test]
    fn generate_raw_key_is_64_hex_chars() {
        let k = generate_raw_key();
        assert_eq!(k.len(), 64);
        assert!(k.chars().all(|c| c.is_ascii_hexdigit()));
    }
    #[test]
    fn check_password_len_bounds() {
        // Audit TOB-OLY-09: enforce both a floor and a ceiling so very long
        // inputs can't drive scrypt/PBKDF2 CPU cost.
        assert!(check_password_len("short").is_err());
        assert!(check_password_len("just-long-enough!").is_ok());
        assert!(check_password_len(&"a".repeat(MAX_PASSWORD_BYTES)).is_ok());
        assert!(check_password_len(&"a".repeat(MAX_PASSWORD_BYTES + 1)).is_err());
    }
}
