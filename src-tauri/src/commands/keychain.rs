// SPDX-License-Identifier: Apache-2.0

// ─── OS keychain ──────────────────────────────────────────────────────────────
// Thin wrappers over the `keyring` crate (Windows Credential Manager, macOS
// Keychain, Linux libsecret). Both the service and account are fixed in native
// code: the renderer must never choose an account within the service that also
// stores non-UI authority material.

const KEYCHAIN_SERVICE: &str = "olympus-desktop";
const API_KEYCHAIN_ACCOUNT: &str = "api_key";
const API_KEY_HEX_LEN: usize = 64;
const KEYCHAIN_UNAVAILABLE: &str = "the OS keychain is unavailable";

fn validate_keychain_api_key(value: &str) -> Result<(), String> {
    if value.len() == API_KEY_HEX_LEN && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err("API key must be exactly 64 hexadecimal characters".to_owned())
    }
}

fn api_keychain_entry() -> Result<keyring::Entry, String> {
    keyring::Entry::new(KEYCHAIN_SERVICE, API_KEYCHAIN_ACCOUNT)
        .map_err(|_| KEYCHAIN_UNAVAILABLE.to_owned())
}

/// Read the API key from the one renderer-accessible OS-keychain account.
/// Returns `None` if no entry exists (not an error — callers use it for
/// "first launch" detection).
#[tauri::command]
pub(crate) fn keychain_get() -> Result<Option<String>, String> {
    let entry = api_keychain_entry()?;
    match entry.get_password() {
        Ok(value) => {
            validate_keychain_api_key(&value)?;
            Ok(Some(value))
        }
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(_) => Err(KEYCHAIN_UNAVAILABLE.to_owned()),
    }
}

/// Write a validated API key to the fixed OS-keychain account.
#[tauri::command]
pub(crate) fn keychain_set(value: String) -> Result<(), String> {
    validate_keychain_api_key(&value)?;
    let entry = api_keychain_entry()?;
    entry
        .set_password(&value)
        .map_err(|_| KEYCHAIN_UNAVAILABLE.to_owned())
}

/// Delete the fixed API-key account. Idempotent if the entry does not exist.
#[tauri::command]
pub(crate) fn keychain_delete() -> Result<(), String> {
    let entry = api_keychain_entry()?;
    match entry.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(_) => Err(KEYCHAIN_UNAVAILABLE.to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renderer_keychain_account_is_fixed_and_separate_from_authority_material() {
        assert_eq!(API_KEYCHAIN_ACCOUNT, "api_key");
        assert_ne!(API_KEYCHAIN_ACCOUNT, crate::bootstrap::BJJ_KEYCHAIN_ACCOUNT);
    }

    #[test]
    fn keychain_api_key_validation_is_exact_and_bounded() {
        assert!(validate_keychain_api_key(&"ab".repeat(32)).is_ok());
        assert!(validate_keychain_api_key(&"AB".repeat(32)).is_ok());
        assert!(validate_keychain_api_key(&"a".repeat(63)).is_err());
        assert!(validate_keychain_api_key(&"a".repeat(65)).is_err());
        assert!(validate_keychain_api_key(&"g".repeat(64)).is_err());
        assert!(validate_keychain_api_key(&"a".repeat(1_000_000)).is_err());
    }
}
