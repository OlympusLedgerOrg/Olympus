//! Credential DB row and the read-side wire view it converts into.
//! Split out of the credentials module.

use serde::Serialize;

use crate::quorum::{self, QuorumSigner};

#[derive(Debug, sqlx::FromRow)]
pub(super) struct CredentialRow {
    pub(super) id: String,
    pub(super) holder_key: String,
    pub(super) credential_type: String,
    pub(super) issued_at: chrono::NaiveDateTime,
    pub(super) revoked_at: Option<chrono::NaiveDateTime>,
    pub(super) issuer: String,
    pub(super) commit_id: String,
    pub(super) details: serde_json::Value,
    pub(super) issuer_pubkey_x: Option<String>,
    pub(super) issuer_pubkey_y: Option<String>,
    pub(super) issued_sig_r8x: Option<String>,
    pub(super) issued_sig_r8y: Option<String>,
    pub(super) issued_sig_s: Option<String>,
    pub(super) revoked_sig_r8x: Option<String>,
    pub(super) revoked_sig_r8y: Option<String>,
    pub(super) revoked_sig_s: Option<String>,
    // Pedersen commitment columns (PD-3). NULL on plaintext rows.
    pub(super) commitment_x: Option<String>,
    pub(super) commitment_y: Option<String>,
    pub(super) commitment_version: Option<i16>,
    // Federation quorum columns (migration 0032). NULL on single-sig rows.
    pub(super) quorum_threshold: Option<i32>,
    pub(super) quorum_signers: Option<serde_json::Value>,
    pub(super) quorum_proof: Option<serde_json::Value>,
    pub(super) quorum_proof_signals: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
struct SignaturePayload {
    r8x: String,
    r8y: String,
    s: String,
}

#[derive(Debug, Serialize)]
struct CommitmentPayload {
    x: String,
    y: String,
    version: i16,
}

/// Quorum summary attached to a credential view. Read-side metadata only —
/// the per-signer collected signatures live in `credential_quorum_signatures`
/// and the live satisfied/valid counts are surfaced by the verify endpoint.
#[derive(Debug, Serialize)]
struct QuorumView {
    /// Required number of valid signatures `M`.
    threshold: i32,
    /// Size of the pinned signer set `N`.
    total_signers: usize,
    /// The pinned signer set (BJJ pubkey coordinates).
    signers: Vec<QuorumSigner>,
    /// Whether a (privacy-preserving) ZK quorum proof is attached.
    has_proof: bool,
}

#[derive(Debug, Serialize)]
pub(super) struct CredentialView {
    id: String,
    holder_key: String,
    credential_type: String,
    issued_at: String,
    revoked_at: Option<String>,
    issuer: String,
    commit_id: String,
    details: serde_json::Value,
    issuer_pubkey: Option<SignaturePayload>, // reused shape: (x, y) but `s` always empty
    issued_signature: Option<SignaturePayload>,
    revoked_signature: Option<SignaturePayload>,
    /// Pedersen commitment over `details`. Present iff the row was issued
    /// with `commit: true`; `details` in that case is an empty object and
    /// the cleartext is held only by the original opener.
    #[serde(skip_serializing_if = "Option::is_none")]
    commitment: Option<CommitmentPayload>,
    /// Federation quorum metadata. Present iff the row was issued with
    /// `quorum: true` (i.e. `quorum_threshold` is non-NULL).
    #[serde(skip_serializing_if = "Option::is_none")]
    quorum: Option<QuorumView>,
}

impl From<CredentialRow> for CredentialView {
    fn from(r: CredentialRow) -> Self {
        let issuer_pubkey = match (r.issuer_pubkey_x.as_deref(), r.issuer_pubkey_y.as_deref()) {
            (Some(x), Some(y)) => Some(SignaturePayload {
                r8x: x.to_owned(),
                r8y: y.to_owned(),
                s: String::new(),
            }),
            _ => None,
        };
        let issued_signature = match (
            r.issued_sig_r8x.as_deref(),
            r.issued_sig_r8y.as_deref(),
            r.issued_sig_s.as_deref(),
        ) {
            (Some(x), Some(y), Some(s)) => Some(SignaturePayload {
                r8x: x.to_owned(),
                r8y: y.to_owned(),
                s: s.to_owned(),
            }),
            _ => None,
        };
        let revoked_signature = match (
            r.revoked_sig_r8x.as_deref(),
            r.revoked_sig_r8y.as_deref(),
            r.revoked_sig_s.as_deref(),
        ) {
            (Some(x), Some(y), Some(s)) => Some(SignaturePayload {
                r8x: x.to_owned(),
                r8y: y.to_owned(),
                s: s.to_owned(),
            }),
            _ => None,
        };
        let commitment = match (r.commitment_x, r.commitment_y, r.commitment_version) {
            (Some(x), Some(y), Some(version)) => Some(CommitmentPayload { x, y, version }),
            _ => None,
        };
        let quorum = r.quorum_threshold.map(|threshold| {
            let signers = r
                .quorum_signers
                .as_ref()
                .map(quorum::signers_from_json)
                .unwrap_or_default();
            QuorumView {
                threshold,
                total_signers: signers.len(),
                signers,
                has_proof: r.quorum_proof.is_some(),
            }
        });
        CredentialView {
            id: r.id,
            holder_key: r.holder_key,
            credential_type: r.credential_type,
            issued_at: r.issued_at.and_utc().to_rfc3339(),
            revoked_at: r.revoked_at.map(|t| t.and_utc().to_rfc3339()),
            issuer: r.issuer,
            commit_id: r.commit_id,
            details: r.details,
            issuer_pubkey,
            issued_signature,
            revoked_signature,
            commitment,
            quorum,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// A plaintext credential row with every optional column NULL.
    fn bare_row() -> CredentialRow {
        let ts = chrono::DateTime::from_timestamp(1_700_000_000, 0)
            .expect("valid ts")
            .naive_utc();
        CredentialRow {
            id: "id-1".into(),
            holder_key: "alice".into(),
            credential_type: "press".into(),
            issued_at: ts,
            revoked_at: None,
            issuer: "olympus:federation".into(),
            commit_id: "deadbeef".into(),
            details: json!({"role": "journalist"}),
            issuer_pubkey_x: None,
            issuer_pubkey_y: None,
            issued_sig_r8x: None,
            issued_sig_r8y: None,
            issued_sig_s: None,
            revoked_sig_r8x: None,
            revoked_sig_r8y: None,
            revoked_sig_s: None,
            commitment_x: None,
            commitment_y: None,
            commitment_version: None,
            quorum_threshold: None,
            quorum_signers: None,
            quorum_proof: None,
            quorum_proof_signals: None,
        }
    }

    #[test]
    fn view_omits_optional_blocks_when_columns_null() {
        let view: CredentialView = bare_row().into();
        // No pubkey/signature/commitment/quorum columns -> all None.
        assert!(view.issuer_pubkey.is_none());
        assert!(view.issued_signature.is_none());
        assert!(view.revoked_signature.is_none());
        assert!(view.commitment.is_none());
        assert!(view.quorum.is_none());
        // Scalar fields carry through; issued_at is rendered as RFC 3339.
        assert_eq!(view.holder_key, "alice");
        assert!(view.issued_at.contains("2023-11-14"));
    }

    #[test]
    fn view_assembles_issuer_pubkey_signature_and_commitment() {
        let mut row = bare_row();
        row.issuer_pubkey_x = Some("11".into());
        row.issuer_pubkey_y = Some("22".into());
        row.issued_sig_r8x = Some("33".into());
        row.issued_sig_r8y = Some("44".into());
        row.issued_sig_s = Some("55".into());
        row.commitment_x = Some("66".into());
        row.commitment_y = Some("77".into());
        row.commitment_version = Some(1);
        let view: CredentialView = row.into();

        let pubkey = view.issuer_pubkey.expect("pubkey assembled");
        assert_eq!((pubkey.r8x.as_str(), pubkey.r8y.as_str()), ("11", "22"));
        // issuer_pubkey reuses the signature shape; `s` is always empty.
        assert!(pubkey.s.is_empty());

        let sig = view.issued_signature.expect("signature assembled");
        assert_eq!(
            (sig.r8x.as_str(), sig.r8y.as_str(), sig.s.as_str()),
            ("33", "44", "55")
        );

        let c = view.commitment.expect("commitment assembled");
        assert_eq!((c.x.as_str(), c.y.as_str(), c.version), ("66", "77", 1));
    }

    #[test]
    fn view_requires_all_three_signature_fields() {
        // A partial signature (missing `s`) must NOT assemble a payload — the
        // all-or-nothing tuple match guards against half-populated columns.
        let mut row = bare_row();
        row.issued_sig_r8x = Some("33".into());
        row.issued_sig_r8y = Some("44".into());
        // issued_sig_s left None
        let view: CredentialView = row.into();
        assert!(view.issued_signature.is_none());
    }
}
