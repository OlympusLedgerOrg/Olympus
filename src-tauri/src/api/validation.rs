use std::sync::OnceLock;

use regex::Regex;

use super::error::{ApiError, ApiResult};

pub const MAX_LEAVES_PER_SHARD: i64 = 50_000;

static DOC_HASH_RE: OnceLock<Regex> = OnceLock::new();
static SHARD_ID_RE: OnceLock<Regex> = OnceLock::new();

fn doc_hash_re() -> &'static Regex {
    DOC_HASH_RE.get_or_init(|| Regex::new(r"^[0-9a-f]{64}$").unwrap())
}

fn shard_id_re() -> &'static Regex {
    SHARD_ID_RE.get_or_init(|| Regex::new(r"^[A-Za-z0-9:._-]{1,128}$").unwrap())
}

pub fn validate_doc_hash(h: &str) -> ApiResult<()> {
    if doc_hash_re().is_match(h) {
        Ok(())
    } else {
        Err(ApiError::BadRequest(
            "doc_hash must be 64 lowercase hex chars (BLAKE3)".into(),
        ))
    }
}

pub fn validate_shard_id(id: &str) -> ApiResult<()> {
    if shard_id_re().is_match(id) {
        Ok(())
    } else {
        Err(ApiError::BadRequest("invalid shard_id".into()))
    }
}

pub fn validate_shard_id_str(id: &str) -> ApiResult<String> {
    validate_shard_id(id)?;
    Ok(id.to_owned())
}
