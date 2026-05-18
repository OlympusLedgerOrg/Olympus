use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct MerkleStep {
    pub hash: String,
    pub direction: String, // "L" | "R"
}

/// Hash two hex-encoded leaf/node values with BLAKE3.
pub fn hash_pair(left: &str, right: &str) -> String {
    let mut h = blake3::Hasher::new();
    h.update(left.as_bytes());
    h.update(right.as_bytes());
    h.finalize().to_hex().to_string()
}

/// Compute the BLAKE3 binary Merkle root of an ordered slice of hex leaves.
pub fn root(leaves: &[String]) -> String {
    if leaves.is_empty() {
        return blake3::hash(b"empty").to_hex().to_string();
    }
    let mut level: Vec<String> = leaves.to_vec();
    while level.len() > 1 {
        if level.len() % 2 == 1 {
            level.push(level.last().unwrap().clone());
        }
        level = level
            .chunks(2)
            .map(|p| hash_pair(&p[0], &p[1]))
            .collect();
    }
    level.into_iter().next().unwrap()
}

/// Build an inclusion proof for `target` within `leaves`.
/// Returns an empty vec if `target` is not found.
pub fn proof_for(leaves: &[String], target: &str) -> Vec<MerkleStep> {
    let Some(mut idx) = leaves.iter().position(|h| h == target) else {
        return vec![];
    };
    let mut proof = Vec::new();
    let mut level: Vec<String> = leaves.to_vec();

    while level.len() > 1 {
        if level.len() % 2 == 1 {
            level.push(level.last().unwrap().clone());
        }
        let sibling_idx = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
        proof.push(MerkleStep {
            hash: level[sibling_idx].clone(),
            direction: if idx % 2 == 0 { "R".into() } else { "L".into() },
        });
        level = level
            .chunks(2)
            .map(|p| hash_pair(&p[0], &p[1]))
            .collect();
        idx /= 2;
    }
    proof
}
