//! Prepared-transaction store for two-phase commit between the Rust SMT
//! and the Go sequencer's Postgres layer (H-2).
//!
//! The Go sequencer flow is:
//!
//!   1. PrepareUpdate (Rust)        — compute new root + deltas, *no* mutation
//!   2. BEGIN; insert leaf+deltas; COMMIT (Postgres)
//!   3. CommitPreparedUpdate (Rust) — atomically advance live SMT
//!
//! On any failure between (1) and (3), the sequencer calls
//! AbortPreparedUpdate. To bound memory in the face of buggy or hostile
//! clients that prepare without committing, this module wraps an `LruCache`
//! with a per-entry TTL: lookups treat expired entries as absent and prune
//! them lazily.
//!
//! ## Crash recovery contract (read me before changing the TTL)
//!
//! If the Go sequencer process crashes after step (2) succeeds but before
//! step (3) returns, the prepared transaction will eventually expire from
//! this LRU and the live SMT will lag durable Postgres state until the
//! sequencer restarts. **Crash recovery does NOT rely on the LRU surviving
//! the crash.** Instead, the Go sequencer's startup path
//! (`cmd/sequencer/main.go`) replays every persisted leaf in insertion
//! order via `ReplayLeaves` and then asserts that the resulting live root
//! equals the latest signed root in Postgres. Any leaf that was committed
//! to Postgres in step (2) but never confirmed via step (3) is therefore
//! re-applied on restart, restoring convergence. This is why the TTL can
//! safely be measured in tens of seconds rather than hours.
//!
//! The Sacred Law (H-2): a prepared-but-uncommitted update MUST NOT appear
//! in any signed root or proof. That property is enforced by
//! `SparseMerkleTree::compute_update` not mutating live state at all; this
//! module only owns the bookkeeping that lets a later `CommitPreparedUpdate`
//! find and apply the right `PreparedUpdate`.

use std::num::NonZeroUsize;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use lru::LruCache;

use crate::smt::PreparedUpdate;

/// Default TTL for a prepared transaction. Tuned to dominate any realistic
/// Postgres COMMIT latency (single-digit ms in healthy state, tens to low
/// hundreds of ms under load) while still being short enough that a stuck
/// preparer cannot pin much memory before it gets reaped.
pub const DEFAULT_PREPARED_TTL: Duration = Duration::from_secs(30);

/// Default cap on the number of in-flight prepared transactions. Each entry
/// holds ~256 NodeDelta records (~10 KiB) so 4096 entries ≈ 40 MiB worst
/// case. That's small enough not to threaten the service and large enough
/// to absorb realistic burst traffic without spurious LRU evictions.
pub const DEFAULT_PREPARED_CAPACITY: usize = 4096;

struct Entry {
    prepared: PreparedUpdate,
    inserted_at: Instant,
}

/// Bounded, TTL-aware store of prepared two-phase-commit transactions.
///
/// Insertions are O(1); expired entries are removed lazily on access (and
/// during `prune_expired`). The store is internally synchronised with a
/// `std::sync::Mutex`; callers do not need to hold their own lock.
pub struct PreparedTxStore {
    inner: Mutex<LruCache<String, Entry>>,
    ttl: Duration,
}

impl PreparedTxStore {
    /// Create a new store with the given capacity and TTL.
    ///
    /// `capacity` MUST be > 0 (zero would be a configuration bug). It is
    /// clamped up to 1 to satisfy the underlying `NonZeroUsize` invariant.
    pub fn new(capacity: usize, ttl: Duration) -> Self {
        let cap = NonZeroUsize::new(capacity.max(1)).expect("capacity clamped to >= 1");
        Self {
            inner: Mutex::new(LruCache::new(cap)),
            ttl,
        }
    }

    /// Insert a prepared transaction under `transaction_id`, evicting the
    /// oldest entry if the LRU is at capacity. Returns the number of
    /// currently-tracked entries after insertion (used for the
    /// `prepared_pending` metric).
    pub fn insert(&self, transaction_id: String, prepared: PreparedUpdate) -> usize {
        let mut cache = self.inner.lock().expect("PreparedTxStore mutex poisoned");
        cache.put(
            transaction_id,
            Entry {
                prepared,
                inserted_at: Instant::now(),
            },
        );
        cache.len()
    }

    /// Remove and return the prepared transaction, if present and not
    /// expired. Returns `None` for unknown / aborted / TTL-evicted ids,
    /// which the gRPC layer maps to `NOT_FOUND`.
    pub fn take(&self, transaction_id: &str) -> Option<PreparedUpdate> {
        let mut cache = self.inner.lock().expect("PreparedTxStore mutex poisoned");
        let entry = cache.pop(transaction_id)?;
        if entry.inserted_at.elapsed() > self.ttl {
            // Expired between prepare and commit. Treat as absent so the
            // sequencer falls back to its abort/retry path; the entry is
            // already removed from the cache by `pop`.
            None
        } else {
            Some(entry.prepared)
        }
    }

    /// Discard a prepared transaction. Idempotent: returns `true` iff an
    /// entry was actually removed (used by `aborts_after_db_failure` to
    /// distinguish "we cleaned up" from "the entry had already been
    /// evicted by TTL", though both cases are non-fatal).
    pub fn discard(&self, transaction_id: &str) -> bool {
        let mut cache = self.inner.lock().expect("PreparedTxStore mutex poisoned");
        cache.pop(transaction_id).is_some()
    }

    /// Number of currently-tracked entries (including any that have
    /// expired but not yet been pruned). Used for the `prepared_pending`
    /// gauge.
    pub fn len(&self) -> usize {
        let cache = self.inner.lock().expect("PreparedTxStore mutex poisoned");
        cache.len()
    }

    /// Test-only / metrics helper: remove all entries whose TTL has
    /// elapsed and return the number reaped.
    #[allow(dead_code)]
    pub fn prune_expired(&self) -> usize {
        let mut cache = self.inner.lock().expect("PreparedTxStore mutex poisoned");
        let now = Instant::now();
        let mut to_remove: Vec<String> = Vec::new();
        for (k, v) in cache.iter() {
            if now.duration_since(v.inserted_at) > self.ttl {
                to_remove.push(k.clone());
            }
        }
        let n = to_remove.len();
        for k in to_remove {
            cache.pop(&k);
        }
        n
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::smt::{NodeDelta, PreparedUpdate};

    fn fake_prepared() -> PreparedUpdate {
        PreparedUpdate {
            prior_root: [0u8; 32],
            new_root: [1u8; 32],
            new_tree_size: 1,
            is_new_leaf: true,
            key: [2u8; 32],
            value_hash: [3u8; 32],
            parser_id: "p@1".to_string(),
            canonical_parser_version: "v1".to_string(),
            nodes_to_write: Vec::new(),
            deltas: vec![NodeDelta {
                path: Vec::new(),
                level: 0,
                hash: [1u8; 32],
            }],
        }
    }

    #[test]
    fn insert_then_take_returns_value_once() {
        let store = PreparedTxStore::new(8, Duration::from_secs(30));
        store.insert("tx-1".to_string(), fake_prepared());
        assert_eq!(store.len(), 1);

        let got = store.take("tx-1");
        assert!(got.is_some(), "first take must hit");
        assert!(store.take("tx-1").is_none(), "second take must miss");
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn discard_is_idempotent() {
        let store = PreparedTxStore::new(8, Duration::from_secs(30));
        store.insert("tx-2".to_string(), fake_prepared());
        assert!(store.discard("tx-2"));
        assert!(!store.discard("tx-2"));
        assert!(!store.discard("never-existed"));
    }

    #[test]
    fn capacity_evicts_oldest() {
        let store = PreparedTxStore::new(2, Duration::from_secs(30));
        store.insert("a".to_string(), fake_prepared());
        store.insert("b".to_string(), fake_prepared());
        store.insert("c".to_string(), fake_prepared());
        // "a" must be evicted.
        assert!(store.take("a").is_none());
        assert!(store.take("b").is_some());
        assert!(store.take("c").is_some());
    }

    #[test]
    fn ttl_evicts_on_take() {
        let store = PreparedTxStore::new(8, Duration::from_millis(10));
        store.insert("stale".to_string(), fake_prepared());
        std::thread::sleep(Duration::from_millis(25));
        assert!(
            store.take("stale").is_none(),
            "TTL-expired entries must be invisible"
        );
    }

    #[test]
    fn zero_capacity_is_clamped_to_one() {
        // Defensive: a configuration bug shouldn't crash the service.
        let store = PreparedTxStore::new(0, Duration::from_secs(1));
        store.insert("only".to_string(), fake_prepared());
        assert!(store.take("only").is_some());
    }

    #[test]
    fn prune_expired_removes_old_entries() {
        let store = PreparedTxStore::new(8, Duration::from_millis(5));
        store.insert("x".to_string(), fake_prepared());
        store.insert("y".to_string(), fake_prepared());
        std::thread::sleep(Duration::from_millis(15));
        store.insert("fresh".to_string(), fake_prepared());
        let pruned = store.prune_expired();
        assert_eq!(pruned, 2);
        assert!(store.take("fresh").is_some());
    }
}
