//! With-DB happy-path coverage for `src-tauri/src/routes/public_stats.rs`.
//!
//! The existing `src/server/mod.rs::tests` only assert the 503 path when
//! the pool is absent. This file boots `pg_embed` and asserts that:
//!
//! 1. `/public/stats` and `/v1/public/stats` both return the JSON shape
//!    the frontend dashboards depend on (PublicStats struct).
//! 2. The 10-second in-memory cache returns identical bodies on a fast
//!    second hit — important for the ledger/landing page which polls
//!    these endpoints.
//!
//! Replaces the deleted `tests/test_public_stats.py`.

use crate::common;

use serde_json::Value;

const FIELDS: &[&str] = &[
    "nodes",
    "shards",
    "proofs",
    "sbts_issued",
    "uptime",
    "uptime_seconds",
    "copies",
];

#[tokio::test]
async fn public_stats_returns_full_shape() {
    let h = common::boot().await;
    let resp = h
        .client
        .get(common::url(h, "/public/stats"))
        .send()
        .await
        .expect("GET");
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.expect("JSON");
    for f in FIELDS {
        assert!(
            body.get(*f).is_some(),
            "missing field `{f}` in /public/stats response: {body:#}"
        );
    }
}

#[tokio::test]
async fn v1_public_stats_returns_same_shape() {
    // The Python API mounted the same handler at /v1/public/stats so
    // existing api.ts clients keep working. Verify byte-for-byte parity
    // is *not* claimed (the cache can refresh between the two requests)
    // but the field set is.
    let h = common::boot().await;
    let resp = h
        .client
        .get(common::url(h, "/v1/public/stats"))
        .send()
        .await
        .expect("GET");
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.expect("JSON");
    for f in FIELDS {
        assert!(
            body.get(*f).is_some(),
            "missing field `{f}` in /v1/public/stats response: {body:#}"
        );
    }
}

#[tokio::test]
async fn public_stats_cache_returns_identical_body_within_ttl() {
    let h = common::boot().await;
    let url = common::url(h, "/public/stats");
    // First call populates the cache. Second within 10s must be served
    // from cache and have an identical `uptime_seconds` (real-time
    // recomputation would tick this up between calls).
    let a: Value = h
        .client
        .get(&url)
        .send()
        .await
        .expect("GET 1")
        .json()
        .await
        .expect("JSON 1");
    let b: Value = h
        .client
        .get(&url)
        .send()
        .await
        .expect("GET 2")
        .json()
        .await
        .expect("JSON 2");
    assert_eq!(
        a["uptime_seconds"], b["uptime_seconds"],
        "stats_cache should return the same uptime_seconds within TTL"
    );
}
