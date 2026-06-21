//! Dual-mode end-to-end endpoint sweep.
//!
//! Two run modes, one body of checks:
//!   * **In-proc (default):** boots the shared `common` pg_embed + Axum server
//!     and sweeps every route against it. Runs on the host under default
//!     features (`cargo test --test e2e_http`).
//!   * **Container / remote:** set `OLYMPUS_E2E_BASE_URL` (e.g.
//!     `http://127.0.0.1:3737`), `OLYMPUS_E2E_API_KEY` (an **admin-scoped**
//!     key), and `OLYMPUS_ADMIN_KEY`. The exact same sweep then runs against a
//!     running `olympus-server` container — this is the "E2E in a container"
//!     validation (see docker/compose.audit.yml). Because the container binds
//!     127.0.0.1 only, the runner must share its network namespace.
//!
//! This is the *breadth + invariants* sweep: it proves every endpoint is
//! reachable and correctly gated, and re-checks the load-bearing audit
//! invariants (Host-guard, CORS, body limit, ZK treeSize=0 (H-2), shard
//! authorize_write 403, insert-only 409, credential/anchor auth). Exhaustive
//! per-endpoint body validation lives in the `api_db` suite; this complements
//! it and is the part that can target a container. A coverage matrix is printed
//! at the end and the test fails if any row is unexpected.

#[path = "common/mod.rs"]
mod common;

use reqwest::multipart::{Form, Part};
use reqwest::Client;
use serde_json::json;
use std::time::Duration;

/// Resolved target: a base URL + a broad (admin-scoped) api key + the operator
/// admin key + an HTTP client. Works for both in-proc and container modes.
struct Target {
    base: String,
    api_key: String,
    admin_key: String,
    client: Client,
    /// True when we booted the in-proc harness (vs. a remote container).
    in_proc: bool,
}

impl Target {
    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base, path)
    }
}

/// Container mode: mint a broad-but-not-admin API key via the operator admin
/// path (register a plain user, then mint a scoped key for them). Gives the
/// sweep the `write`/`ingest`/`verify`/`prove` scopes its invariant checks need
/// without requiring the caller to know the bootstrap system key.
async fn mint_broad_key(client: &Client, base: &str, admin_key: &str) -> String {
    let email = format!("{}@example.com", uniq("e2e-remote"));
    let reg = client
        .post(format!("{base}/auth/register"))
        .json(&json!({
            "email": email,
            "password": "correct-horse-battery-staple",
            "name": "e2e",
            "scopes": ["read", "verify"],
        }))
        .send()
        .await
        .expect("remote register");
    assert_eq!(reg.status().as_u16(), 201, "remote register should be 201");
    let user_id = reg
        .json::<serde_json::Value>()
        .await
        .expect("register json")["user_id"]
        .as_str()
        .expect("user_id")
        .to_owned();
    let mint = client
        .post(format!("{base}/admin/users/{user_id}/keys"))
        .header("x-admin-key", admin_key)
        .json(&json!({ "name": "e2e-broad", "scopes": ["read", "write", "verify", "ingest", "prove"] }))
        .send()
        .await
        .expect("remote mint");
    assert_eq!(mint.status().as_u16(), 200, "remote key mint should be 200");
    mint.json::<serde_json::Value>().await.expect("mint json")["raw_key"]
        .as_str()
        .expect("raw_key")
        .to_owned()
}

async fn resolve_target() -> Target {
    if let Ok(base) = std::env::var("OLYMPUS_E2E_BASE_URL") {
        let base = base.trim_end_matches('/').to_owned();
        let admin_key = std::env::var("OLYMPUS_ADMIN_KEY").unwrap_or_default();
        assert!(
            !admin_key.is_empty(),
            "container mode needs OLYMPUS_ADMIN_KEY"
        );
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("client");
        // Explicit override wins; otherwise self-mint a scoped key.
        let api_key = match std::env::var("OLYMPUS_E2E_API_KEY") {
            Ok(k) if !k.is_empty() => k,
            _ => mint_broad_key(&client, &base, &admin_key).await,
        };
        Target {
            base,
            api_key,
            admin_key,
            client,
            in_proc: false,
        }
    } else {
        let h = common::boot().await;
        Target {
            base: format!("http://{}", h.addr),
            api_key: h.api_key.clone(),
            admin_key: h.admin_key.clone(),
            client: h.client.clone(),
            in_proc: true,
        }
    }
}

/// One coverage-matrix row.
struct Row {
    route: &'static str,
    case: &'static str,
    status: u16,
    ok: bool,
}

struct Matrix {
    rows: Vec<Row>,
}

impl Matrix {
    fn new() -> Self {
        Self { rows: Vec::new() }
    }

    /// Record an outcome: `ok` iff the observed status is in `allowed`.
    fn record(&mut self, route: &'static str, case: &'static str, status: u16, allowed: &[u16]) {
        let ok = allowed.contains(&status);
        self.rows.push(Row {
            route,
            case,
            status,
            ok,
        });
    }

    fn print(&self) {
        eprintln!("\n=== E2E coverage matrix ({} checks) ===", self.rows.len());
        eprintln!("{:<38} {:<34} {:>6}  OK", "ROUTE", "CASE", "STATUS");
        for r in &self.rows {
            eprintln!(
                "{:<38} {:<34} {:>6}  {}",
                r.route,
                r.case,
                r.status,
                if r.ok { "ok" } else { "FAIL" }
            );
        }
        let fails = self.rows.iter().filter(|r| !r.ok).count();
        eprintln!("=== {} ok / {} FAIL ===\n", self.rows.len() - fails, fails);
    }

    fn fails(&self) -> usize {
        self.rows.iter().filter(|r| !r.ok).count()
    }
}

fn uniq(prefix: &str) -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{prefix}-{nanos}")
}

#[tokio::test]
async fn e2e_endpoint_sweep() {
    let t = resolve_target().await;
    let c = &t.client;
    let mut m = Matrix::new();

    // ── Public / unauthenticated reads ───────────────────────────────────────
    for (route, path) in [
        ("GET /health", "/health"),
        ("GET /public/stats", "/public/stats"),
        ("GET /v1/public/stats", "/v1/public/stats"),
        ("GET /ledger/state", "/ledger/state"),
        ("GET /ledger/shard/files", "/ledger/shard/files"),
        ("GET /ledger/activity", "/ledger/activity?limit=5"),
    ] {
        let r = c.get(t.url(path)).send().await.expect("GET");
        m.record(route, "public 200", r.status().as_u16(), &[200]);
    }

    // Read-side 4xx behaviors.
    let r = c
        .get(t.url("/ledger/shard/has space"))
        .send()
        .await
        .expect("GET");
    m.record(
        "GET /ledger/shard/{id}",
        "invalid id 4xx",
        r.status().as_u16(),
        &[400, 404, 422],
    );

    let r = c
        .get(t.url("/ledger/proof/0xdeadbeefdeadbeef"))
        .send()
        .await
        .expect("GET");
    m.record(
        "GET /ledger/proof/{id}",
        "unknown 404",
        r.status().as_u16(),
        &[404],
    );

    let r = c
        .get(t.url(&format!("/ingest/records/{}", uniq("noproof"))))
        .send()
        .await
        .expect("GET");
    m.record(
        "GET /ingest/records/{id}",
        "unknown 404",
        r.status().as_u16(),
        &[404],
    );

    let bogus_hash = "0".repeat(64);
    let r = c
        .get(t.url(&format!("/ingest/records/hash/{bogus_hash}/verify")))
        .send()
        .await
        .expect("GET");
    m.record(
        "GET /ingest/records/hash/{h}/verify",
        "public 200",
        r.status().as_u16(),
        &[200, 404],
    );

    // ── Auth flow ────────────────────────────────────────────────────────────
    let email = format!("{}@example.com", uniq("e2e"));
    let reg = c
        .post(t.url("/auth/register"))
        .json(&json!({
            "email": email,
            "password": "correct-horse-battery-staple",
            "name": "e2e",
            "scopes": ["read", "verify"],
        }))
        .send()
        .await
        .expect("register");
    let reg_status = reg.status().as_u16();
    m.record("POST /auth/register", "create 201", reg_status, &[201]);
    let user_api_key = if reg_status == 201 {
        reg.json::<serde_json::Value>()
            .await
            .ok()
            .and_then(|b| b["api_key"].as_str().map(|s| s.to_owned()))
            .unwrap_or_default()
    } else {
        String::new()
    };

    // Duplicate email rejected.
    let dup = c
        .post(t.url("/auth/register"))
        .json(&json!({
            "email": email,
            "password": "correct-horse-battery-staple",
            "name": "e2e",
            "scopes": ["read"],
        }))
        .send()
        .await
        .expect("register dup");
    m.record(
        "POST /auth/register",
        "dup email 409",
        dup.status().as_u16(),
        &[409, 400, 422],
    );

    // Unknown scope rejected.
    let badscope = c
        .post(t.url("/auth/register"))
        .json(&json!({
            "email": format!("{}@example.com", uniq("badscope")),
            "password": "correct-horse-battery-staple",
            "name": "e2e",
            "scopes": ["totally-made-up-scope"],
        }))
        .send()
        .await
        .expect("register badscope");
    m.record(
        "POST /auth/register",
        "unknown scope 4xx",
        badscope.status().as_u16(),
        &[400, 422],
    );

    // Login good / bad.
    let login = c
        .post(t.url("/auth/login"))
        .json(&json!({ "email": email, "password": "correct-horse-battery-staple" }))
        .send()
        .await
        .expect("login");
    m.record(
        "POST /auth/login",
        "good 200",
        login.status().as_u16(),
        &[200],
    );

    let badlogin = c
        .post(t.url("/auth/login"))
        .json(&json!({ "email": email, "password": "wrong-password" }))
        .send()
        .await
        .expect("badlogin");
    m.record(
        "POST /auth/login",
        "bad pw 401",
        badlogin.status().as_u16(),
        &[401, 400],
    );

    // Authenticated key listing (use the freshly-registered user's key).
    if !user_api_key.is_empty() {
        let keys = c
            .get(t.url("/auth/keys"))
            .header("x-api-key", &user_api_key)
            .send()
            .await
            .expect("keys");
        m.record(
            "GET /auth/keys",
            "authed 200",
            keys.status().as_u16(),
            &[200],
        );
    }
    let noauth_keys = c
        .get(t.url("/auth/keys"))
        .send()
        .await
        .expect("keys noauth");
    m.record(
        "GET /auth/keys",
        "no auth 401",
        noauth_keys.status().as_u16(),
        &[401],
    );

    // ── Invariant: Host-header guard (DNS-rebinding defense) ─────────────────
    let host_guard = c
        .get(t.url("/health"))
        .header(reqwest::header::HOST, "evil.example")
        .send()
        .await
        .expect("host guard");
    m.record(
        "GET /health",
        "bad Host rejected",
        host_guard.status().as_u16(),
        &[400, 403, 421],
    );

    // ── Invariant: CORS preflight ─────────────────────────────────────────────
    let preflight = c
        .request(reqwest::Method::OPTIONS, t.url("/public/stats"))
        .header(reqwest::header::ORIGIN, "tauri://localhost")
        .header("access-control-request-method", "GET")
        .send()
        .await
        .expect("cors preflight");
    let has_allow = preflight
        .headers()
        .contains_key("access-control-allow-origin");
    m.record(
        "OPTIONS /public/stats",
        "CORS preflight 2xx",
        preflight.status().as_u16(),
        &[200, 204],
    );
    m.rows.push(Row {
        route: "OPTIONS /public/stats",
        case: "allow-origin echoed",
        status: if has_allow { 1 } else { 0 },
        ok: has_allow,
    });

    // ── Invariant: body limit on the unauth surface (64 KiB on /auth/*) ──────
    let huge = "x".repeat(200 * 1024);
    let toobig = c
        .post(t.url("/auth/register"))
        .json(&json!({
            "email": format!("{}@example.com", uniq("big")),
            "password": "correct-horse-battery-staple",
            "name": huge,
            "scopes": ["read"],
        }))
        .send()
        .await
        .expect("toobig");
    m.record(
        "POST /auth/register",
        "oversize body 413",
        toobig.status().as_u16(),
        &[413],
    );

    // ── Invariant: ZK /zk/verify guards ──────────────────────────────────────
    let zk_noauth = c
        .post(t.url("/zk/verify"))
        .json(&json!({ "circuit": "document_existence", "proofJson": "{}", "publicSignals": ["1","0","1"] }))
        .send()
        .await
        .expect("zk noauth");
    m.record(
        "POST /zk/verify",
        "no auth 401",
        zk_noauth.status().as_u16(),
        &[401],
    );

    // H-2: treeSize=0 with a non-empty root must be rejected (400, "treeSize=0").
    let zk_h2 = c
        .post(t.url("/zk/verify"))
        .header("x-api-key", &t.api_key)
        .json(&json!({ "circuit": "document_existence", "proofJson": "{}", "publicSignals": ["1","0","0"] }))
        .send()
        .await
        .expect("zk h2");
    let zk_h2_status = zk_h2.status().as_u16();
    let zk_h2_body: serde_json::Value = zk_h2.json().await.unwrap_or_default();
    let h2_msg = zk_h2_body["error"]
        .as_str()
        .unwrap_or_default()
        .contains("treeSize=0");
    m.record(
        "POST /zk/verify",
        "H-2 treeSize=0 400",
        zk_h2_status,
        &[400],
    );
    m.rows.push(Row {
        route: "POST /zk/verify",
        case: "H-2 error mentions treeSize=0",
        status: if h2_msg { 1 } else { 0 },
        ok: h2_msg,
    });

    // /zk/prove: reachable + gated. Happy path needs real artifacts (placeholders → 503).
    let zk_prove_noauth = c
        .post(t.url("/zk/prove"))
        .json(&json!({ "circuit": "document_existence" }))
        .send()
        .await
        .expect("zk prove noauth");
    m.record(
        "POST /zk/prove",
        "no auth 401",
        zk_prove_noauth.status().as_u16(),
        &[401],
    );

    // ── Invariant: shard authorize_write fail-closed (403 on unregistered) ────
    let unreg_shard = uniq("unreg");
    let shard_form = Form::new()
        .part(
            "file",
            Part::bytes(b"e2e unregistered shard".to_vec()).file_name("t.txt"),
        )
        .text("shard_id", unreg_shard);
    let shard_403 = c
        .post(t.url("/ingest/files"))
        .header("x-api-key", &t.api_key)
        .multipart(shard_form)
        .send()
        .await
        .expect("shard 403");
    m.record(
        "POST /ingest/files",
        "unregistered shard 403",
        shard_403.status().as_u16(),
        &[403],
    );

    // ── Invariant: insert-only ledger (409 on rewriting a record identity) ────
    let rec = uniq("insert-only");
    let mk_ident_form = |body: &'static str| {
        Form::new()
            .part(
                "file",
                Part::bytes(body.as_bytes().to_vec()).file_name("t.txt"),
            )
            .text("shard_id", "files".to_string())
            .text("record_id", rec.clone())
            .text("version", "1")
    };
    let first = c
        .post(t.url("/ingest/files"))
        .header("x-api-key", &t.api_key)
        .multipart(mk_ident_form("original bytes"))
        .send()
        .await
        .expect("ingest first");
    m.record(
        "POST /ingest/files",
        "first commit 2xx",
        first.status().as_u16(),
        &[200, 201],
    );

    let conflict = c
        .post(t.url("/ingest/files"))
        .header("x-api-key", &t.api_key)
        .multipart(mk_ident_form("tampered bytes"))
        .send()
        .await
        .expect("ingest conflict");
    m.record(
        "POST /ingest/files",
        "write-once 409",
        conflict.status().as_u16(),
        &[409],
    );

    // ── Admin routes (x-admin-key) ────────────────────────────────────────────
    for (route, path) in [
        ("GET /admin/users", "/admin/users"),
        ("GET /admin/shards", "/admin/shards"),
        ("GET /admin/smt/stats", "/admin/smt/stats"),
        ("GET /api/admin/stats", "/api/admin/stats"),
        ("GET /api/admin/customers", "/api/admin/customers"),
    ] {
        let r = c
            .get(t.url(path))
            .header("x-admin-key", &t.admin_key)
            .send()
            .await
            .expect("admin GET");
        m.record(route, "admin 200", r.status().as_u16(), &[200]);
    }
    // Admin gate: same route without the admin key is rejected.
    let admin_noauth = c
        .get(t.url("/admin/users"))
        .send()
        .await
        .expect("admin noauth");
    m.record(
        "GET /admin/users",
        "no admin key 401",
        admin_noauth.status().as_u16(),
        &[401],
    );

    // Register a shard via the admin path.
    let new_shard = uniq("e2e-shard");
    let reg_shard = c
        .post(t.url("/admin/shards"))
        .header("x-admin-key", &t.admin_key)
        .json(&json!({ "shard_id": new_shard, "label": "e2e" }))
        .send()
        .await
        .expect("reg shard");
    m.record(
        "POST /admin/shards",
        "register 201",
        reg_shard.status().as_u16(),
        &[201],
    );

    // ── Credentials (reachable + gated; deep H-1/H-2 logic is in unit tests) ──
    let cred_noauth = c
        .post(t.url("/credentials"))
        .json(&json!({ "holder_key": "x", "credential_type": "authority_sbt" }))
        .send()
        .await
        .expect("cred noauth");
    m.record(
        "POST /credentials",
        "no auth 401",
        cred_noauth.status().as_u16(),
        &[401],
    );

    let cred_list = c
        .get(t.url("/credentials"))
        .header("x-api-key", &t.api_key)
        .send()
        .await
        .expect("cred list");
    m.record(
        "GET /credentials",
        "admin-scope 200",
        cred_list.status().as_u16(),
        &[200, 403],
    );

    let cred_get = c
        .get(t.url(&format!("/credentials/{}", uniq("nocred"))))
        .header("x-api-key", &t.api_key)
        .send()
        .await
        .expect("cred get");
    m.record(
        "GET /credentials/{id}",
        "unknown 404",
        cred_get.status().as_u16(),
        &[404, 403],
    );

    let cred_verify_noauth = c
        .post(t.url(&format!("/credentials/{}/verify", uniq("nocred"))))
        .json(&json!({}))
        .send()
        .await
        .expect("cred verify noauth");
    m.record(
        "POST /credentials/{id}/verify",
        "no auth 401",
        cred_verify_noauth.status().as_u16(),
        &[401],
    );

    // ── Redaction (reachable + gated) ─────────────────────────────────────────
    let redact_noauth = c
        .post(t.url("/redaction/describe"))
        .json(&json!({}))
        .send()
        .await
        .expect("redact noauth");
    m.record(
        "POST /redaction/describe",
        "no auth 401",
        redact_noauth.status().as_u16(),
        &[401],
    );

    let manifest = c
        .get(t.url(&format!("/redaction/manifest/{}", "0".repeat(64))))
        .header("x-api-key", &t.api_key)
        .send()
        .await
        .expect("manifest");
    m.record(
        "GET /redaction/manifest/{h}",
        "unknown 4xx",
        manifest.status().as_u16(),
        &[404, 400, 403],
    );

    // ── Anchors ───────────────────────────────────────────────────────────────
    let anchors_noauth = c
        .get(t.url("/anchors"))
        .send()
        .await
        .expect("anchors noauth");
    m.record(
        "GET /anchors",
        "no auth 401",
        anchors_noauth.status().as_u16(),
        &[401],
    );

    let anchors = c
        .get(t.url("/anchors"))
        .header("x-api-key", &t.api_key)
        .send()
        .await
        .expect("anchors");
    m.record(
        "GET /anchors",
        "authed 200",
        anchors.status().as_u16(),
        &[200],
    );

    let anchor_unknown = c
        .get(t.url(&format!("/anchors/{}", uniq("noanchor"))))
        .header("x-api-key", &t.api_key)
        .send()
        .await
        .expect("anchor unknown");
    m.record(
        "GET /anchors/{id}",
        "unknown 4xx",
        anchor_unknown.status().as_u16(),
        &[404, 400],
    );

    // ── Verdict ───────────────────────────────────────────────────────────────
    m.print();
    let mode = if t.in_proc { "in-proc" } else { "container" };
    assert_eq!(
        m.fails(),
        0,
        "[{mode}] {} endpoint/invariant checks failed — see matrix above",
        m.fails()
    );
}
