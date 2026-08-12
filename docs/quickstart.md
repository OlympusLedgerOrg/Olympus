# Olympus Quick Start

Olympus v0.10.0 is a **Tauri 2 desktop application** with an embedded Axum HTTP
server and embedded PostgreSQL (`pg_embed`). There is no separate Python
service, no Docker requirement, and no external database to provision for local
use.

> **Release status:** v0.10 installer assets are not currently published. The
> GitHub Releases page may contain older demonstration builds; contributors
> should build the current application from source.

---

## Build from source

### Prerequisites

| Tool | Why | How |
|---|---|---|
| Rust **1.94 or newer** | Tauri + Axum + arkworks; the resolved SQLx 0.9 toolchain requires Rust 1.94, while `pg-embed-local` also uses edition 2024 | `rustup update stable` |
| Node.js ≥ 22.12 and `pnpm` 11.1.2 | Frontend build | `corepack enable && corepack prepare pnpm@11.1.2 --activate` |
| Tauri CLI 2 | Provides the `cargo tauri` command | `cargo install tauri-cli --version "^2.0.0" --locked` |
| Tauri 2 system dependencies | WebView + native bundlers | see [Tauri prerequisites](https://v2.tauri.app/start/prerequisites/) |
| `circom` ≥ 2.2 | Only needed to generate real ZK artifacts | [iden3/circom releases](https://github.com/iden3/circom/releases) |

Windows additionally needs the WiX toolset (for MSI) and NSIS (for the setup
`.exe`) when building installer bundles.

Linux bundle builds additionally need `libwebkit2gtk-4.1-dev`,
`libsoup-3.0-dev`, `libssl-dev`, `libgtk-3-dev`, `librsvg2-dev`, `patchelf`, and
`appimagetool`.

### Clone and install dependencies

```bash
git clone https://github.com/OlympusLedgerOrg/Olympus.git
cd Olympus
pnpm install --frozen-lockfile
```

### Run in development

A fresh clone contains placeholder ZK artifacts. That is expected for ordinary
UI and contributor development. Olympus intentionally treats an unset or
unrecognized `OLYMPUS_ENV` as production, so development mode must be explicit.

**Bash / Zsh:**

```bash
OLYMPUS_ENV=development OLYMPUS_API_PORT=3737 cargo tauri dev
```

**PowerShell:**

```powershell
$env:OLYMPUS_ENV = "development"
$env:OLYMPUS_API_PORT = "3737"
cargo tauri dev
```

The frontend hot-reloads via Vite; the Rust process restarts on `src-tauri/`
changes. Placeholder artifacts are permitted in development, but `/zk/prove`
will return 503 until real circuit artifacts are generated.

### One-time ZK setup for real proofs or production bundles

This step is **not required to reach the UI in development**. Run it only when
you need `/zk/prove` to produce real proofs or when preparing a production
bundle.

There are two scripts, sharing the same Phase 1 input
(`proofs/keys/powersOfTau28_hez_final_20.ptau`):

- **`proofs/setup_circuits.sh`** — fast all-in-one path for development. One
  dev Phase 2 contribution per circuit plus automatic `export_ark_zkey`
  conversion to the runtime `.ark.zkey` format. Not production-safe, because a
  single contributor holds all the entropy.
- **`proofs/phase2_ceremony.sh prepare | contribute | verify | finalize`** —
  multi-contributor Phase 2 ceremony for v1.0 releases. Each contributor adds
  independent entropy on their own machine; the coordinator verifies the chain
  and finalizes with an optional public-randomness beacon.

The Hermez Phase 1 file is checksum-verified (BLAKE2b `89a66eb5…`) on every
run. You can either let the script download it or drop your own copy at
`proofs/keys/powersOfTau28_hez_final_20.ptau` first. See
[`proofs/README.md`](../proofs/README.md) for the full pipeline.

For files it can open and read, the production startup placeholder detector
rejects relevant `.wasm`, `.r1cs`, or `.ark.zkey` files beginning with
`PLACEHOLDER`, and verification-key JSON beginning with `{"placeholder`. It
does not enforce a fixed file-size threshold or reject missing, unreadable, or
shorter-than-prefix files; this is not comprehensive artifact validation.
Generate the real artifacts:

```bash
cd proofs
bash setup_circuits.sh            # ~10-30 min — compiles + Phase 2 dev keys
```

Then convert each snarkjs `_final.zkey` to arkworks format and stage it into
`proofs/keys/` alongside the `.wasm` and `.r1cs`:

```bash
cd ..
cargo build --release --bin export_ark_zkey
EXPORTER=target/release/export_ark_zkey

for c in document_existence non_existence \
         unified_canonicalization_inclusion_root_sign federation_quorum; do
  cp proofs/build/${c}_js/${c}.wasm proofs/keys/${c}.wasm
  cp proofs/build/${c}.r1cs        proofs/keys/${c}.r1cs
  "$EXPORTER" proofs/build/${c}_final.zkey proofs/keys/${c}.ark.zkey
done

ls -lh proofs/keys/*.wasm proofs/keys/*.r1cs proofs/keys/*.ark.zkey
```

Generated files are normally MB-range rather than the roughly 60-byte committed
stubs, but size is only a heuristic. Padding or appending bytes while preserving
the expected prefix does not bypass the placeholder-prefix check.
(`setup_circuits.sh` already stages these files into `proofs/keys/`; the loop
above is the explicit equivalent.)

> `unified_canonicalization_inclusion_root_sign` is the historical artifact
> stem compiled by `setup_circuits.sh`; its live R1CS proves a structured
> section commitment plus Merkle/SMT inclusion, not canonicalization or a
> signature. The API exposes that narrower proof as
> `unified_section_commitment_inclusion_root` and the RISC Zero + Groth16
> composite as `unified_canonicalization_inclusion_root`. Its verification key
> is generated by the trusted setup (gitignored until then), so either path's
> Groth16 verification works only after a real ceremony run for that circuit.

### Build a production bundle

Generate real ZK artifacts first. Before running in production, configure stable,
independent 32-byte-hex values for both `OLYMPUS_INGEST_SIGNING_KEY` and
`OLYMPUS_REDACTION_BLIND_SECRET` (alongside the persisted
`OLYMPUS_BJJ_AUTHORITY_KEY`). The blind secret is required for object-redaction
ingest and issuance; keeping it independent ensures a BJJ-key compromise cannot
retroactively de-hide historical redactions. Then build with production mode
explicit:

**Bash / Zsh:**

```bash
OLYMPUS_ENV=production cargo tauri build
```

**PowerShell:**

```powershell
$env:OLYMPUS_ENV = "production"
cargo tauri build
```

Outputs land under `target/release/bundle/` — `msi/` and `nsis/` on Windows,
`deb/`, `rpm/`, `appimage/` on Linux. The `bundle.resources` glob embeds the ZK
artifacts from `proofs/keys/`, so a fresh install needs no post-install setup.

---

## First-launch sanity checks

Once the development app is running:

1. **Frontend** opens to a verify page; the WhoAmI chip in the header shows the
   bootstrap user and effective scopes.
2. **API health**: `curl http://127.0.0.1:3737/health` returns 200 when you use
   the pinned development port above.
3. **Authentication**:
   `curl -H "X-API-Key: <bootstrap_key>" http://127.0.0.1:3737/admin/users`
   returns the bootstrap user as JSON. See
   [Where `<bootstrap_key>` comes from](#where-bootstrap_key-comes-from) below.
4. **ZK verify**: after generating real artifacts, a small `POST /zk/verify`
   with one of the test vectors in `verifiers/test_vectors/vectors.json` should
   return 200 with `{"valid": true}`.

If any of these fail, see [`development.md`](development.md#troubleshooting).

### Where `<bootstrap_key>` comes from

On the very first launch against an empty database, bootstrap mints a system
admin API key (an `oly_…` string) and shows it — together with the Baby Jubjub
authority private key — in a one-shot "save these now" modal
(`InitialSecretsModal`). That modal is the only place the raw key is ever
displayed: the database stores just its BLAKE3 hash, and the key is
deliberately never written to logs, stdout, or stderr, because process logs get
scraped by journald, CI runners, and shell redirects. Copy it out of the modal
and paste it into the `curl` above in place of `<bootstrap_key>`.

The modal hands the key to the frontend's in-memory key store, so the Admin and
Ingest pages are pre-filled for the rest of that session. It is **not**
persisted: `app/public-ui/src/lib/storage.ts` keeps API keys and the admin key
in module-level variables only, never in `localStorage`, `sessionStorage`,
`IndexedDB`, or cookies (audit F-4). A page reload, a webview restart, or a Vite
hot-reload discards them and you paste the key back in. Only the operator's
"I have saved these" acknowledgement is stored persistently — that flag is not
secret material.

So the modal is the one chance to copy the key. `curl` does not share the
frontend's memory either way, so command-line checks always need the copied
value.

If you dismissed the modal without saving, the key is recoverable as long as you
have the BJJ authority key hex (from that same modal, or pinned via
`OLYMPUS_BJJ_AUTHORITY_KEY`) — it is a pure derivation, not a random secret:

```text
bootstrap_key = "oly_" || hex( blake3( "OLY:APIKEY:V1" || bjj_private_key_bytes ) )
```

That is `derive_api_key_from_bjj` in
[`src-tauri/src/api/middleware/auth.rs`](../src-tauri/src/api/middleware/auth.rs);
recomputing it off the same 32 bytes always reproduces the same key.

If both secrets are lost, mint a replacement through an account that still has
`admin` scope (`POST /admin/users/{user_id}/keys`), or set `OLYMPUS_ADMIN_KEY` and
use the `x-admin-key` operator path — that env gate exists precisely so losing
every database-backed admin key is recoverable. Re-bootstrapping is **not** the
answer for any database holding real records: the ledger is append-only, and
dropping it destroys committed records and every proof that referenced them.
Deleting the data directory and letting bootstrap run again is only appropriate
for a throwaway development database you are willing to lose entirely.

Note that `<bootstrap_key>` authenticates via the `X-API-Key` header as an
`admin`-scoped API key. It is not automatically the `x-admin-key` operator
secret — that header is compared against `OLYMPUS_ADMIN_KEY` and is unset by
default.
