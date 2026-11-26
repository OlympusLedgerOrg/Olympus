# verify-gate

Run the repo's own checks for whatever a change actually touched, stop at the
first failure, and name the tier the fix belongs to.

```bash
node tools/verify-gate/verify.mjs                 # working tree vs HEAD
node tools/verify-gate/verify.mjs --base main     # a branch vs main
node tools/verify-gate/verify.mjs --dry-run       # the plan, nothing executed
node tools/verify-gate/verify.mjs --fast          # fmt/lint/typecheck, no tests
node tools/verify-gate/verify.mjs --json
```

Exit codes: `0` every check passed, `1` a check failed (escalate), `2` usage or
git error.

## Why

AGENTS.md documents one correct invocation per scope, and several of them are
not reachable from the repo root: `cargo fmt --all` skips `verifiers/rust`,
`pnpm --filter` never matches a path, eslint from outside `app/public-ui`
reports success while ignoring the directory, and `verifiers/javascript` is not
a workspace member. An agent that edits three files and runs "the tests" can be
wrong in four different ways without seeing an error. This encodes that table.

## What runs for what

| Touched                          | Checks                                                                                                                         |
| -------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| anything                         | `prettier --check` over the repo glob, `node scripts/check-license-headers.mjs`; `taplo format --check` when a `.toml` changed |
| `src-tauri/`, `crates/<pkg>/`    | `cargo fmt --all --check`, `cargo clippy -p <pkg> -- -D warnings`, `cargo test -p <pkg>`                                       |
| root `Cargo.toml` / `Cargo.lock` | the same, at `--workspace`                                                                                                     |
| `verifiers/rust/`                | fmt, clippy and tests via `--manifest-path`; the fuzz workspace gets `cargo check`                                             |
| `clients/cli/`                   | fmt, clippy `--all-features`, `cargo test --locked … --all-features`                                                           |
| `clients/python/`                | `python -m pytest -q clients/python/tests`                                                                                     |
| `app/public-ui/`                 | from inside the directory: `tsc -b`, `eslint . --max-warnings 0`, `vitest run` (local binaries, not `pnpm exec`)               |
| `verifiers/javascript/`          | `npm test` from inside the directory                                                                                           |
| `pg-embed-local/`                | its library tests only, as the CI job does                                                                                     |
| `tools/<name>/`                  | that tool's own `*.test.mjs` files                                                                                             |

`--fast` keeps the compile, lint and type checks and drops the test suites. It
catches a broken build, not a broken behaviour — not a substitute for a full run
before a commit that matters.

## Why the binaries, not `pnpm`

`pnpm <script>` verifies the dependency graph before running, and when the
lockfile disagrees with the installed tree it installs to "fix" it — rewriting
`pnpm-lock.yaml`. A verification gate that dirties the tree it is checking is
not a gate, so Prettier, taplo, tsc, eslint and vitest are invoked through their
`node` entry points in `node_modules`; cargo, npm and python are unaffected.

## First failure is the verdict

The gate does not collect every error. A failed check means the change was not
finished by the tier that produced it, so the remaining scopes would only spend
more time proving that. It prints the failing scope, the exact command and its
exit code, then:

```
escalate: true, tier: top
```

`top` when a touched file sits under a policy critical prefix (`crates/`,
`src-tauri/`, `proofs/`, `verifiers/`, `clients/`, `migrations/`), `mid`
otherwise. Local is never the answer: a failure is precisely the evidence that
the local tier could not do it.

## Tests

```bash
node --test tools/verify-gate/verify.test.mjs
```

The plan is pure and the runner is injectable, so the tests assert the exact
command per scope and prove the stop-on-first-failure behaviour without invoking
cargo, pnpm or npm.
