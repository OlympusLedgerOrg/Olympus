# serena

Project-scoped [Serena](https://github.com/oraios/serena) MCP server: LSP-backed
symbol navigation and symbol-scoped edits. `.mcp.json` registers it and
`AGENTS.md` says when to reach for it; this file owns the setup.

## Install into its own venv

Do **not** install it into the shared user site-packages. `serena-agent` 2.1.0
pins `mcp==2.2.0` and `click==8.3.1`, while the semgrep 1.168.0 installed there
pins `mcp==1.23.3` and `click~=8.1.8`. A `pip install --user serena-agent`
upgrades those two and leaves semgrep's dependency view broken — that is not
hypothetical, it happened while wiring this up and had to be reverted.

Windows (Git Bash):

```bash
python -m venv "$LOCALAPPDATA/serena-venv"
"$LOCALAPPDATA/serena-venv/Scripts/python.exe" -m pip install serena-agent
setx SERENA_BIN "$LOCALAPPDATA\\serena-venv\\Scripts\\serena.exe"
```

POSIX: the same venv with `bin/serena` instead of `Scripts/serena.exe`, and
export `SERENA_BIN` from your shell profile. `serena init` is optional: the
global `~/.serena/serena_config.yml` is reused when present, and a missing
project config is auto-generated on first start (`Saving project configuration
to <repo>\.serena\project.yml`). `.serena/` is gitignored here.

## Knobs

| Variable              | Default          | Meaning                                                                                       |
| --------------------- | ---------------- | --------------------------------------------------------------------------------------------- |
| `SERENA_BIN`          | `serena` on PATH | the Serena executable the launcher spawns                                                     |
| `SERENA_NODE`         | `node`           | interpreter for the launcher; set it when a client's PATH lacks node (same as `WISEREPO_NODE`) |
| `SERENA_PROJECT_ROOT` | this checkout    | overrides the pinned cwd; a relative value resolves against the caller's cwd                   |

## Why the launcher pins the cwd

`.mcp.json` runs `tools/serena/bin/mcp-launcher.mjs`, which starts
`serena start-mcp-server --context ide --project-from-cwd` with its working
directory pinned to this checkout.

Both flags depend on that. Serena resolves its project from the process's cwd
(`--project-from-cwd` walks up to the nearest `.git`), and an MCP client spawns
`command` in **its own** directory — for a GUI/IDE client, frequently not this
repo. Launched that way Serena starts with no project activated (its log reads
`No project root found from cwd=…`) and every symbol tool fails until someone
calls `activate_project`. `--context ide` is Serena's single-project context, so
the project is fixed at startup rather than switched mid-session.

The web dashboard follows `~/.serena/serena_config.yml`, which has
`web_dashboard: true` and `web_dashboard_open_on_launch: false`: it listens on
127.0.0.1 and opens no browser.

## Tests

```bash
pnpm serena:test        # node --test tools/serena/test/mcp-launcher.test.mjs
```

Wired into `pnpm tooling:check` and the verify gate's `tools/<name>/` row. The
argv, root-resolution and missing-binary tests always run. The live handshake
test skips unless `SERENA_BIN` points at an installed Serena, so locally it
runs only for a developer who has one. CI does not skip it: the
`serena-handshake` job in `.github/workflows/ci.yml` installs `serena-agent`
into a throwaway venv, exports `SERENA_BIN`, and runs this suite, so the
handshake cannot rot behind a skip.
