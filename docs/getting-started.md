# Getting Started with Olympus

## Prerequisites

- [Python 3.10-3.13](https://python.org/downloads/)
- PostgreSQL 18 running locally on `127.0.0.1:5432` (PostgreSQL 16+ supported)
- [Node.js 20.19+ or 22.12+](https://nodejs.org/) (for the public UX)

---

## One-Command Setup

### Windows

Double-click this file in the repository root:

```text
Olympus-Start-Windows.cmd
```

For advanced setup, open PowerShell in the repository root and run:

```powershell
.\scripts\doctor.ps1
.\scripts\setup-windows.ps1
.\scripts\dev.ps1
```

---

### macOS / Linux

```bash
chmod +x setup-unix.sh && ./setup-unix.sh
```

---

## What it does

The Windows native path automatically:

1. Checks Python, Node, npm, Git, `psql`, local PostgreSQL, `.venv`, `.env.local`, and Alembic.
2. Creates a Python virtual environment (`.venv/`).
3. Installs Python dependencies.
4. Creates `.env.local` from `.env.local.example`.
5. Installs the public UX dependencies.
6. Runs Alembic database migrations.
7. Starts the UX at **http://127.0.0.1:5173** and the API at **http://127.0.0.1:8000**.

Docker remains available for optional packaging and integration demos, but the
Windows launcher does not run Docker commands.

The scripts are **idempotent** — safe to re-run at any time.

---

## Access

| URL | Description |
|-----|-------------|
| http://localhost:5173 | Olympus public UX |
| http://localhost:8000 | Olympus REST API |
| http://localhost:8000/docs | Interactive API docs (Swagger UI) |
| http://localhost:8000/redoc | Alternative API docs (ReDoc) |

---

## Options

### Unix/macOS (`setup-unix.sh`)

| Flag | Description |
|------|-------------|
| `--skip-docker` | Skip the PostgreSQL container step (use if Postgres is already running) |
| `--skip-start` | Set everything up but do not start the API |
| `--db-user USER` | Custom PostgreSQL username (default: `olympus`) |
| `--db-pass PASS` | Custom PostgreSQL password (default: `olympus`) |

### Windows (`setup-windows.ps1`)

Use the native script path for custom setup behavior:

```powershell
.\scripts\setup-windows.ps1
.\scripts\dev.ps1
```

The native scripts use `.env.local` only. Docker-specific values belong in
`.env.docker.example` and `.env`.

---

## Day-to-day use (after first setup)

**Windows:**
```text
Double-click Olympus-Start-Windows.cmd
```

**macOS/Linux:**
```bash
./setup-unix.sh
```

The script reuses the existing local virtual environment and dependency
installations. PostgreSQL should already be running locally.

---

## Troubleshooting

**Native doctor reports `psql not found`** - add your PostgreSQL `bin`
directory to PATH, then reopen the terminal.

**Port 5432 is not accepting connections** - start the local PostgreSQL 18
service and rerun `.\scripts\doctor.ps1`.

**Alembic migration fails** — confirm Postgres is reachable:
```bash
python -c "import psycopg; psycopg.connect('postgresql://olympus:olympus@localhost:5432/olympus'); print('OK')"
```

**Docker container fails to start** - Docker is optional. See
`docs/quickstart.md` for the optional Docker setup.

For more detailed setup options, see [setup.md](setup.md).
