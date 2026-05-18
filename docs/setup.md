# Olympus — Quick Setup Guide

Get Olympus running locally with **one command**.

## Prerequisites

| Requirement | Notes |
|-------------|-------|
| **PostgreSQL 18** | Recommended local service on `127.0.0.1:5432`; PostgreSQL 16+ supported |
| **Python 3.10-3.13** | [python.org](https://www.python.org/downloads/) |
| **Rust / Cargo** | Required by `maturin` to build the `olympus_core` extension. Install via [rustup.rs](https://rustup.rs) |
| **Node.js 20.19+ or 22.12+** | Required for the public UX dev server. Install via [nodejs.org](https://nodejs.org/) |

Docker is optional for packaging and integration demos. Native Windows
development uses local PostgreSQL, `.env.local`, a repo-local virtual
environment, migrations, API server, and UX server.

### Optional: Protocol Buffers Compiler (`protoc`)

`protoc` is **only** required when **regenerating gRPC/protobuf stubs** for
the Go sequencer service (`services/sequencer-go/`) or the Rust CD-HS-ST
service (`services/cdhs-smf-rust/`).  You do **not** need `protoc` to run
the Python API.

| Platform | Install command |
|----------|----------------|
| macOS | `brew install protobuf` |
| Debian/Ubuntu | `sudo apt install -y protobuf-compiler` |
| Other | [github.com/protocolbuffers/protobuf/releases](https://github.com/protocolbuffers/protobuf/releases) |

`setup-unix.sh` will warn (but not fail) if `protoc` is absent.

---

## Windows

For the full Windows app path, double-click:

```text
Olympus-Start-Windows.cmd
```

That launcher runs the native Windows path, starts the API and public UX, and
does not run Docker commands.

For advanced setup, open **PowerShell** in the repository root and run:

```powershell
.\scripts\doctor.ps1
.\scripts\setup-windows.ps1
.\scripts\dev.ps1
```

If the script was downloaded from the internet and PowerShell reports that it
is not digitally signed, unblock only this file and rerun it:

```powershell
Unblock-File -LiteralPath .\scripts\setup-windows.ps1
```

If your execution policy blocks scripts, first allow the current user to run local scripts:

```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
```

### Windows Native Scripts

| Script | Description |
|--------|-------------|
| `scripts\doctor.ps1` | Checks prerequisites, local PostgreSQL, `.venv`, `.env.local`, Alembic, and rejects Docker-shaped native hostnames. |
| `scripts\setup-windows.ps1` | Creates `.venv`, installs Python dependencies, creates `.env.local`, and installs UI dependencies. |
| `scripts\dev.ps1` | Loads `.env.local`, runs Alembic, starts FastAPI on `127.0.0.1:8000`, and starts Vite from `app/public-ui`. |

---

## macOS / Linux

Open a terminal in the repository root and run:

```bash
chmod +x setup-unix.sh   # only needed once
./setup-unix.sh
```

To use a custom database username and password:

```bash
./setup-unix.sh --db-user myuser --db-password s3cr3t
```

### Unix Options

| Flag | Default | Description |
|------|---------|-------------|
| `--db-user USER` | `olympus` | PostgreSQL username for the Docker container and `DATABASE_URL`. |
| `--db-password PASS` | `olympus` | PostgreSQL password. Use a strong value for any non-local environment. |
| `--skip-docker` | — | Skip the PostgreSQL container step (use when Postgres is already running). |
| `--skip-start` | — | Set everything up but do not start the API at the end. |

---

## What the scripts do

The native Windows scripts perform these core steps:

1. **Check prerequisites** — Python 3.10-3.13, Node, npm, Git, `psql`, local PostgreSQL, `.venv`, `.env.local`, and Alembic.
2. **Set environment variables** — `.env.local` is created from `.env.local.example` and loaded by native scripts only.
3. **Create virtual environment** — `.venv/` in the repo root.
   Re-running is safe: an existing venv is reused.
4. **Install dependencies** — `requirements.txt`, `requirements-dev.txt`, and the `olympus` package.
5. **Run Alembic migrations** — Brings the database schema up to date.
6. **Install public UX dependencies** — `npm ci` in `app/public-ui`.
7. **Start the app** — API on `http://localhost:8000`, public UX on `http://localhost:5173`.

Docker-specific values live in `.env.docker.example` and are used only by the
optional Docker Compose path.

---

## After setup

| URL | Description |
|-----|-------------|
| `http://localhost:5173` | Olympus public UX |
| `http://localhost:8000` | Olympus REST API |
| `http://localhost:8000/docs` | Interactive API documentation (Swagger UI) |
| `http://localhost:8000/redoc` | Alternative API docs (ReDoc) |

---

## Re-running / day-to-day use

The scripts are **idempotent** — you can run them again at any time to bring the environment back to a good state (e.g., after a reboot).

If you only want to restart the API (Postgres still running, venv already set up):

**Windows:**
```text
Double-click Olympus-Start-Windows.cmd
```

**Unix/macOS:**
```bash
source .venv/bin/activate
uvicorn api.main:app --reload --host 0.0.0.0 --port 8000
```

---

## Troubleshooting

### Docker container fails to start
```bash
docker logs olympus-postgres
```

### Port 5432 already in use
Stop any local PostgreSQL service, or pass a different port:
```bash
docker run --name olympus-postgres \
  -e POSTGRES_USER=olympus -e POSTGRES_PASSWORD=olympus -e POSTGRES_DB=olympus \
  -p 5433:5432 -d postgres:18
```
Then update `DATABASE_URL` to use port `5433`.

### Alembic migration fails
Make sure `DATABASE_URL` is correct and PostgreSQL is accepting connections:
```bash
python -c "import psycopg; psycopg.connect('postgresql://olympus:olympus@localhost:5432/olympus'); print('OK')"
```

### `OLYMPUS_INGEST_SIGNING_KEY` lost after reboot
The key is printed once during setup with a warning to save it.
Copy it into your `.env` file before closing the terminal:
```
OLYMPUS_INGEST_SIGNING_KEY=<the-key-printed-during-setup>
```
Both scripts also write a `.env` file automatically on first run.

### Windows: execution policy error
```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
```

For a downloaded local copy, prefer the narrower fix:

```powershell
Unblock-File -LiteralPath .\setup-windows.ps1
```

### Python version too old
Install Python 3.10 or later from [python.org](https://www.python.org/downloads/).
On macOS you can also use Homebrew:
```bash
brew install python@3.12
```
