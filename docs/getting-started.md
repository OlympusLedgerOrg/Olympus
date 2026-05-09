# Getting Started with Olympus

## Prerequisites

- [Python 3.10-3.13](https://python.org/downloads/)
- [Docker](https://docs.docker.com/get-docker/) (for the PostgreSQL database)
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
.\setup-windows.ps1
```

---

### macOS / Linux

```bash
chmod +x setup-unix.sh && ./setup-unix.sh
```

---

## What it does

Both setup scripts automatically:

1. Start a PostgreSQL container via Docker (`olympus-postgres` on port 5432)
2. Create a Python virtual environment (`.venv/`)
3. Install all dependencies
4. Generate a `.env` file with `DATABASE_URL` and `OLYMPUS_INGEST_SIGNING_KEY`
5. Run Alembic database migrations
6. Install the public UX dependencies
7. Start the UX at **http://localhost:5173** and the API at **http://localhost:8000**

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

Use PowerShell parameters for custom setup behavior:

```powershell
.\setup-windows.ps1 -SkipStart -ForceLocalDbUrl
```

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

The script reuses the existing container and virtual environment — it only re-runs what is needed.

---

## Troubleshooting

**Docker container fails to start**
```bash
docker logs olympus-postgres
```

**Port 5432 already in use** — stop your local PostgreSQL or pass a custom URL:
```bash
export DATABASE_URL=postgresql://olympus:olympus@localhost:5433/olympus
./setup-unix.sh --skip-docker
```

**Alembic migration fails** — confirm Postgres is reachable:
```bash
python -c "import psycopg; psycopg.connect('postgresql://olympus:olympus@localhost:5432/olympus'); print('OK')"
```

**`OLYMPUS_INGEST_SIGNING_KEY` lost after reboot** — the key is saved to `.env` on first run. Check that file.

For more detailed setup options, see [setup.md](setup.md).
