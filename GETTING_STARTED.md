# Getting Started with Olympus

## Prerequisites

- [Python 3.10+](https://python.org/downloads/)
- [Docker](https://docs.docker.com/get-docker/) (for the PostgreSQL database)

---

## One-Command Setup

### Windows — Double-click to start

```
run.bat
```

Or from Command Prompt / PowerShell:

```cmd
run.bat
```

No execution-policy changes required.

---

### macOS / Linux

```bash
chmod +x run.sh && ./run.sh
```

---

## What it does

Both scripts automatically:

1. Start a PostgreSQL container via Docker (`olympus-postgres` on port 5432)
2. Create a Python virtual environment (`.venv/`)
3. Install all dependencies
4. Generate a `.env` file with `DATABASE_URL` and `OLYMPUS_INGEST_SIGNING_KEY`
5. Run Alembic database migrations
6. Start the API server at **http://localhost:8000**

The scripts are **idempotent** — safe to re-run at any time.

---

## Access

| URL | Description |
|-----|-------------|
| http://localhost:8000 | Olympus REST API |
| http://localhost:8000/docs | Interactive API docs (Swagger UI) |
| http://localhost:8000/redoc | Alternative API docs (ReDoc) |

---

## Options

### Unix/macOS (`run.sh`)

| Flag | Description |
|------|-------------|
| `--skip-docker` | Skip the PostgreSQL container step (use if Postgres is already running) |
| `--skip-start` | Set everything up but do not start the API |
| `--db-user USER` | Custom PostgreSQL username (default: `olympus`) |
| `--db-pass PASS` | Custom PostgreSQL password (default: `olympus`) |

### Windows (`run.bat`)

Set `DATABASE_URL` in your environment before running to skip the Docker step:

```cmd
set DATABASE_URL=postgresql://myuser:mypass@localhost:5432/olympus
run.bat
```

---

## Day-to-day use (after first setup)

**Windows:**
```cmd
run.bat
```

**macOS/Linux:**
```bash
./run.sh
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
./run.sh --skip-docker
```

**Alembic migration fails** — confirm Postgres is reachable:
```bash
python -c "import psycopg; psycopg.connect('postgresql://olympus:olympus@localhost:5432/olympus'); print('OK')"
```

**`OLYMPUS_INGEST_SIGNING_KEY` lost after reboot** — the key is saved to `.env` on first run. Check that file.

For more detailed setup options, see [setup.md](setup.md).
