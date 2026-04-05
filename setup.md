# Olympus — Quick Setup Guide

Get Olympus running locally with **one command**.

## Prerequisites

| Requirement | Notes |
|-------------|-------|
| **Docker** | [docker.com/get-docker](https://docs.docker.com/get-docker/) |
| **Python 3.10+** | [python.org](https://www.python.org/downloads/) |

No other software needs to be installed manually; both scripts handle everything else (PostgreSQL, virtual environment, migrations, API server).

---

## Windows

Open **PowerShell** (not Command Prompt) in the repository root and run:

```powershell
.\setup-windows.ps1
```

To use a custom database username and password:

```powershell
.\setup-windows.ps1 -DbUser myuser -DbPassword s3cr3t
```

If your execution policy blocks scripts, first allow the current user to run local scripts:

```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
```

### Windows Options

| Flag | Default | Description |
|------|---------|-------------|
| `-DbUser` | `olympus` | PostgreSQL username for the Docker container and `DATABASE_URL`. |
| `-DbPassword` | `olympus` | PostgreSQL password. Use a strong value for any non-local environment. |
| `-SkipDocker` | — | Skip the PostgreSQL container step (use when Postgres is already running). |
| `-SkipStart` | — | Set everything up but do not start the API at the end. |

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

Both scripts perform the same steps in order:

1. **Check prerequisites** — Docker and Python 3.10+.
2. **Start PostgreSQL** — Launches `olympus-postgres` container on port 5432.  
   Re-running is safe: an already-running container is reused.
3. **Set environment variables** — `DATABASE_URL` and `OLYMPUS_INGEST_SIGNING_KEY`.  
   A `.env` file is written to the repo root so values persist between terminal sessions.
4. **Create virtual environment** — `.venv/` in the repo root.  
   Re-running is safe: an existing venv is reused.
5. **Install dependencies** — `requirements.txt`, `requirements-dev.txt`, and the `olympus` package.
6. **Run Alembic migrations** — Brings the database schema up to date.
7. **Start the API** — `uvicorn api.app:app --reload` on `http://localhost:8000`.

---

## After setup

| URL | Description |
|-----|-------------|
| `http://localhost:8000` | Olympus REST API |
| `http://localhost:8000/docs` | Interactive API documentation (Swagger UI) |
| `http://localhost:8000/redoc` | Alternative API docs (ReDoc) |

---

## Re-running / day-to-day use

The scripts are **idempotent** — you can run them again at any time to bring the environment back to a good state (e.g., after a reboot).

If you only want to restart the API (Postgres still running, venv already set up):

**Windows:**
```powershell
.\.venv\Scripts\Activate.ps1
uvicorn api.app:app --reload --host 0.0.0.0 --port 8000
```

**Unix/macOS:**
```bash
source .venv/bin/activate
uvicorn api.app:app --reload --host 0.0.0.0 --port 8000
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
  -p 5433:5432 -d postgres:16
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

### Python version too old
Install Python 3.10 or later from [python.org](https://www.python.org/downloads/).  
On macOS you can also use Homebrew:
```bash
brew install python@3.12
```
