# `secrets/` — local Docker secrets for self-hosted deployments

This directory holds **file-backed Docker secrets** referenced by
`docker-compose.yml` (and `docker-compose.federation.yml`).

Files in here are **never** committed — see the repo `.gitignore`. The only
files tracked under `secrets/` are this README and `.gitkeep`.

## Bootstrapping

Run from the repository root:

```bash
./scripts/bootstrap.sh
```

That script will:

1. Generate `secrets/db_password` (mode 600) if it doesn't already exist.
2. Copy `.env.example` → `.env` if `.env` doesn't already exist, and fill
   in the `POSTGRES_PASSWORD` / `DATABASE_URL` / `PSYCOPG_URL` /
   `OLYMPUS_NODE_REHASH_GATE_SECRET` / `OLYMPUS_SEQUENCER_TOKEN` values
   that the stack refuses to start without.

It is idempotent — re-running it never overwrites an existing secret.

## How the secret is consumed

`docker-compose.yml` declares:

```yaml
secrets:
  db_password:
    file: ./secrets/db_password
```

…and three services mount it at `/run/secrets/db_password`:

| Service        | Reads it via                      |
| -------------- | --------------------------------- |
| `db`           | `POSTGRES_PASSWORD_FILE`          |
| `app`          | `DATABASE_PASSWORD_FILE`          |
| `sequencer-go` | `SEQUENCER_DB_PASSWORD_FILE`      |

This avoids ever putting the password into a process env var
(`docker inspect` and `/proc/<pid>/environ` would otherwise expose it).

## Rotating the password

1. Stop the stack: `docker compose down`.
2. Replace `secrets/db_password` with the new password.
3. Update the database role's password to match:
   `docker compose run --rm db psql ... -c "ALTER USER ... PASSWORD '<new>';"`
   (or do it before bringing the stack down).
4. Update `.env` so `POSTGRES_PASSWORD`, `DATABASE_URL`, and `PSYCOPG_URL`
   stay in sync with the new value.
5. `docker compose up -d`.
