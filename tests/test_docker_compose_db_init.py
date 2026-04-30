import os
import re
from pathlib import Path

import yaml


EXPECTED_FEDERATION_NODES = 3
REPO_ROOT = Path(__file__).parent.parent


def _load_primary_compose() -> dict:
    return yaml.safe_load((REPO_ROOT / "docker-compose.yml").read_text(encoding="utf-8"))


def test_primary_docker_compose_starts_api_without_migrations():
    """
    The primary compose stack must start uvicorn directly without a separate
    migration step.  Schema is created automatically at first request via
    StorageLayer.init_schema() and Base.metadata.create_all().
    """
    # Verify docker-compose.yml references startup.sh
    compose_text = (REPO_ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    assert "startup.sh" in compose_text, "docker-compose.yml app command must reference startup.sh"

    # Verify startup.sh runs uvicorn and does NOT call alembic
    startup = (REPO_ROOT / "scripts" / "startup.sh").read_text(encoding="utf-8")
    uvicorn_match = re.search(
        r"exec\s+uvicorn\s+api\.main:app\s+--host\s+0\.0\.0\.0\s+--port\s+8000", startup
    )
    alembic_match = re.search(r"python\s+-m\s+alembic\s+upgrade\s+head", startup)

    assert uvicorn_match is not None, "startup.sh must call 'exec uvicorn api.main:app ...'"
    assert alembic_match is None, (
        "startup.sh must not call 'alembic upgrade head'; "
        "schema is created automatically by init_schema() and Base.metadata.create_all()"
    )


def test_federation_docker_compose_starts_each_api_node_without_migrations():
    compose = (REPO_ROOT / "docker-compose.federation.yml").read_text(encoding="utf-8")

    assert "alembic upgrade head" not in compose, (
        "docker-compose.federation.yml must not call 'alembic upgrade head'; "
        "schema is created automatically by init_schema() and Base.metadata.create_all()"
    )
    uvicorn_matches = list(
        re.finditer(
            r"exec\s+uvicorn\s+api\.main:app\s+--host\s+0\.0\.0\.0\s+--port\s+8000", compose
        )
    )

    assert len(uvicorn_matches) == EXPECTED_FEDERATION_NODES


# ---------------------------------------------------------------------------
# Regression tests for migration-scripts issues
# ---------------------------------------------------------------------------


def test_alembic_ini_does_not_default_to_sqlite():
    """alembic.ini must not fall back to sqlite — production uses PostgreSQL."""
    ini = (REPO_ROOT / "alembic.ini").read_text(encoding="utf-8")
    assert "sqlite" not in ini.lower(), "alembic.ini still contains a sqlite URL"


def test_alembic_env_normalises_to_psycopg_driver():
    """env.py must convert any postgresql URL to the psycopg v3 sync driver."""
    env_py = (REPO_ROOT / "alembic" / "env.py").read_text(encoding="utf-8")
    assert "postgresql+psycopg://" in env_py, (
        "env.py should normalise DATABASE_URL to postgresql+psycopg://"
    )
    # The regex replacement target must NOT be bare 'postgresql://' (which needs psycopg2)
    assert '"postgresql://"' not in env_py, (
        "env.py should not strip the driver to bare postgresql://"
    )


def test_docker_compose_app_has_env_file():
    """The app service in docker-compose.yml must load .env."""
    compose = _load_primary_compose()
    assert compose["services"]["app"]["env_file"] == [".env"]


def test_docker_compose_ui_has_env_file():
    """The ui service in docker-compose.yml must load .env."""
    compose = _load_primary_compose()
    assert compose["services"]["ui"]["env_file"] == [".env"]


def test_docker_compose_ui_exposes_psycopg_url():
    """The ui service in docker-compose.yml must require PSYCOPG_URL (no hardcoded fallback)."""
    compose = _load_primary_compose()
    psycopg_url = compose["services"]["ui"]["environment"]["PSYCOPG_URL"]
    # Must require the env var (fail-closed) — no hardcoded credentials
    assert "PSYCOPG_URL" in psycopg_url
    # Must not contain a hardcoded connection string with credentials
    assert "postgresql://" not in psycopg_url


def test_docker_compose_app_healthcheck_start_period_allows_migrations():
    """The app healthcheck must allow enough startup time for alembic + uvicorn."""
    compose = _load_primary_compose()
    start_period = compose["services"]["app"]["healthcheck"]["start_period"]
    assert start_period == "40s"


def test_docker_compose_app_dev_signing_key_default_is_truthy():
    """docker-compose.yml must default OLYMPUS_DEV_SIGNING_KEY to a truthy value."""
    compose = _load_primary_compose()
    assert (
        compose["services"]["app"]["environment"]["OLYMPUS_DEV_SIGNING_KEY"]
        == "${OLYMPUS_DEV_SIGNING_KEY:-true}"
    )


def test_docker_compose_app_does_not_use_init_schema():
    """docker-compose.yml must not call the legacy init_schema runner."""
    compose = (REPO_ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    assert "init_schema" not in compose


def test_federation_compose_nodes_have_env_file():
    """Each federation node-app must load .env."""
    compose = (REPO_ROOT / "docker-compose.federation.yml").read_text(encoding="utf-8")
    assert compose.count("env_file:") >= EXPECTED_FEDERATION_NODES


def test_federation_compose_uses_component_db_config():
    """Federation nodes must use component-based DB config (not inline DATABASE_URL)."""
    compose = (REPO_ROOT / "docker-compose.federation.yml").read_text(encoding="utf-8")
    # Each node-app should reference DATABASE_HOST, DATABASE_NAME, DATABASE_USER
    assert compose.count("DATABASE_HOST:") >= EXPECTED_FEDERATION_NODES
    assert compose.count("DATABASE_NAME:") >= EXPECTED_FEDERATION_NODES
    assert compose.count("DATABASE_USER:") >= EXPECTED_FEDERATION_NODES
    assert compose.count("DATABASE_PASSWORD_FILE:") >= EXPECTED_FEDERATION_NODES


def test_dockerfile_copies_alembic_files():
    """Production Dockerfile must COPY alembic/ and alembic.ini (not migrations/)."""
    dockerfile = (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert "alembic /app/alembic" in dockerfile
    assert "alembic.ini /app/alembic.ini" in dockerfile
    assert "migrations /app/migrations" not in dockerfile


# ---------------------------------------------------------------------------
# Part 2 hardening: kill A.Smith default, file-backed db_password secret,
# sequencer-go must not receive the password as an inline env var.
# ---------------------------------------------------------------------------


def test_no_a_smith_default_in_compose_files():
    """The legacy POSTGRES_USER default ``A.Smith`` must not reappear."""
    for compose_name in ("docker-compose.yml", "docker-compose.federation.yml"):
        text = (REPO_ROOT / compose_name).read_text(encoding="utf-8")
        assert "A.Smith" not in text, (
            f"{compose_name} still references the legacy 'A.Smith' default — use 'olympus' instead"
        )


def test_db_password_secret_is_file_backed():
    """``db_password`` must be file-backed so a fresh ``docker compose up``
    succeeds without first running ``docker secret create`` (which only
    works in Swarm mode and is the #1 first-boot cliff for self-hosters)."""
    for compose_name in ("docker-compose.yml", "docker-compose.federation.yml"):
        compose = yaml.safe_load((REPO_ROOT / compose_name).read_text(encoding="utf-8"))
        secret = compose["secrets"]["db_password"]
        assert secret.get("external") is not True, (
            f"{compose_name}: db_password must not be external:true — "
            "use file: ./secrets/db_password instead"
        )
        assert secret.get("file") == "./secrets/db_password", (
            f"{compose_name}: db_password must be backed by ./secrets/db_password"
        )


def test_secrets_dir_is_gitignored():
    """The generated ./secrets/ contents must never be committed."""
    gitignore = (REPO_ROOT / ".gitignore").read_text(encoding="utf-8")
    # Allow either form: '/secrets/*' (rooted) is what we ship.
    assert "/secrets/*" in gitignore or "secrets/" in gitignore, (
        ".gitignore must exclude the local secrets directory"
    )
    dockerignore = (REPO_ROOT / ".dockerignore").read_text(encoding="utf-8")
    assert "secrets/" in dockerignore, (
        ".dockerignore must exclude secrets/ so passwords never bake into the image"
    )


def test_bootstrap_script_exists_and_is_executable():
    bootstrap = REPO_ROOT / "scripts" / "bootstrap.sh"
    assert bootstrap.exists(), "scripts/bootstrap.sh is missing"
    if os.name == "nt":
        return
    # Script must be executable so the README's `./scripts/bootstrap.sh`
    # works straight from a fresh clone.
    mode = bootstrap.stat().st_mode
    assert mode & 0o111, "scripts/bootstrap.sh must be executable"


def test_sequencer_go_uses_file_backed_password():
    """sequencer-go must mount the db_password secret and source the password
    from a file — never as an inline env var like ${POSTGRES_PASSWORD}."""
    compose = _load_primary_compose()
    seq = compose["services"]["sequencer-go"]

    # Must mount the same db_password secret the app and db services use.
    assert "db_password" in (seq.get("secrets") or []), (
        "sequencer-go must list db_password in its secrets so it gets "
        "mounted at /run/secrets/db_password"
    )

    env = seq["environment"]
    # Must use the new component-based env vars and the file-backed password.
    assert env.get("SEQUENCER_DB_PASSWORD_FILE") == "/run/secrets/db_password"
    assert "SEQUENCER_DB_HOST" in env
    assert "SEQUENCER_DB_USER" in env
    assert "SEQUENCER_DB_NAME" in env
    assert "SEQUENCER_DB_SSLMODE" in env

    # Must NOT use the old single-URL form (which forced an inline password).
    assert "SEQUENCER_DB_URL" not in env, (
        "sequencer-go must not use SEQUENCER_DB_URL — it leaks the password "
        "into the process environment. Use SEQUENCER_DB_PASSWORD_FILE plus "
        "the component vars instead."
    )

    # Belt-and-braces: nowhere in the compose file should we see the
    # password interpolated into a connection string.
    raw = (REPO_ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    assert "${POSTGRES_PASSWORD}" not in raw, (
        "docker-compose.yml must not interpolate ${POSTGRES_PASSWORD} into "
        "any service environment — use the db_password secret instead"
    )


def test_env_example_has_asyncpg_database_url():
    """.env.example must specify postgresql+asyncpg in DATABASE_URL."""
    env_example = (REPO_ROOT / ".env.example").read_text(encoding="utf-8")
    assert "postgresql+asyncpg://" in env_example


def test_env_example_has_plain_psycopg_url():
    """.env.example must provide PSYCOPG_URL without the asyncpg driver suffix."""
    env_example = (REPO_ROOT / ".env.example").read_text(encoding="utf-8")
    assert "PSYCOPG_URL=postgresql://" in env_example


def test_env_example_is_not_corrupted_with_sql_filenames():
    """.env.example must not have SQL migration filenames appended."""
    env_example = (REPO_ROOT / ".env.example").read_text(encoding="utf-8")
    assert ".sql" not in env_example


def test_ci_workflows_do_not_use_alembic_or_sql_loop():
    """CI workflows must not use 'alembic upgrade head' or the old SQL migration loop.
    Schema is created automatically by init_schema() and Base.metadata.create_all()."""
    for wf_name in ("ci.yml", "smoke.yml"):
        wf = (REPO_ROOT / ".github" / "workflows" / wf_name).read_text(encoding="utf-8")
        assert "alembic upgrade head" not in wf, f"{wf_name} still calls 'alembic upgrade head'"
        assert "migrations/*.sql" not in wf, f"{wf_name} still uses old SQL migration loop"
