import re
from pathlib import Path

import yaml


EXPECTED_FEDERATION_NODES = 3
REPO_ROOT = Path(__file__).parent.parent


def _load_primary_compose() -> dict:
    return yaml.safe_load((REPO_ROOT / "docker-compose.yml").read_text(encoding="utf-8"))


def test_primary_docker_compose_initializes_schema_before_starting_api():
    compose = (REPO_ROOT / "docker-compose.yml").read_text(encoding="utf-8")

    alembic_match = re.search(r"python\s+-m\s+alembic\s+upgrade\s+head", compose)
    uvicorn_match = re.search(
        r"exec\s+uvicorn\s+api\.app:app\s+--host\s+0\.0\.0\.0\s+--port\s+8000", compose
    )

    assert alembic_match is not None
    assert uvicorn_match is not None
    assert alembic_match.start() < uvicorn_match.start()


def test_federation_docker_compose_initializes_schema_before_starting_each_api_node():
    compose = (REPO_ROOT / "docker-compose.federation.yml").read_text(
        encoding="utf-8"
    )

    assert compose.count("alembic upgrade head") == EXPECTED_FEDERATION_NODES
    uvicorn_matches = list(
        re.finditer(r"exec\s+uvicorn\s+api\.app:app\s+--host\s+0\.0\.0\.0\s+--port\s+8000", compose)
    )

    assert len(uvicorn_matches) == EXPECTED_FEDERATION_NODES

    alembic_positions = [match.start() for match in re.finditer(r"alembic\s+upgrade\s+head", compose)]
    assert len(alembic_positions) == EXPECTED_FEDERATION_NODES
    assert all(alembic_pos < uvicorn_match.start() for alembic_pos, uvicorn_match in zip(alembic_positions, uvicorn_matches))


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
    """The ui service in docker-compose.yml must expose PSYCOPG_URL for psycopg."""
    compose = _load_primary_compose()
    assert compose["services"]["ui"]["environment"]["PSYCOPG_URL"].startswith(
        "${PSYCOPG_URL:-postgresql://"
    )


def test_docker_compose_app_healthcheck_start_period_allows_migrations():
    """The app healthcheck must allow enough startup time for alembic + uvicorn."""
    compose = _load_primary_compose()
    assert compose["services"]["app"]["healthcheck"]["start_period"] == "30s"


def test_docker_compose_app_does_not_use_init_schema():
    """docker-compose.yml must not call the legacy init_schema runner."""
    compose = (REPO_ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    assert "init_schema" not in compose


def test_federation_compose_nodes_have_env_file():
    """Each federation node-app must load .env."""
    compose = (REPO_ROOT / "docker-compose.federation.yml").read_text(encoding="utf-8")
    assert compose.count("env_file:") >= EXPECTED_FEDERATION_NODES


def test_federation_compose_uses_asyncpg_driver():
    """Federation DATABASE_URLs must include +asyncpg for the async app engine."""
    compose = (REPO_ROOT / "docker-compose.federation.yml").read_text(encoding="utf-8")
    assert compose.count("postgresql+asyncpg://") >= EXPECTED_FEDERATION_NODES


def test_dockerfile_copies_alembic_files():
    """Production Dockerfile must COPY alembic/ and alembic.ini (not migrations/)."""
    dockerfile = (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert "alembic /app/alembic" in dockerfile
    assert "alembic.ini /app/alembic.ini" in dockerfile
    assert "migrations /app/migrations" not in dockerfile


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


def test_ci_workflows_use_alembic_not_sql_loop():
    """CI workflows must use 'alembic upgrade head', not the old SQL migration loop."""
    for wf_name in ("ci.yml", "smoke.yml"):
        wf = (REPO_ROOT / ".github" / "workflows" / wf_name).read_text(encoding="utf-8")
        assert "alembic upgrade head" in wf, f"{wf_name} missing 'alembic upgrade head'"
        assert "migrations/*.sql" not in wf, f"{wf_name} still uses old SQL migration loop"
