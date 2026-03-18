import re
from pathlib import Path


EXPECTED_FEDERATION_NODES = 3


def test_primary_docker_compose_initializes_schema_before_starting_api():
    compose = (Path(__file__).parent.parent / "docker-compose.yml").read_text(encoding="utf-8")

    alembic_match = re.search(r"alembic\s+upgrade\s+head", compose)
    uvicorn_match = re.search(
        r"exec\s+uvicorn\s+api\.app:app\s+--host\s+0\.0\.0\.0\s+--port\s+8000", compose
    )

    assert alembic_match is not None
    assert uvicorn_match is not None
    assert alembic_match.start() < uvicorn_match.start()


def test_federation_docker_compose_initializes_schema_before_starting_each_api_node():
    compose = (Path(__file__).parent.parent / "docker-compose.federation.yml").read_text(
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
