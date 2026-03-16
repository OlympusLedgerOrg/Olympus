from pathlib import Path
import re


EXPECTED_FEDERATION_NODES = 3


def test_primary_docker_compose_initializes_schema_before_starting_api():
    compose = (Path(__file__).parent.parent / "docker-compose.yml").read_text(encoding="utf-8")

    init_index = compose.find("init_schema()")
    uvicorn_match = re.search(
        r"exec\s+uvicorn\s+api\.app:app\s+--host\s+0\.0\.0\.0\s+--port\s+8000", compose
    )

    assert init_index != -1
    assert uvicorn_match is not None
    assert init_index < uvicorn_match.start()


def test_federation_docker_compose_initializes_schema_before_starting_each_api_node():
    compose = (Path(__file__).parent.parent / "docker-compose.federation.yml").read_text(
        encoding="utf-8"
    )

    assert compose.count("init_schema()") == EXPECTED_FEDERATION_NODES
    uvicorn_matches = list(
        re.finditer(r"exec\s+uvicorn\s+api\.app:app\s+--host\s+0\.0\.0\.0\s+--port\s+8000", compose)
    )

    assert len(uvicorn_matches) == EXPECTED_FEDERATION_NODES

    init_positions = [match.start() for match in re.finditer(r"init_schema\(\)", compose)]
    assert len(init_positions) == EXPECTED_FEDERATION_NODES
    assert all(init_pos < uvicorn_match.start() for init_pos, uvicorn_match in zip(init_positions, uvicorn_matches))
