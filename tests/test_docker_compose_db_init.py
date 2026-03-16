from pathlib import Path


def test_primary_docker_compose_initializes_schema_before_starting_api():
    compose = (Path(__file__).parent.parent / "docker-compose.yml").read_text(encoding="utf-8")

    assert "StorageLayer(os.environ['DATABASE_URL']).init_schema()" in compose
    assert "exec uvicorn api.app:app --host 0.0.0.0 --port 8000" in compose


def test_federation_docker_compose_initializes_schema_before_starting_each_api_node():
    compose = (Path(__file__).parent.parent / "docker-compose.federation.yml").read_text(
        encoding="utf-8"
    )

    assert compose.count("StorageLayer(os.environ['DATABASE_URL']).init_schema()") == 3
    assert compose.count("exec uvicorn api.app:app --host 0.0.0.0 --port 8000") == 3
