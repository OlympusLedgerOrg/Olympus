from pathlib import Path


def test_dev_smoke_script_includes_required_steps():
    script_path = Path(__file__).parent.parent / "tools" / "dev_smoke.sh"
    script = script_path.read_text(encoding="utf-8")

    assert "docker compose up -d db" in script
    assert "pip install -r requirements-dev.txt" in script
    assert ".init_schema()" in script
    assert "import api.app" in script
    assert 'pytest tests/ -v --tb=short -m "postgres"' in script


def test_makefile_smoke_target_uses_script():
    makefile = (Path(__file__).parent.parent / "Makefile").read_text(encoding="utf-8")

    assert "\nsmoke:\n\tbash tools/dev_smoke.sh\n" in makefile
