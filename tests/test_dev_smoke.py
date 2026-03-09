from pathlib import Path


def test_dev_smoke_script_includes_required_steps():
    script_path = Path(__file__).parent.parent / "tools" / "dev_smoke.sh"
    script = script_path.read_text(encoding="utf-8")

    assert "docker compose up -d db" in script
    assert "pip install -r requirements-dev.txt" in script
    assert "pip install ruff" in script
    assert ".init_schema()" in script
    assert "import app_testonly" in script
    assert 'pytest tests/ -v --tb=short -m "postgres"' in script


def test_makefile_smoke_target_uses_script():
    repo_root = Path(__file__).parent.parent
    # Collect the root Makefile and all included .mk fragments
    make_sources = [repo_root / "Makefile"] + sorted((repo_root / "tools" / "make").glob("*.mk"))
    combined = "\n".join(p.read_text(encoding="utf-8") for p in make_sources)

    assert "smoke:" in combined
    assert "bash tools/dev_smoke.sh" in combined
