import os

from validate_db_config import BASE_DIR, check_database_urls


def test_validate_db_config_from_other_cwd(tmp_path, monkeypatch):
    """Ensure DB config validation uses repo-relative paths."""
    monkeypatch.chdir(tmp_path)
    assert os.getcwd() != str(BASE_DIR)
    assert check_database_urls() is True
