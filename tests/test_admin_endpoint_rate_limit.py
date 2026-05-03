from __future__ import annotations

from fastapi.routing import APIRoute
import pytest
from fastapi.testclient import TestClient

import api.main as api_main
from api.routers import keys as keys_router


def test_admin_generate_endpoint_has_rate_limit_dependency():
    app = api_main.create_app()
    route = next(
        r
        for r in app.routes
        if isinstance(r, APIRoute)
        and r.path == "/key/admin/generate"
        and "POST" in (r.methods or set())
    )
    dependency_names = {dep.call.__name__ for dep in route.dependant.dependencies if dep.call}
    assert "rate_limit" in dependency_names


def test_weak_admin_key_fails_startup_check(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("OLYMPUS_ENV", "production")
    monkeypatch.setenv("OLYMPUS_ADMIN_KEY", "short-key")
    monkeypatch.setattr(api_main, "_assert_no_dev_zk_stub_artifacts", lambda: None)
    monkeypatch.setattr(api_main, "_assert_no_dev_signing_key_in_non_development", lambda: None)
    monkeypatch.setattr(api_main, "_assert_dev_auth_flag_restricted_to_development", lambda: None)
    monkeypatch.setattr(api_main, "_assert_no_multiworker_with_memory_rate_limit", lambda: None)
    monkeypatch.setattr(api_main, "_assert_redis_url_when_redis_backend", lambda: None)
    monkeypatch.setattr(api_main, "_assert_xff_default_deny", lambda: None)

    with pytest.raises(RuntimeError, match="weak OLYMPUS_ADMIN_KEY"):
        with TestClient(api_main.create_app()):
            pass


def test_weak_admin_key_check_function_direct(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("OLYMPUS_ENV", "production")
    monkeypatch.setenv("OLYMPUS_ADMIN_KEY", "short-key")
    with pytest.raises(RuntimeError, match="weak OLYMPUS_ADMIN_KEY"):
        keys_router.assert_admin_key_strength_for_environment()
