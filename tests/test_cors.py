# Copyright Yahoo, Licensed under the terms of the Apache 2.0 license. See LICENSE for terms.

"""CORS policy tests.

Imports the FastAPI app, so it requires the app dependencies (fastapi, langchain, ...).
It runs in CI (.github/workflows/tests.yml installs requirements.txt, so nothing here
is skipped there); in a bare local shell without those deps it skips cleanly via
importorskip. The built image does not contain tests/ (the Dockerfile copies app/ only),
so this suite is not runnable from inside the container. The deterministic write-authz
gate is covered separately in test_write_authz.py (no app import needed).
"""
import importlib

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402


def _client(monkeypatch, origins_env=None):
    monkeypatch.setenv("SECRET_PROVIDER", "env")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "dummy")
    if origins_env is None:
        monkeypatch.delenv("CORS_ALLOWED_ORIGINS", raising=False)
    else:
        monkeypatch.setenv("CORS_ALLOWED_ORIGINS", origins_env)
    import app.main as main
    importlib.reload(main)  # CORS origins are read at import time
    return TestClient(main._app)


def test_cross_origin_denied_by_default(monkeypatch):
    client = _client(monkeypatch)
    resp = client.options(
        "/api/query",
        headers={
            "Origin": "https://evil.example",
            "Access-Control-Request-Method": "POST",
        },
    )
    assert "access-control-allow-origin" not in {k.lower() for k in resp.headers}


def test_configured_origin_allowed(monkeypatch):
    client = _client(monkeypatch, "https://good.example")
    resp = client.options(
        "/api/query",
        headers={
            "Origin": "https://good.example",
            "Access-Control-Request-Method": "POST",
        },
    )
    assert resp.headers.get("access-control-allow-origin") == "https://good.example"


def test_wildcard_origin_warns_and_is_denied(monkeypatch, caplog):
    """CORS_ALLOWED_ORIGINS=* must NOT enable allow-all-origins; it warns and is ignored."""
    import logging

    with caplog.at_level(logging.WARNING, logger="app.main"):
        client = _client(monkeypatch, "*")
    assert any(
        "CORS_ALLOWED_ORIGINS contains wildcard" in rec.getMessage()
        for rec in caplog.records
    )
    resp = client.options(
        "/api/query",
        headers={
            "Origin": "https://evil.example",
            "Access-Control-Request-Method": "POST",
        },
    )
    assert "access-control-allow-origin" not in {k.lower() for k in resp.headers}


def test_wildcard_mixed_with_explicit_origins(monkeypatch, caplog):
    """Wildcard entries are stripped with a warning; explicit origins keep working."""
    import logging

    with caplog.at_level(logging.WARNING, logger="app.main"):
        client = _client(monkeypatch, "*,https://good.example")
    assert any("wildcard" in rec.getMessage() for rec in caplog.records)
    allowed = client.options(
        "/api/query",
        headers={
            "Origin": "https://good.example",
            "Access-Control-Request-Method": "POST",
        },
    )
    assert allowed.headers.get("access-control-allow-origin") == "https://good.example"
    denied = client.options(
        "/api/query",
        headers={
            "Origin": "https://evil.example",
            "Access-Control-Request-Method": "POST",
        },
    )
    assert "access-control-allow-origin" not in {k.lower() for k in denied.headers}


def test_subdomain_wildcard_pattern_warns_and_never_matches(monkeypatch, caplog):
    """Entries like https://*.example.com are inert in Starlette; they warn and are dropped."""
    import logging

    with caplog.at_level(logging.WARNING, logger="app.main"):
        client = _client(monkeypatch, "https://*.example.com")
    assert any("wildcard" in rec.getMessage() for rec in caplog.records)
    resp = client.options(
        "/api/query",
        headers={
            "Origin": "https://app.example.com",
            "Access-Control-Request-Method": "POST",
        },
    )
    assert "access-control-allow-origin" not in {k.lower() for k in resp.headers}


def test_preflight_grant_excludes_mutating_methods(monkeypatch):
    """A successful preflight from a trusted origin must only grant GET/POST."""
    client = _client(monkeypatch, "https://good.example")
    resp = client.options(
        "/api/query",
        headers={
            "Origin": "https://good.example",
            "Access-Control-Request-Method": "POST",
        },
    )
    assert resp.status_code == 200
    allowed = {
        m.strip().upper()
        for m in resp.headers.get("access-control-allow-methods", "").split(",")
        if m.strip()
    }
    assert "POST" in allowed
    assert not allowed & {"DELETE", "PATCH", "PUT"}


def test_delete_preflight_denied_for_allowed_origin(monkeypatch):
    """Even a trusted origin must not receive preflight approval for DELETE."""
    client = _client(monkeypatch, "https://good.example")
    resp = client.options(
        "/api/remediation/apply",
        headers={
            "Origin": "https://good.example",
            "Access-Control-Request-Method": "DELETE",
        },
    )
    allowed = resp.headers.get("access-control-allow-methods", "")
    assert "DELETE" not in {m.strip().upper() for m in allowed.split(",")}
    # Starlette rejects a disallowed preflight outright.
    assert resp.status_code == 400


def test_nonallowlisted_header_preflight_denied(monkeypatch):
    """Preflight requesting a header outside the explicit allowlist is rejected."""
    client = _client(monkeypatch, "https://good.example")
    resp = client.options(
        "/api/query",
        headers={
            "Origin": "https://good.example",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "X-Custom-Evil",
        },
    )
    assert resp.status_code == 400
    assert "x-custom-evil" not in resp.headers.get(
        "access-control-allow-headers", ""
    ).lower()


def test_content_type_header_preflight_allowed(monkeypatch):
    """The UI's Content-Type: application/json preflight must keep working."""
    client = _client(monkeypatch, "https://good.example")
    resp = client.options(
        "/api/query",
        headers={
            "Origin": "https://good.example",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "Content-Type",
        },
    )
    assert resp.status_code == 200
    assert "content-type" in resp.headers.get("access-control-allow-headers", "").lower()
