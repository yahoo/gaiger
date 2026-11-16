# Copyright Yahoo, Licensed under the terms of the Apache 2.0 license. See LICENSE for terms.

"""FastAPI auto-generated documentation must be disabled.

The app sits behind an SSO reverse proxy that authenticates but does not
authorize, so any doc route would expose the full API inventory (endpoint
paths, request/response models, validators) to every SSO-authenticated
user. All three FastAPI doc endpoints must therefore 404.

Imports the FastAPI app, so it requires the app dependencies (fastapi,
langchain, ...). It runs in CI (the built image does not contain tests/); in a bare local
shell without those deps it skips cleanly via importorskip.
"""
import importlib

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("SECRET_PROVIDER", "env")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "dummy")
    import app.main as main
    importlib.reload(main)
    return TestClient(main._app)


@pytest.mark.parametrize("path", ["/openapi.json", "/docs", "/redoc"])
def test_doc_endpoints_return_404(client, path):
    assert client.get(path).status_code == 404


def test_ui_root_still_served(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert "text/html" in resp.headers.get("content-type", "")


def test_ui_sends_anti_framing_headers(client):
    resp = client.get("/")
    assert resp.headers.get("x-frame-options") == "DENY"
    assert resp.headers.get("content-security-policy") == "frame-ancestors 'none'"
