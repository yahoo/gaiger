# Copyright Yahoo, Licensed under the terms of the Apache 2.0 license. See LICENSE for terms.

"""Default development UI content must not be served.

The app sits behind an SSO reverse proxy that authenticates but does not
authorize, so any reachable route is exposed to every SSO-authenticated
user. The demo landing page and the alternate UI variants are development
content (one disclosed the dev toolchain vendor), so all of their routes
must 404. The production UI at "/" must still be served.

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


@pytest.mark.parametrize(
    "path",
    [
        "/demo",
        "/ui/demo.html",
        "/ui/index-dashboard.html",
        "/ui/index-chat-plus.html",
        "/ui/index-tabbed.html",
    ],
)
def test_demo_content_returns_404(client, path):
    assert client.get(path).status_code == 404


@pytest.mark.parametrize("path", ["/", "/chat"])
def test_ui_root_still_served(client, path):
    resp = client.get(path)
    assert resp.status_code == 200
    assert "text/html" in resp.headers.get("content-type", "")
