# Copyright Yahoo, Licensed under the terms of the Apache 2.0 license. See LICENSE for terms.

"""The unauthenticated Grafana push-webhook endpoint must stay removed.

POST /api/webhooks/grafana used to accept arbitrary unauthenticated JSON that
flowed directly into the LangGraph AI agent (missing authentication for a
critical function: request forgery, prompt injection, cost DoS). The endpoint
was removed and replaced by the authenticated pull model in
app/grafana_poller.py (Grafana service account token supplied via the
GRAFANA_SA_TOKEN env var, pointed at GRAFANA_URL).

These tests lock that removal in place. If a Grafana push webhook is ever
re-introduced, this suite fails loudly: any such endpoint MUST verify the
X-Grafana-Signature HMAC-SHA256 header (constant-time comparison over the raw
request body, fail-closed) before parsing the payload.

Imports the FastAPI app, so it requires the app dependencies (fastapi,
langchain, ...). It runs in CI (the built image does not contain tests/); in a bare local
shell without those deps it skips cleanly via importorskip.
"""
import importlib

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402


@pytest.fixture
def main_module(monkeypatch):
    monkeypatch.setenv("SECRET_PROVIDER", "env")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "dummy")
    import app.main as main
    importlib.reload(main)
    return main


@pytest.fixture
def client(main_module):
    return TestClient(main_module._app)


def test_grafana_webhook_endpoint_is_absent(client):
    """The legacy unauthenticated alert-ingress endpoint must return 404."""
    resp = client.post(
        "/api/webhooks/grafana",
        json={"status": "firing", "alerts": [{"status": "firing"}]},
    )
    assert resp.status_code == 404


def test_no_routes_registered_under_api_webhooks(main_module):
    """No inbound webhook surface may exist at all.

    Alert ingestion is pull-only (app/grafana_poller.py). Re-adding any
    /api/webhooks/* route requires a security review and MUST include HMAC signature verification.
    """
    webhook_routes = [
        route.path
        for route in main_module._app.routes
        if getattr(route, "path", "").startswith("/api/webhooks")
    ]
    assert webhook_routes == []
