# Copyright Yahoo, Licensed under the terms of the Apache 2.0 license. See LICENSE for terms.

"""Error responses must not reflect user input or enumerate valid values (CWE-209).

GET /api/logs/{log_type} and POST /api/remediation/apply previously echoed the
caller's value back in the 400 detail, and the remediation endpoint additionally
listed all valid remediation types — easing payload discovery for any user who
can reach the endpoint (the front-door SSO proxy authenticates but does not
authorize). Both must now return a static message; the rejected value is recorded
server-side via audit() only, never in the response body.

Imports the FastAPI app, so it needs the app dependencies (fastapi, langchain, ...).
runs in CI (the built image does not contain tests/); in a bare local shell without those deps it
skips cleanly via importorskip — same pattern as the other endpoint tests.
"""
import importlib

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402


def _client(monkeypatch, write_tools=False):
    monkeypatch.setenv("SECRET_PROVIDER", "env")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "dummy")
    if write_tools:
        # The remediation 400 (invalid type) sits *after* the write-authz gate, so the
        # type validation is only reachable when write tools are enabled (dev posture).
        monkeypatch.setenv("ENABLE_WRITE_TOOLS", "true")
        monkeypatch.setenv("DEPLOY_ENV", "nonprod")
    else:
        monkeypatch.delenv("ENABLE_WRITE_TOOLS", raising=False)
    import app.main as main
    importlib.reload(main)
    return TestClient(main._app)


def test_logs_invalid_type_static_no_echo(monkeypatch):
    payload = "INJECTED_XSS_PAYLOAD"
    resp = _client(monkeypatch).get(f"/api/logs/{payload}")
    assert resp.status_code == 400
    assert resp.json()["detail"] == "Invalid log type"
    assert payload not in resp.text


def test_remediation_invalid_type_static_no_echo_no_enumeration(monkeypatch):
    from app.auto_remediator import RemediationType

    client = _client(monkeypatch, write_tools=True)
    resp = client.post(
        "/api/remediation/apply",
        json={"type": "INJECTED_TYPE", "dry_run": True},
    )
    assert resp.status_code == 400
    assert resp.json()["detail"] == "Invalid remediation type"
    # Neither the echoed input nor any valid type name may leak.
    assert "INJECTED_TYPE" not in resp.text
    for rtype in RemediationType:
        assert rtype.value not in resp.text
