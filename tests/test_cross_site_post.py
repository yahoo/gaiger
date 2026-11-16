"""Cross-site and non-JSON POSTs are refused (CWE-352).

Every POST route takes JSON or no body and the UI always sends
Content-Type: application/json, so a POST without it (an HTML form, a
body-less fetch from another site) is refused with 415, and a browser request
marked Sec-Fetch-Site cross-site / same-site, or carrying a foreign Origin, is
refused with 403. The same-origin UI keeps working.
"""
import importlib
import re
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

_JSON = {"Content-Type": "application/json"}


@pytest.fixture
def app_client(monkeypatch):
    monkeypatch.setenv("SECRET_PROVIDER", "env")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "dummy")
    monkeypatch.setenv("RATE_LIMIT_HEAVY_PER_MINUTE", "100")
    monkeypatch.setenv("CORS_ALLOWED_ORIGINS", "https://trusted.example")
    import app.main as main
    importlib.reload(main)
    calls = []

    async def _fake_dump(*args, **kwargs):
        calls.append(1)
        return {"dumps": []}

    monkeypatch.setattr(main.flink_client, "analyze_thread_dumps", _fake_dump)
    return TestClient(main._app), calls


def test_post_without_content_type_is_415(app_client):
    client, calls = app_client
    assert client.post("/api/diagnostics/thread-dump").status_code == 415
    assert client.post("/api/diagnostics/thread-dump",
                       headers={"Content-Type": "text/plain"}).status_code == 415
    assert client.post("/api/diagnostics/thread-dump",
                       headers={"Content-Type": "application/x-www-form-urlencoded"}).status_code == 415
    assert calls == []


@pytest.mark.parametrize("site", ["cross-site", "same-site"])
def test_cross_site_fetch_is_403(app_client, site):
    client, calls = app_client
    resp = client.post("/api/diagnostics/thread-dump",
                       headers={**_JSON, "Sec-Fetch-Site": site, "Origin": "https://evil.example"})
    assert resp.status_code == 403
    assert calls == []


def test_same_origin_json_post_passes(app_client):
    client, calls = app_client
    resp = client.post("/api/diagnostics/thread-dump",
                       headers={**_JSON, "Sec-Fetch-Site": "same-origin",
                                "Origin": "https://flink.example"})
    assert resp.status_code == 200
    assert calls == [1]


def test_plain_json_post_without_browser_headers_passes(app_client):
    client, calls = app_client
    assert client.post("/api/diagnostics/thread-dump", headers=_JSON).status_code == 200


def test_foreign_origin_without_sec_fetch_site_is_403(app_client):
    client, calls = app_client
    resp = client.post("/api/diagnostics/thread-dump",
                       headers={**_JSON, "Origin": "https://evil.example"})
    assert resp.status_code == 403
    resp = client.post("/api/diagnostics/thread-dump",
                       headers={**_JSON, "Origin": "null"})
    assert resp.status_code == 403
    assert calls == []


def test_origin_matching_forwarded_host_passes(app_client):
    # Behind a reverse proxy Host is the loopback upstream; the browser's
    # Origin matches the public name the proxy forwards in X-Forwarded-Host.
    client, calls = app_client
    resp = client.post("/api/diagnostics/thread-dump",
                       headers={**_JSON, "Origin": "https://flink.example",
                                "X-Forwarded-Host": "flink.example"})
    assert resp.status_code == 200


def test_operator_trusted_cors_origin_passes(app_client):
    client, calls = app_client
    resp = client.post("/api/diagnostics/thread-dump",
                       headers={**_JSON, "Sec-Fetch-Site": "cross-site",
                                "Origin": "https://trusted.example"})
    assert resp.status_code == 200


def test_get_routes_are_unaffected(app_client):
    client, _ = app_client
    assert client.get("/api/health", headers={"Sec-Fetch-Site": "cross-site"}).status_code == 200


def test_ui_sends_json_content_type_on_every_post():
    html = (Path(__file__).resolve().parent.parent / "app" / "ui" / "index.html").read_text()
    # The diagnostics fetch builds a JSON Content-Type header for its POSTs.
    assert re.search(r"method === 'POST' \? \{'Content-Type': 'application/json'\}", html)
    assert "fetch(endpoints[type], {method, headers})" in html
    # The streaming query POST already sends JSON.
    assert "'Content-Type': 'application/json'" in html


def test_fastapi_floor():
    req = (Path(__file__).resolve().parent.parent / "requirements.txt").read_text()
    assert re.search(r"^fastapi>=0\.132\.0$", req, re.M)
