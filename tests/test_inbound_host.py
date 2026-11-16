"""Inbound Host allowlist (DNS-rebinding defence, CWE-350 / CWE-346).

The API authenticates nobody itself. During a port-forward, a page whose domain
re-resolves to 127.0.0.1 becomes same-origin with it, so CORS cannot help; the
Host header still names the attacker's domain and is refused. Loopback names
stay allowed because the pod-local reverse proxy forwards to 127.0.0.1:8765
without rewriting Host and the container probes call 127.0.0.1:8765.
"""
import importlib

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402


def _client(monkeypatch, extra=None, root_path=None):
    monkeypatch.setenv("SECRET_PROVIDER", "env")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "dummy")
    if extra is None:
        monkeypatch.delenv("INBOUND_ALLOWED_HOSTS", raising=False)
    else:
        monkeypatch.setenv("INBOUND_ALLOWED_HOSTS", extra)
    if root_path is None:
        monkeypatch.delenv("ROOT_PATH", raising=False)
    else:
        monkeypatch.setenv("ROOT_PATH", root_path)
    import app.main as main
    importlib.reload(main)
    return main, TestClient(main.app)


@pytest.mark.parametrize("host", ["attacker.example:8765", "rebind.test", "10.1.2.3:8765"])
def test_foreign_host_is_refused(monkeypatch, host):
    _, client = _client(monkeypatch)
    resp = client.get("/api/health", headers={"Host": host})
    assert resp.status_code == 400


@pytest.mark.parametrize("host", ["127.0.0.1:8765", "localhost", "localhost:8765", "127.0.0.1"])
def test_loopback_hosts_are_allowed_by_default(monkeypatch, host):
    _, client = _client(monkeypatch)
    resp = client.get("/api/health", headers={"Host": host})
    assert resp.status_code == 200


def test_operator_listed_name_is_allowed(monkeypatch):
    _, client = _client(monkeypatch, "proxy.example")
    assert client.get("/api/health", headers={"Host": "proxy.example"}).status_code == 200
    assert client.get("/api/health", headers={"Host": "attacker.example"}).status_code == 400


def test_bare_wildcard_is_dropped(monkeypatch):
    _, client = _client(monkeypatch, "*")
    assert client.get("/api/health", headers={"Host": "attacker.example"}).status_code == 400
    assert client.get("/api/health", headers={"Host": "127.0.0.1:8765"}).status_code == 200


def test_refusal_happens_before_any_route_runs(monkeypatch):
    # Outermost: even a POST that would otherwise be refused for its
    # Content-Type gets the Host refusal first.
    _, client = _client(monkeypatch)
    resp = client.post("/api/diagnostics/thread-dump", headers={"Host": "attacker.example"})
    assert resp.status_code == 400


def test_sub_path_proxy_hop_still_reaches_the_app(monkeypatch):
    # Deployed shape: a pod-local reverse proxy forwards /chat/* to
    # http://127.0.0.1:8765 (Host 127.0.0.1:8765) with ROOT_PATH=/chat.
    _, client = _client(monkeypatch, root_path="/chat")
    resp = client.get("/chat/api/health", headers={"Host": "127.0.0.1:8765"})
    assert resp.status_code == 200
    resp = client.get("/chat/api/health", headers={"Host": "attacker.example"})
    assert resp.status_code == 400
