"""Egress-policy tests (CWE-319 / CWE-295).

Covers the ticket's acceptance criteria:
- Negative: each env-overridable, credential-bearing destination
  (FLINK_JM_ENDPOINT, GITHUB_API_BASE, GRAFANA_URL, OTEL_EXPORTER_OTLP_ENDPOINT,
  SLACK_WEBHOOKS, ANTHROPIC_API_URL/ANTHROPIC_BASE_URL, POSTGRES_HOST)
  is rejected AT CONSTRUCTION when plaintext off-loopback or off-allowlist —
  the service refuses to start instead of silently shipping credentials.
- The Anthropic endpoint is resolved with the library's own precedence and
  a violation aborts main.startup_event rather than degrading to "chat off".
- Positive control: every shipped default passes, so a correctly configured
  deployment starts and every client works.
- FLINK_SSL_VERIFY defaults to verification ON (code now matches README.md
  and ARCHITECTURE.md).
- The Flink 301 SSL-upgrade path is a scheme-only upgrade of the loopback
  base (same port, same path): a non-loopback Location host becomes the TLS
  name, never the socket destination.
- GITHUB_API_BASE falls back to a built-in known-host set when
  EGRESS_ALLOWED_HOSTS is unset.
- PostgresStateReader is inert (no validation, no env reads) when
  POSTGRES_ENABLED is not true.
"""
import pytest

from app.egress_policy import EgressPolicyError, is_loopback, validate_destination


# ── validate_destination unit tests ─────────────────────────────────────────

def test_rejects_plaintext_non_loopback():
    with pytest.raises(EgressPolicyError, match="GITHUB_API_BASE"):
        validate_destination(
            "http://attacker.example/api/v3",
            name="GITHUB_API_BASE", require_https=True, allow_loopback=False,
        )


def test_rejects_plaintext_non_loopback_even_when_loopback_allowed():
    with pytest.raises(EgressPolicyError):
        validate_destination(
            "http://collector.other.svc:4317",
            name="OTEL_EXPORTER_OTLP_ENDPOINT", require_https=True, allow_loopback=True,
        )


@pytest.mark.parametrize("url", [
    "http://localhost:4317",
    "http://127.0.0.1:8081",
    "http://[::1]:4317",
])
def test_accepts_plaintext_loopback_when_declared(url):
    assert validate_destination(url, name="X", require_https=True, allow_loopback=True) == url


def test_loopback_not_exempt_when_not_declared():
    # GitHub/Grafana have no legitimate loopback case: plaintext loopback is
    # rejected for them (https loopback would still pass the scheme rule).
    with pytest.raises(EgressPolicyError):
        validate_destination(
            "http://127.0.0.1:9999", name="GRAFANA_URL",
            require_https=True, allow_loopback=False,
        )


@pytest.mark.parametrize("url", ["", "not-a-url", "ftp://host/x", "https://"])
def test_rejects_non_http_or_hostless(url):
    with pytest.raises(EgressPolicyError):
        validate_destination(url, name="X")


def test_allowlist_rejects_unlisted_host(monkeypatch):
    monkeypatch.setenv("EGRESS_ALLOWED_HOSTS", "ghe.example.com, grafana.example.com")
    with pytest.raises(EgressPolicyError, match="EGRESS_ALLOWED_HOSTS"):
        validate_destination("https://ghe-example.attacker.example/api/v3", name="GITHUB_API_BASE")


def test_allowlist_accepts_listed_host_case_insensitively(monkeypatch):
    monkeypatch.setenv("EGRESS_ALLOWED_HOSTS", "ghe.example.com")
    url = "https://GHE.EXAMPLE.COM/api/v3"
    assert validate_destination(url, name="GITHUB_API_BASE") == url


def test_allowlist_unset_skips_allowlist_but_keeps_https_rule(monkeypatch):
    monkeypatch.delenv("EGRESS_ALLOWED_HOSTS", raising=False)
    assert validate_destination("https://anywhere.example", name="X")
    with pytest.raises(EgressPolicyError):
        validate_destination("http://anywhere.example", name="X")


@pytest.mark.parametrize("host,expected", [
    ("localhost", True), ("127.0.0.1", True), ("127.9.9.9", True), ("::1", True),
    ("10.0.0.1", False), ("grafana.example", False), ("", False),
])
def test_is_loopback(host, expected):
    assert is_loopback(host) is expected


# ── FlinkClient (construction-time validation) ────────────────────

def _make_flink_client(monkeypatch, endpoint, ssl_verify_env=None):
    from app.flink_client import FlinkClient
    monkeypatch.setenv("FLINK_JM_ENDPOINT", endpoint)
    if ssl_verify_env is None:
        monkeypatch.delenv("FLINK_SSL_VERIFY", raising=False)
    else:
        monkeypatch.setenv("FLINK_SSL_VERIFY", ssl_verify_env)
    return FlinkClient()


def test_flink_client_rejects_plaintext_offbox_endpoint_at_construction(monkeypatch):
    with pytest.raises(EgressPolicyError, match="FLINK_JM_ENDPOINT"):
        _make_flink_client(monkeypatch, "http://evil.example:8081")


def test_flink_client_rejects_off_allowlist_https_endpoint(monkeypatch):
    monkeypatch.setenv("EGRESS_ALLOWED_HOSTS", "flink.prod.example")
    with pytest.raises(EgressPolicyError, match="FLINK_JM_ENDPOINT"):
        _make_flink_client(monkeypatch, "https://evil.example:8081")


def test_flink_ssl_verify_defaults_on(monkeypatch):
    # Unset FLINK_SSL_VERIFY on an https endpoint => verification enabled
    # (aiohttp ssl param is a verifying SSLContext, not False).
    import ssl
    client = _make_flink_client(monkeypatch, "https://flink.example:8081")
    assert client.ssl_verify is True
    assert isinstance(client._ssl_param, ssl.SSLContext)
    assert client._ssl_param.verify_mode == ssl.CERT_REQUIRED
    assert client._ssl_param.check_hostname is True


def test_flink_ssl_verify_explicit_false_disables_with_warning(monkeypatch, caplog):
    import logging
    with caplog.at_level(logging.WARNING, logger="app.flink_client"):
        client = _make_flink_client(monkeypatch, "https://flink.example:8081", "false")
    assert client.ssl_verify is False
    assert client._ssl_param is False
    assert any("DISABLED" in r.message for r in caplog.records)


def test_flink_ssl_trusts_configured_ca_bundle_when_present(monkeypatch, tmp_path):
    """The verifying context is built from the FLINK_SSL_CA_BUNDLE file when it
    exists; there is no built-in bundle path (system trust store otherwise)."""
    import ssl
    from app import flink_client as fc
    assert fc.DEFAULT_FLINK_SSL_CA_BUNDLE == ""
    # A syntactically valid (self-signed) CA so create_default_context(cafile=) loads it.
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    import datetime
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-ca")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(1)
            .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))
    ca = tmp_path / "ca.cert.pem"
    ca.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    monkeypatch.setenv("FLINK_SSL_CA_BUNDLE", str(ca))
    client = _make_flink_client(monkeypatch, "https://flink.example:8081")
    assert isinstance(client._ssl_param, ssl.SSLContext)
    assert client._ssl_param.verify_mode == ssl.CERT_REQUIRED
    assert client._ssl_param.cert_store_stats()["x509_ca"] == 1  # only the configured CA, no system roots


def test_flink_ssl_falls_back_to_system_roots_when_bundle_absent(monkeypatch, tmp_path):
    import ssl
    monkeypatch.setenv("FLINK_SSL_CA_BUNDLE", str(tmp_path / "missing.pem"))
    client = _make_flink_client(monkeypatch, "https://flink.example:8081")
    assert isinstance(client._ssl_param, ssl.SSLContext)
    assert client._ssl_param.verify_mode == ssl.CERT_REQUIRED


# ── Flink 301 SSL upgrade: scheme-only upgrade of the LOOPBACK base ─────────
#
# A typical deployment enables security.ssl.rest.enabled=true and sets neither
# FLINK_JM_ENDPOINT nor FLINK_SSL_VERIFY, so the sidecar starts on the default
# http://127.0.0.1:8081 and Flink answers 301 Location: https://<rest.address>:8081
# (rest.address is the JobManager service name, never 127.0.0.1). The client
# must keep connecting to loopback, switch to https, and verify the server
# certificate under the Location host (SNI + hostname) — the nginx recipe for
# the same hop. It must never follow the redirect to a non-loopback socket.

REST_ADDRESS = "my-job-rest.flink-ns.svc.cluster.local"


def test_flink_301_named_host_is_scheme_only_upgrade_of_loopback_base(monkeypatch):
    import ssl
    client = _make_flink_client(monkeypatch, "http://127.0.0.1:8081")
    location = f"https://{REST_ADDRESS}:8081/jobs"
    assert client._should_honor_ssl_redirect(location, "/jobs") is True
    client._upgrade_to_https(location)
    assert client.base_url == "https://127.0.0.1:8081"      # socket stays on loopback
    assert client.server_hostname == REST_ADDRESS            # TLS name = Location host
    assert isinstance(client._ssl_param, ssl.SSLContext)     # verification stays ON
    assert client._ssl_param.check_hostname is True


def test_flink_301_named_host_upgrade_from_localhost_base(monkeypatch):
    # A localhost (not 127.0.0.1) base, as a rendered pod or a dev run may set.
    client = _make_flink_client(monkeypatch, "http://localhost:8081")
    location = f"https://{REST_ADDRESS}:8081/jobs/overview"
    assert client._should_honor_ssl_redirect(location, "/jobs/overview") is True
    client._upgrade_to_https(location)
    assert client.base_url == "https://localhost:8081"
    assert client.server_hostname == REST_ADDRESS


def test_flink_301_same_host_scheme_change_keeps_url_tls_name(monkeypatch):
    client = _make_flink_client(monkeypatch, "http://127.0.0.1:8081")
    assert client._should_honor_ssl_redirect("https://127.0.0.1:8081/jobs", "/jobs") is True
    client._upgrade_to_https("https://127.0.0.1:8081/jobs")
    assert client.base_url == "https://127.0.0.1:8081"
    assert client.server_hostname is None  # verify against the URL host as before


def test_flink_301_different_port_not_honored(monkeypatch):
    client = _make_flink_client(monkeypatch, "http://127.0.0.1:8081")
    assert client._should_honor_ssl_redirect(f"https://{REST_ADDRESS}:8443/jobs", "/jobs") is False
    assert client._should_honor_ssl_redirect(f"https://{REST_ADDRESS}/jobs", "/jobs") is False  # implicit 443
    assert client._should_honor_ssl_redirect("https://127.0.0.1:9000/jobs", "/jobs") is False


def test_flink_301_different_path_not_honored(monkeypatch):
    client = _make_flink_client(monkeypatch, "http://127.0.0.1:8081")
    assert client._should_honor_ssl_redirect(f"https://{REST_ADDRESS}:8081/other", "/jobs") is False
    assert client._should_honor_ssl_redirect(f"https://{REST_ADDRESS}:8081/", "/jobs") is False
    assert client._should_honor_ssl_redirect("https://127.0.0.1:8081/other", "/jobs") is False
    # Query string: identical or absent is fine, a different one is not.
    assert client._should_honor_ssl_redirect(f"https://{REST_ADDRESS}:8081/m?get=a", "/m?get=a") is True
    assert client._should_honor_ssl_redirect(f"https://{REST_ADDRESS}:8081/m", "/m?get=a") is True
    assert client._should_honor_ssl_redirect(f"https://{REST_ADDRESS}:8081/m?get=b", "/m?get=a") is False


def test_flink_301_plain_http_location_not_honored(monkeypatch):
    client = _make_flink_client(monkeypatch, "http://127.0.0.1:8081")
    assert client._should_honor_ssl_redirect("http://127.0.0.1:8081/jobs", "/jobs") is False
    assert client._should_honor_ssl_redirect(f"http://{REST_ADDRESS}:8081/jobs", "/jobs") is False
    assert client._should_honor_ssl_redirect("", "/jobs") is False
    assert client._should_honor_ssl_redirect("/jobs", "/jobs") is False  # relative: no scheme


def test_flink_301_never_connects_to_non_loopback_host(monkeypatch):
    """End-to-end through _request with a fake session: the honoured redirect
    re-issues the request to https://127.0.0.1:8081 (never to the Location
    host) with server_hostname set to the Location host."""
    import asyncio
    from app import flink_client as fc

    client = _make_flink_client(monkeypatch, "http://127.0.0.1:8081")
    calls = []

    class _Resp:
        def __init__(self, status, headers=None, body=None):
            self.status, self.headers, self._body = status, headers or {}, body
        async def json(self):
            return self._body
        async def __aenter__(self):
            return self
        async def __aexit__(self, *a):
            return False

    class _Session:
        def __init__(self, **kw):
            pass
        async def __aenter__(self):
            return self
        async def __aexit__(self, *a):
            return False
        def request(self, method, url, **kw):
            calls.append((url, kw))
            if url.startswith("http://"):
                return _Resp(301, {"Location": f"https://{REST_ADDRESS}:8081/jobs"})
            return _Resp(200, body={"jobs": []})

    monkeypatch.setattr(fc.aiohttp, "ClientSession", _Session)
    result = asyncio.run(client._get("/jobs"))
    assert result == {"jobs": []}
    assert [u for u, _ in calls] == ["http://127.0.0.1:8081/jobs", "https://127.0.0.1:8081/jobs"]
    assert "server_hostname" not in calls[0][1]
    assert calls[1][1]["server_hostname"] == REST_ADDRESS
    assert all(REST_ADDRESS not in u for u, _ in calls)


def test_flink_301_to_non_loopback_socket_stays_301(monkeypatch):
    """A redirect that would need a different socket (other port) is not
    honoured: the call surfaces the 301 and the client does not move."""
    import asyncio
    from app import flink_client as fc

    client = _make_flink_client(monkeypatch, "http://127.0.0.1:8081")

    class _Resp:
        status = 301
        headers = {"Location": "https://attacker.example:8443/jobs"}
        async def __aenter__(self):
            return self
        async def __aexit__(self, *a):
            return False

    class _Session:
        def __init__(self, **kw):
            pass
        async def __aenter__(self):
            return self
        async def __aexit__(self, *a):
            return False
        def request(self, method, url, **kw):
            return _Resp()

    monkeypatch.setattr(fc.aiohttp, "ClientSession", _Session)
    assert asyncio.run(client._get("/jobs")) == {"error": "HTTP 301", "path": "/jobs"}
    assert client.base_url == "http://127.0.0.1:8081"
    assert client.server_hostname is None


# ── GitHubClient / GrafanaAlertPoller / telemetry (construction-time validation) ────────

def test_github_client_rejects_plaintext_api_base(monkeypatch):
    from app.github_client import GitHubClient
    monkeypatch.setenv("GITHUB_API_BASE", "http://ghe-example.attacker.example/api/v3")
    with pytest.raises(EgressPolicyError, match="GITHUB_API_BASE"):
        GitHubClient(token="x")


def test_github_client_rejects_off_allowlist_api_base(monkeypatch):
    from app.github_client import GitHubClient
    monkeypatch.setenv("EGRESS_ALLOWED_HOSTS", "ghe.example.com")
    monkeypatch.setenv("GITHUB_API_BASE", "https://ghe-example.attacker.example/api/v3")
    with pytest.raises(EgressPolicyError, match="EGRESS_ALLOWED_HOSTS"):
        GitHubClient(token="x")


def test_github_client_rejects_unknown_https_host_by_default(monkeypatch):
    """EGRESS_ALLOWED_HOSTS is set nowhere in the shipped config, so the
    GitHub base must fall back to a BUILT-IN known-host set: an arbitrary
    https host must not be accepted merely because no allowlist is set."""
    from app.github_client import GitHubClient
    monkeypatch.delenv("EGRESS_ALLOWED_HOSTS", raising=False)
    monkeypatch.setenv("GITHUB_API_BASE", "https://attacker.example/api/v3")
    with pytest.raises(EgressPolicyError, match="GITHUB_API_BASE.*not a known host"):
        GitHubClient(token="x")


def test_github_client_accepts_known_hosts_by_default(monkeypatch):
    from app.github_client import GitHubClient
    from app.egress_policy import GITHUB_DEFAULT_ALLOWED_HOSTS
    monkeypatch.delenv("EGRESS_ALLOWED_HOSTS", raising=False)
    assert GITHUB_DEFAULT_ALLOWED_HOSTS == {"api.github.com"}
    monkeypatch.setenv("GITHUB_API_BASE", "https://api.github.com")
    assert GitHubClient(token=None).api_base == "https://api.github.com"
    monkeypatch.setenv("GITHUB_API_BASE", "https://API.github.com")  # host match is case-insensitive
    assert GitHubClient(token=None).api_base == "https://API.github.com"


def test_github_client_operator_allowlist_extends_known_hosts(monkeypatch):
    """Setting EGRESS_ALLOWED_HOSTS is how an operator admits another GitHub
    host; the operator's list is then authoritative (it replaces, not unions,
    the built-in set — the documented pinning semantics)."""
    from app.github_client import GitHubClient
    monkeypatch.setenv("EGRESS_ALLOWED_HOSTS", "ghe.partner.example")
    monkeypatch.setenv("GITHUB_API_BASE", "https://ghe.partner.example/api/v3")
    assert GitHubClient(token=None).api_base == "https://ghe.partner.example/api/v3"
    monkeypatch.setenv("GITHUB_API_BASE", "https://api.github.com")
    with pytest.raises(EgressPolicyError, match="EGRESS_ALLOWED_HOSTS"):
        GitHubClient(token=None)


def test_validate_destination_default_hosts_only_apply_without_env_allowlist(monkeypatch):
    monkeypatch.delenv("EGRESS_ALLOWED_HOSTS", raising=False)
    known = frozenset({"known.example"})
    assert validate_destination("https://known.example/x", name="X", default_allowed_hosts=known)
    with pytest.raises(EgressPolicyError, match="not a known host"):
        validate_destination("https://other.example/x", name="X", default_allowed_hosts=known)
    # No built-in set => unchanged behaviour (allowlist off).
    assert validate_destination("https://other.example/x", name="X")
    monkeypatch.setenv("EGRESS_ALLOWED_HOSTS", "other.example")
    assert validate_destination("https://other.example/x", name="X", default_allowed_hosts=known)


def test_grafana_poller_rejects_plaintext_url(monkeypatch):
    from app.grafana_poller import GrafanaAlertPoller
    monkeypatch.setenv("GRAFANA_URL", "http://grafana.attacker.example")
    with pytest.raises(EgressPolicyError, match="GRAFANA_URL"):
        GrafanaAlertPoller(None, None)


def test_telemetry_setup_rejects_plaintext_offbox_otlp_endpoint(monkeypatch):
    from app import telemetry
    monkeypatch.setattr(telemetry, "_ENABLED", False)
    monkeypatch.delenv("OTEL_SDK_DISABLED", raising=False)
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://collector.attacker.example:4317")
    with pytest.raises(EgressPolicyError, match="OTEL_EXPORTER_OTLP_ENDPOINT"):
        telemetry.setup_telemetry(object())


def test_telemetry_insecure_derived_from_loopback(monkeypatch):
    from app import telemetry
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4317")
    endpoint, insecure = telemetry._validated_endpoint()
    assert insecure is True
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "https://o11y-gw.example:4317")
    endpoint, insecure = telemetry._validated_endpoint()
    assert insecure is False  # off-box hop is never plaintext


# ── Anthropic endpoint (ANTHROPIC_API_URL / ANTHROPIC_BASE_URL / default) ───
#
# langchain-anthropic resolves the endpoint from ANTHROPIC_API_URL first, then
# ANTHROPIC_BASE_URL, then https://api.anthropic.com. The policy must follow
# the SAME precedence or the validated URL is not the one used.

def _clear_anthropic_env(monkeypatch):
    for var in ("ANTHROPIC_API_URL", "ANTHROPIC_BASE_URL", "EGRESS_ALLOWED_HOSTS"):
        monkeypatch.delenv(var, raising=False)


def test_library_precedence_is_api_url_then_base_url():
    # Guard against the library changing precedence under us: the resolver
    # must keep mirroring langchain_anthropic's env lookup order.
    pytest.importorskip("langchain_anthropic")
    import inspect
    from langchain_anthropic import chat_models
    from app.egress_policy import ANTHROPIC_BASE_URL_ENV_VARS
    src = inspect.getsource(chat_models.ChatAnthropic)
    assert 'base_url_env=["ANTHROPIC_API_URL", "ANTHROPIC_BASE_URL"]' in src
    assert ANTHROPIC_BASE_URL_ENV_VARS == ("ANTHROPIC_API_URL", "ANTHROPIC_BASE_URL")


def test_resolve_anthropic_base_url_precedence(monkeypatch):
    from app.egress_policy import resolve_anthropic_base_url, ANTHROPIC_DEFAULT_BASE_URL
    _clear_anthropic_env(monkeypatch)
    assert resolve_anthropic_base_url() == (ANTHROPIC_DEFAULT_BASE_URL, "default")
    monkeypatch.setenv("ANTHROPIC_BASE_URL", "https://b.example")
    assert resolve_anthropic_base_url() == ("https://b.example", "ANTHROPIC_BASE_URL")
    monkeypatch.setenv("ANTHROPIC_API_URL", "https://a.example")
    assert resolve_anthropic_base_url() == ("https://a.example", "ANTHROPIC_API_URL")


def test_validated_anthropic_base_url_rejects_plaintext_api_url_alone(monkeypatch):
    from app.egress_policy import validated_anthropic_base_url
    _clear_anthropic_env(monkeypatch)
    monkeypatch.setenv("ANTHROPIC_API_URL", "http://attacker.example")
    with pytest.raises(EgressPolicyError, match="ANTHROPIC_API_URL"):
        validated_anthropic_base_url()


def test_validated_anthropic_base_url_both_set_bad_api_url_wins(monkeypatch):
    # Both set, the ignored one (BASE_URL) is valid — the effective one must be
    # what is judged.
    from app.egress_policy import validated_anthropic_base_url
    _clear_anthropic_env(monkeypatch)
    monkeypatch.setenv("ANTHROPIC_BASE_URL", "https://gateway.example")
    monkeypatch.setenv("ANTHROPIC_API_URL", "http://attacker.example")
    with pytest.raises(EgressPolicyError, match="ANTHROPIC_API_URL"):
        validated_anthropic_base_url()


def test_validated_anthropic_base_url_both_set_bad_base_url_ignored(monkeypatch):
    # Mirror image: API_URL valid, BASE_URL bad. The library ignores BASE_URL,
    # so the policy must too — and must return the API_URL value.
    from app.egress_policy import validated_anthropic_base_url
    _clear_anthropic_env(monkeypatch)
    monkeypatch.setenv("ANTHROPIC_API_URL", "https://gateway.example")
    monkeypatch.setenv("ANTHROPIC_BASE_URL", "http://attacker.example")
    assert validated_anthropic_base_url() == "https://gateway.example"


def test_validated_anthropic_base_url_default_is_subject_to_allowlist(monkeypatch):
    from app.egress_policy import validated_anthropic_base_url, ANTHROPIC_DEFAULT_BASE_URL
    _clear_anthropic_env(monkeypatch)
    assert validated_anthropic_base_url() == ANTHROPIC_DEFAULT_BASE_URL
    monkeypatch.setenv("EGRESS_ALLOWED_HOSTS", "gateway.example")
    with pytest.raises(EgressPolicyError, match="api.anthropic.com"):
        validated_anthropic_base_url()
    monkeypatch.setenv("EGRESS_ALLOWED_HOSTS", "gateway.example,api.anthropic.com")
    assert validated_anthropic_base_url() == ANTHROPIC_DEFAULT_BASE_URL


def test_validated_anthropic_base_url_allows_plaintext_loopback_mock(monkeypatch):
    from app.egress_policy import validated_anthropic_base_url
    _clear_anthropic_env(monkeypatch)
    monkeypatch.setenv("ANTHROPIC_API_URL", "http://127.0.0.1:9999")
    assert validated_anthropic_base_url() == "http://127.0.0.1:9999"


def _build_agent(monkeypatch):
    """Construct LangGraphAgent with the model/client factories stubbed;
    returns the ChatAnthropic stub so tests can inspect what it received."""
    from unittest.mock import MagicMock
    from app import langgraph_agent as lg
    monkeypatch.setattr(lg.secret_provider, "get_api_key", lambda: "sk-test")
    chat_anthropic = MagicMock(name="ChatAnthropic")
    monkeypatch.setattr(lg, "ChatAnthropic", chat_anthropic)
    monkeypatch.setattr(lg, "create_react_agent", MagicMock(name="create_react_agent"))
    lg.LangGraphAgent(MagicMock(), MagicMock(), MagicMock(), MagicMock(), MagicMock())
    return chat_anthropic


def test_langgraph_agent_rejects_plaintext_anthropic_api_url(monkeypatch):
    pytest.importorskip("langgraph")
    _clear_anthropic_env(monkeypatch)
    monkeypatch.setenv("ANTHROPIC_API_URL", "http://attacker.example")
    with pytest.raises(EgressPolicyError, match="ANTHROPIC_API_URL"):
        _build_agent(monkeypatch)


def test_langgraph_agent_rejects_plaintext_api_url_even_when_base_url_valid(monkeypatch):
    pytest.importorskip("langgraph")
    _clear_anthropic_env(monkeypatch)
    monkeypatch.setenv("ANTHROPIC_BASE_URL", "https://gateway.example")
    monkeypatch.setenv("ANTHROPIC_API_URL", "http://attacker.example")
    with pytest.raises(EgressPolicyError, match="ANTHROPIC_API_URL"):
        _build_agent(monkeypatch)


def test_langgraph_agent_passes_validated_url_explicitly_to_model(monkeypatch):
    # Coupling: the URL that was validated is the URL the client is told to
    # use, so the library never re-resolves the environment on its own.
    pytest.importorskip("langgraph")
    _clear_anthropic_env(monkeypatch)
    monkeypatch.setenv("ANTHROPIC_API_URL", "https://gateway.example")
    monkeypatch.setenv("ANTHROPIC_BASE_URL", "http://attacker.example")
    chat_anthropic = _build_agent(monkeypatch)
    assert chat_anthropic.call_args.kwargs["base_url"] == "https://gateway.example"


def _run_startup(monkeypatch):
    """Run the REAL main.startup_event with every network/secret side effect
    stubbed: secret fetches fail (as they do off-cluster), telemetry and the
    metrics collector are no-ops, Postgres is disabled."""
    import asyncio
    from unittest.mock import MagicMock
    from app import main as m

    def _backend_unavailable():
        raise RuntimeError("secret backend unavailable in test")

    for fn in ("fetch_slack_token", "fetch_grafana_sa_token", "fetch_github_token",
               "fetch_key", "fetch_postgres_password"):
        monkeypatch.setattr(m.secret_provider, fn, _backend_unavailable)
    monkeypatch.setattr(m.telemetry, "setup_telemetry", lambda app: None)

    async def _noop():
        return None
    monkeypatch.setattr(m.metrics_collector, "start_background_collection", _noop)
    monkeypatch.setenv("POSTGRES_ENABLED", "false")
    monkeypatch.setenv("ENABLE_WRITE_TOOLS", "false")
    monkeypatch.setattr(m, "langgraph_agent", None)
    asyncio.run(m.startup_event())
    return m


def test_startup_fails_closed_on_bad_anthropic_api_url(monkeypatch):
    # A policy violation on the Anthropic endpoint must abort startup (pod
    # never Ready), not be swallowed as "API key fetch failed, chat
    # unavailable" while everything else serves.
    pytest.importorskip("langgraph")
    _clear_anthropic_env(monkeypatch)
    monkeypatch.setenv("ANTHROPIC_API_URL", "http://attacker.example")
    with pytest.raises(EgressPolicyError, match="ANTHROPIC_API_URL"):
        _run_startup(monkeypatch)


def test_startup_still_degrades_gracefully_when_only_key_fetch_fails(monkeypatch):
    # Control: with a policy-clean endpoint, a secret-fetch failure keeps the existing
    # degrade-gracefully behavior (chat unavailable, startup completes).
    pytest.importorskip("langgraph")
    _clear_anthropic_env(monkeypatch)
    m = _run_startup(monkeypatch)
    assert m.langgraph_agent is None


def test_langgraph_agent_default_endpoint_pinned_by_allowlist(monkeypatch):
    pytest.importorskip("langgraph")
    _clear_anthropic_env(monkeypatch)
    monkeypatch.setenv("EGRESS_ALLOWED_HOSTS", "flink.prod.example")
    with pytest.raises(EgressPolicyError, match="api.anthropic.com"):
        _build_agent(monkeypatch)


# ── validate_host + PostgresStateReader (bare-host destination) ─────────────

def test_validate_host_allowlist_and_loopback(monkeypatch):
    from app.egress_policy import validate_host
    monkeypatch.delenv("EGRESS_ALLOWED_HOSTS", raising=False)
    assert validate_host("db.example", name="X") == "db.example"
    monkeypatch.setenv("EGRESS_ALLOWED_HOSTS", "db.prod.example")
    assert validate_host("DB.prod.example", name="X") == "DB.prod.example"
    assert validate_host("localhost", name="X") == "localhost"
    assert validate_host("127.0.0.1", name="X") == "127.0.0.1"
    with pytest.raises(EgressPolicyError, match="X: host 'db.example'"):
        validate_host("db.example", name="X")
    with pytest.raises(EgressPolicyError, match="loopback|not in EGRESS"):
        validate_host("localhost", name="X", allow_loopback=False)
    with pytest.raises(EgressPolicyError, match="empty host"):
        validate_host("", name="X")


def test_postgres_reader_rejects_off_allowlist_host_at_construction(monkeypatch):
    from app.postgres_client import PostgresStateReader
    monkeypatch.setenv("POSTGRES_ENABLED", "true")
    monkeypatch.setenv("EGRESS_ALLOWED_HOSTS", "flink.prod.example,api.anthropic.com")
    monkeypatch.setenv("POSTGRES_HOST", "pg.evil.example")
    with pytest.raises(EgressPolicyError, match="POSTGRES_HOST"):
        PostgresStateReader()


def test_postgres_reader_accepts_allowlisted_host(monkeypatch):
    from app.postgres_client import PostgresStateReader
    monkeypatch.setenv("POSTGRES_ENABLED", "true")
    monkeypatch.setenv("EGRESS_ALLOWED_HOSTS", "flink.prod.example,pg.prod.example")
    monkeypatch.setenv("POSTGRES_HOST", "pg.prod.example")
    assert PostgresStateReader().host == "pg.prod.example"


def test_postgres_reader_default_localhost_passes_with_allowlist(monkeypatch):
    from app.postgres_client import PostgresStateReader
    monkeypatch.setenv("POSTGRES_ENABLED", "true")
    monkeypatch.setenv("EGRESS_ALLOWED_HOSTS", "flink.prod.example")
    monkeypatch.delenv("POSTGRES_HOST", raising=False)
    assert PostgresStateReader().host == "localhost"


def test_postgres_reader_disabled_skips_validation_and_env_reads(monkeypatch):
    """POSTGRES_ENABLED=false (the shipped default, and what the committed
    manifest sets): construction must not validate POSTGRES_HOST or read any
    other POSTGRES_* variable — the integration is inert, so a stale or
    off-allowlist host (or a garbage port) must not stop the pod."""
    from app.postgres_client import PostgresStateReader
    monkeypatch.delenv("POSTGRES_ENABLED", raising=False)
    monkeypatch.setenv("EGRESS_ALLOWED_HOSTS", "flink.prod.example")
    monkeypatch.setenv("POSTGRES_HOST", "pg.evil.example")
    monkeypatch.setenv("POSTGRES_PORT", "not-a-port")
    reader = PostgresStateReader()
    assert reader.enabled is False
    assert reader.host is None and reader.port is None
    assert reader.pool is None
    monkeypatch.setenv("POSTGRES_ENABLED", "false")
    assert PostgresStateReader().enabled is False


def test_postgres_reader_disabled_connect_still_validates_host(monkeypatch):
    """Belt and braces: a caller that bypasses the POSTGRES_ENABLED gate and
    calls connect() on a disabled reader still hits the egress check before
    any credential is used."""
    import asyncio
    from app.postgres_client import PostgresStateReader
    monkeypatch.delenv("POSTGRES_ENABLED", raising=False)
    monkeypatch.setenv("EGRESS_ALLOWED_HOSTS", "flink.prod.example")
    monkeypatch.setenv("POSTGRES_HOST", "pg.evil.example")
    monkeypatch.setenv("POSTGRES_PORT", "5432")
    reader = PostgresStateReader()
    with pytest.raises(EgressPolicyError, match="POSTGRES_HOST"):
        asyncio.run(reader.connect())


# ── Positive control: all shipped defaults must pass ────────────────────────

def test_positive_control_all_shipped_defaults_validate(monkeypatch):
    for var in ("FLINK_JM_ENDPOINT", "GITHUB_API_BASE", "GRAFANA_URL",
                "OTEL_EXPORTER_OTLP_ENDPOINT", "EGRESS_ALLOWED_HOSTS",
                "FLINK_SSL_VERIFY"):
        monkeypatch.delenv(var, raising=False)

    from app.flink_client import FlinkClient
    from app.github_client import GitHubClient
    from app.grafana_poller import GrafanaAlertPoller
    from app import telemetry

    client = FlinkClient()
    assert client.base_url == "http://127.0.0.1:8081"
    assert client.ssl_verify is True

    gh = GitHubClient(token=None)
    assert gh.api_base == "https://api.github.com"

    poller = GrafanaAlertPoller(None, None)
    assert poller._grafana_url == ""  # no default host: poller disabled until GRAFANA_URL is set

    endpoint, insecure = telemetry._validated_endpoint()
    assert endpoint == "http://localhost:4317"
    assert insecure is True
