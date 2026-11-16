# Copyright Yahoo, Licensed under the terms of the Apache 2.0 license. See LICENSE for terms.

"""Deterministic tests for the audit logger.

Pure stdlib — exercises app.audit in isolation (no FastAPI/LangChain needed).
"""
import contextvars
import json
import logging

import pytest

from app.audit import (
    audit,
    audit_remediation,
    client_ip,
    ensure_correlation_id,
    get_correlation_id,
    new_correlation_id,
)


class _FakeReq:
    """Minimal stand-in for a Starlette/FastAPI Request."""
    def __init__(self, headers=None, client_host=None):
        self.headers = headers or {}
        self.client = type("C", (), {"host": client_host})() if client_host else None


@pytest.fixture
def captured():
    """Capture lines emitted on the app.audit logger."""
    records = []

    class _H(logging.Handler):
        def emit(self, record):
            records.append(record.getMessage())

    logger = logging.getLogger("app.audit")
    h = _H()
    logger.addHandler(h)
    try:
        yield records
    finally:
        logger.removeHandler(h)


@pytest.fixture(autouse=True)
def _three_hop_chain(monkeypatch):
    """Most tests below model a 3-proxy chain (edge LB -> SSO gateway -> in-pod
    proxy). The shipped default is 0 (XFF ignored); see the default tests."""
    monkeypatch.setenv("AUDIT_TRUSTED_PROXY_HOPS", "3")


def test_default_ignores_forwarded_for_and_records_the_peer(monkeypatch):
    # Unset: a caller-supplied X-Forwarded-For must not become the source IP.
    monkeypatch.delenv("AUDIT_TRUSTED_PROXY_HOPS")
    req = _FakeReq(headers={"x-forwarded-for": "6.6.6.6"}, client_host="10.0.0.9")
    assert client_ip(req) == "10.0.0.9"
    req = _FakeReq(headers={"x-forwarded-for": "6.6.6.6, 7.7.7.7, 8.8.8.8"}, client_host="127.0.0.1")
    assert client_ip(req) == "127.0.0.1"


@pytest.mark.parametrize("value", ["0", "-2", "abc", ""])
def test_zero_or_invalid_hops_ignore_forwarded_for(monkeypatch, value):
    monkeypatch.setenv("AUDIT_TRUSTED_PROXY_HOPS", value)
    req = _FakeReq(headers={"x-forwarded-for": "6.6.6.6"}, client_host="10.0.0.9")
    assert client_ip(req) == "10.0.0.9"


def test_default_spoof_over_http_records_the_test_client_peer(monkeypatch):
    import importlib
    from fastapi.testclient import TestClient
    monkeypatch.delenv("AUDIT_TRUSTED_PROXY_HOPS")
    monkeypatch.setenv("SECRET_PROVIDER", "env")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "dummy")
    import app.main as main
    importlib.reload(main)
    seen = []

    @main._app.get("/__ip_probe")
    async def _probe(request: main.Request):
        seen.append(client_ip(request))
        return {}

    TestClient(main._app).get("/__ip_probe", headers={"X-Forwarded-For": "6.6.6.6"})
    assert seen == ["testclient"]


# ── source IP: trusted-hop right-indexed parse (3: edge LB → SSO gateway → in-pod proxy) ──

def test_client_ip_uses_trusted_edge_entry_not_leftmost():
    # Full production chain: the edge recorded 203.0.113.7; the SSO gateway and in-pod proxy each
    # appended one in-infra hop. The trusted client is the 3rd entry from the right.
    req = _FakeReq(headers={"x-forwarded-for": "203.0.113.7, 10.0.0.1, 10.0.0.2"})
    assert client_ip(req) == "203.0.113.7"


def test_client_ip_ignores_spoofed_prepended_entries():
    # An attacker prepends fake entries on the LEFT; they cannot shift the trusted
    # right-indexed position, so the real edge-recorded client still wins.
    req = _FakeReq(headers={"x-forwarded-for": "1.2.3.4, 9.9.9.9, 203.0.113.7, 10.0.0.1, 10.0.0.2"})
    ip = client_ip(req)
    assert ip == "203.0.113.7"
    assert ip not in ("1.2.3.4", "9.9.9.9")


def test_client_ip_short_chain_fails_closed_to_untrusted():
    # Off the production chain (dev / port-forward): fewer than 3 hops means there
    # is NO edge-recorded entry to trust — the leftmost entry is caller-supplied,
    # and source_ip is the only attribution the record carries. Fail closed.
    req = _FakeReq(headers={"x-forwarded-for": "10.1.2.3"})
    assert client_ip(req) == "untrusted"


def test_client_ip_short_chain_never_returns_caller_chosen_value():
    # The exact attack: X-Forwarded-For: 10.9.9.9 over port-forward
    # must not become the audit record's source_ip.
    req = _FakeReq(headers={"x-forwarded-for": "10.9.9.9, 10.0.0.1"})
    ip = client_ip(req)
    assert ip == "untrusted"
    assert ip not in ("10.9.9.9", "10.0.0.1")


def test_client_ip_full_depth_chain_still_right_indexed():
    # Regression guard: closing the short-chain fallback must NOT break the sound
    # right-indexed parse on a full-depth production chain.
    req = _FakeReq(headers={"x-forwarded-for": "203.0.113.7, 10.0.0.1, 10.0.0.2"})
    assert client_ip(req) == "203.0.113.7"


def test_client_ip_honors_configurable_hops(monkeypatch):
    monkeypatch.setenv("AUDIT_TRUSTED_PROXY_HOPS", "1")
    # With 1 trusted hop, only the rightmost entry is trusted.
    req = _FakeReq(headers={"x-forwarded-for": "1.2.3.4, 203.0.113.7, 10.0.0.9"})
    assert client_ip(req) == "10.0.0.9"


def test_client_ip_falls_back_to_peer():
    assert client_ip(_FakeReq(headers={}, client_host="10.1.2.3")) == "10.1.2.3"


def test_client_ip_none_is_unknown():
    assert client_ip(None) == "unknown"


# ── audit record shape ──

def test_audit_emits_required_fields(captured):
    audit("ai_query", _FakeReq(headers={"x-forwarded-for": "203.0.113.7, 10.0.0.1, 10.0.0.2"}),
          question="why is it failing?", history_len=2)
    assert len(captured) == 1
    rec = json.loads(captured[0])
    assert rec["event"] == "ai_query"
    assert rec["source_ip"] == "203.0.113.7"                          # trusted edge entry, not leftmost
    assert rec["forwarded_for"] == "203.0.113.7, 10.0.0.1, 10.0.0.2"  # raw chain kept for forensics
    assert rec["auth"] == "unknown"             # observed, never asserted (no verifiable SSO marker yet)
    assert rec["actor"] == "anonymous"          # no human identity (the SSO proxy forwards none)
    assert rec["classification"] == "confidential"   # sink classification travels with the record
    assert isinstance(rec["seq"], int) and rec["seq"] >= 1
    assert rec["question"] == "why is it failing?"
    assert rec["history_len"] == 2
    assert "ts" in rec


def test_audit_seq_is_contiguous_and_monotonic(captured):
    # Without a sequence number, loss is indistinguishable from silence: 50
    # quiet minutes could be a quiet afternoon or a dropped pipeline window.
    audit("ai_query", _FakeReq(), question="q1")
    audit("job_restart", success=True)
    audit("slack_send", channel="c", title="t", message_len=1, success=True)
    recs = [json.loads(line) for line in captured]
    seqs = [r["seq"] for r in recs]
    assert seqs == list(range(seqs[0], seqs[0] + 3))   # contiguous, no repeats
    # One instance id partitions the seq stream, so gap detection is
    # self-contained even when replicas/restarts share a log index.
    instances = {r["instance"] for r in recs}
    assert len(instances) == 1
    assert next(iter(instances))                        # non-empty


def test_audit_auth_is_observed_not_asserted(captured):
    # No request object (poller / internal caller): the service observed no auth.
    audit("job_restart", success=True)
    assert json.loads(captured[-1])["auth"] == "none"
    # HTTP request: nothing in it is verifiable, so "unknown" — never "sso-gated",
    # which was previously stamped even on loopback/port-forward callers.
    audit("ai_query", _FakeReq(), question="q")
    assert json.loads(captured[-1])["auth"] == "unknown"
    assert "sso-gated" not in captured[-1]


def test_answer_sha256_is_allowlisted_byte_stable(captured):
    # A hex digest ending in a long digit run would be mangled by the CC mask if
    # it were not allowlisted; it must stay byte-stable for log-backend joins.
    digest = "a" * 51 + "1234567890123"
    audit("ai_query_result", status="ok", message_len=10, answer_sha256=digest)
    assert json.loads(captured[-1])["answer_sha256"] == digest


def test_audit_never_raises_on_bad_request(captured):
    # A request object missing .headers/.client must not break the caller.
    audit("ai_query", object(), question="x")
    assert len(captured) == 1
    assert json.loads(captured[0])["source_ip"] == "unknown"


def test_audit_write_tool_events(captured):
    # Coverage added for the review: direct config patches and job restarts must
    # each emit their own audit event, not only apply_remediation.
    audit("config_update", config_key="parallelism.default", config_value="10", success=True)
    audit("job_restart", success=True)
    assert len(captured) == 2
    cfg = json.loads(captured[0])
    assert cfg["event"] == "config_update"
    assert cfg["config_key"] == "parallelism.default"
    assert cfg["success"] is True
    restart = json.loads(captured[1])
    assert restart["event"] == "job_restart"
    assert restart["success"] is True


def test_audit_remediation_extracts_result_fields(captured):
    class _Result:
        remediation_type = "increase_parallelism"
        applied_by = "ai_agent_chat"
        success = True
        dry_run = False
        backup_created = "savepoint-trigger-123"
        changes_made = {"parallelism.default": "10"}

    audit_remediation(_Result())
    assert len(captured) == 1
    rec = json.loads(captured[0])
    assert rec["event"] == "remediation"
    assert rec["remediation_type"] == "increase_parallelism"
    assert rec["applied_by"] == "ai_agent_chat"      # trigger path, not the human
    assert rec["savepoint_id"] == "savepoint-trigger-123"
    assert rec["changes_made"] == {"parallelism.default": "10"}
    assert rec["success"] is True


# ── correlation id: ties an ai_query to the tool events it spawns ──
# Each test runs inside a fresh, empty contextvars.Context so a bound id never
# leaks across tests and the unbound case is guaranteed clean.

def test_correlation_id_absent_when_unbound(captured):
    def _run():
        assert get_correlation_id() is None          # fresh context → default
        audit("config_update", config_key="parallelism.default", config_value="8", success=True)
    contextvars.Context().run(_run)
    assert "correlation_id" not in json.loads(captured[-1])


def test_correlation_id_shared_by_query_and_tool_events(captured):
    # The query event (with a request → real source IP) and a downstream tool event
    # (no request → source_ip "unknown") must carry the SAME id so a forensic
    # reviewer can stitch them without timestamp guessing.
    def _run():
        cid = new_correlation_id()
        audit("ai_query", _FakeReq(headers={"x-forwarded-for": "203.0.113.7, 10.0.0.1, 10.0.0.2"}),
              question="why is it failing?")
        audit("job_restart", success=True)           # tool path: no request object
        return cid
    cid = contextvars.Context().run(_run)
    query_ev, tool_ev = json.loads(captured[-2]), json.loads(captured[-1])
    assert query_ev["correlation_id"] == cid
    assert tool_ev["correlation_id"] == cid
    assert query_ev["source_ip"] == "203.0.113.7"
    assert tool_ev["source_ip"] == "unknown"          # still correlated despite no IP


def test_correlation_id_propagates_to_spawned_task_context(captured):
    # Models the SSE path: the handler binds the id, then _produce() runs in a child
    # task. asyncio.create_task snapshots the current context, so the agent's tool
    # calls in that child task inherit the same id. copy_context() reproduces that
    # snapshot deterministically without an event loop.
    def _parent():
        cid = new_correlation_id()
        child_ctx = contextvars.copy_context()        # what create_task() captures
        child_ctx.run(lambda: audit("config_update", config_key="x", config_value="1", success=True))
        return cid
    cid = contextvars.Context().run(_parent)
    assert json.loads(captured[-1])["correlation_id"] == cid


def test_ensure_correlation_id_reuses_bound_id():
    # The agent entry points call ensure(); when the flow start (handler/poller)
    # already bound an id, ensure must NOT rebind — else the entry event and the
    # tool events would split into two chains.
    def _run():
        cid = new_correlation_id()
        assert ensure_correlation_id() == cid
        assert get_correlation_id() == cid
    contextvars.Context().run(_run)


def test_ensure_correlation_id_binds_when_absent(captured):
    # Models a caller that invokes the agent without binding first (the backstop
    # case): the tool-call chain still shares one id.
    def _run():
        assert get_correlation_id() is None           # nothing bound by the caller
        cid = ensure_correlation_id()                 # agent entry binds
        audit("config_update", config_key="x", config_value="1", success=True)
        audit("job_restart", success=True)
        return cid
    cid = contextvars.Context().run(_run)
    first, second = json.loads(captured[-2]), json.loads(captured[-1])
    assert first["correlation_id"] == cid
    assert second["correlation_id"] == cid


def test_correlation_ids_isolated_per_alert_task(captured):
    # Models the poller fan-out: each alert is analyzed in its own task
    # (asyncio.gather wraps coroutines in tasks, each with a context copy), so
    # per-alert ids must not bleed into sibling alerts.
    def _alert():
        new_correlation_id()
        audit("slack_send", channel="flink-alerts", title="t", message_len=1, success=True)
        return get_correlation_id()
    cid_a = contextvars.Context().run(_alert)
    cid_b = contextvars.Context().run(_alert)
    ev_a, ev_b = json.loads(captured[-2]), json.loads(captured[-1])
    assert ev_a["correlation_id"] == cid_a
    assert ev_b["correlation_id"] == cid_b
    assert cid_a != cid_b


# ── slack egress is audited ──

def test_slack_send_event_records_destination_and_size(captured):
    # send_to_slack relays diagnostics to an external channel; the audit records the
    # destination + payload size but never the message body itself.
    audit("slack_send", channel="flink-alerts", title="Flink AI Analysis",
          message_len=128, success=True)
    rec = json.loads(captured[-1])
    assert rec["event"] == "slack_send"
    assert rec["channel"] == "flink-alerts"
    assert rec["message_len"] == 128
    assert rec["success"] is True
    assert "message" not in rec                        # body is never logged, only its length


# ── redaction: sensitive data kept out of the durable sink (CWE-532) ──
# The audit line goes to the durable log backend, so free-text / model-controlled fields must
# be sanitized. Policy is a fail-safe allowlist applied at the single emit choke
# point: listed structured fields pass verbatim, everything else is scrubbed.

_SECRET = "password=hunter2"
_EMAIL = "jane.doe@acme.com"


@pytest.mark.parametrize("field", ["question", "title", "error", "future_unknown_field"])
def test_sensitive_freetext_fields_are_scrubbed(captured, field):
    # Any non-allowlisted field — including one that doesn't exist yet — is sanitized,
    # so a new call site cannot reintroduce the leak by omission (the original bug).
    audit("ai_query", _FakeReq(), **{field: f"{_SECRET} contact {_EMAIL}"})
    line = captured[-1]
    assert "hunter2" not in line
    assert _EMAIL not in line
    assert "<REDACTED:secret>" in line and "<REDACTED:email>" in line


def test_credential_named_keys_mask_their_string_values(captured):
    """Review #38 (audit sink half): `kafka.sasl.password: hunter2` has no
    secret-shaped value, so the text patterns passed it. The key names it."""
    audit("remediation", changes_made={
        "kafka.sasl.password": "hunter2",
        "parallelism.default": "10",
        "secretName": "flink-kafka-creds",
        "state.checkpoints.num-retained": 3,
    })
    rec = json.loads(captured[-1])
    assert rec["changes_made"]["kafka.sasl.password"] == "<REDACTED:secret>"
    assert rec["changes_made"]["parallelism.default"] == "10"
    assert rec["changes_made"]["secretName"] == "flink-kafka-creds"
    assert rec["changes_made"]["state.checkpoints.num-retained"] == 3
    assert "hunter2" not in captured[-1]


def test_credential_named_keys_mask_container_values_whole(captured):
    """Round-2 review: only STRING values under a sensitive key were masked, so
    `{"credentials": {"db": "hunter2"}, "password": ["hunter2"]}` landed in the
    durable sink verbatim. The whole subtree is masked now, and `auth` / the
    plural forms count as credential keys."""
    audit("remediation", changes_made={
        "credentials": {"db": "hunter2", "cache": {"redis": "hunter2"}},
        "password": ["hunter2"],
        "auth": {"user": "svc", "pass": "hunter2"},
        "secrets": ["hunter2"],
        "tokens": {"a": "hunter2"},
        "passwords": ["hunter2"],
        "api_keys": ["hunter2"],
        "parallelism.default": "10",
        "kafka": {"bootstrap.servers": "kafka:9092", "sasl.password": "hunter2"},
    })
    line = captured[-1]
    rec = json.loads(line)["changes_made"]
    for k in ("credentials", "password", "auth", "secrets", "tokens", "passwords", "api_keys"):
        assert rec[k] == "<REDACTED:secret>", k
    assert rec["parallelism.default"] == "10"
    assert rec["kafka"]["bootstrap.servers"] == "kafka:9092"
    assert rec["kafka"]["sasl.password"] == "<REDACTED:secret>"
    assert "hunter2" not in line


def test_env_style_key_value_secrets_are_scrubbed_in_freetext(captured):
    """Round-2 review: the `\\b` boundary let `DB_PASSWORD=hunter2` through the
    audit sink's text scrub because `_` is a word character."""
    audit("ai_query", _FakeReq(), question=(
        "env: DB_PASSWORD=hunter2 AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI "
        "GITHUB_TOKEN=ghp_short client_secret=abc passwordless_login=true token_count=7"
    ))
    line = captured[-1]
    for leaked in ("hunter2", "wJalrXUtnFEMI", "ghp_short", "client_secret=abc"):
        assert leaked not in line, leaked
    assert "passwordless_login=true" in line
    assert "token_count=7" in line


def test_auth_scheme_header_values_are_scrubbed_whole_in_freetext(captured):
    """Round-3 review: `Authorization: Bearer <token>` lost only the word
    Bearer to the key=value rule; the token itself reached the audit sink."""
    audit("ai_query", _FakeReq(), question=(
        "curl -H 'Authorization: Bearer opaque0123456789abcdef' "
        "-H 'Proxy-Authorization: Basic ZGVtbzpzM2NyM3Q=' https://api/"
    ))
    line = captured[-1]
    assert "opaque0123456789abcdef" not in line
    assert "ZGVtbzpzM2NyM3Q=" not in line
    assert "<REDACTED:secret>" in line


def test_single_quoted_values_are_scrubbed_in_freetext(captured):
    """Round-4 review: the key=value rule accepted only `"` as the quote, so
    `password='hunter2'` (Kafka JAAS), `export DB_PASSWORD='hunter2'` and
    `-Dpassword='hunter2'` reached the audit sink verbatim."""
    audit("ai_query", _FakeReq(), question=(
        "PlainLoginModule required username='alice' password='hunter2'; "
        "export DB_PASSWORD='hunter2'; java -Dpassword='hunter2' -jar app.jar; "
        "it's a password' reset"
    ))
    line = captured[-1]
    assert "hunter2" not in line
    assert line.count("<REDACTED:secret>") >= 3
    assert "it's a password' reset" in line          # prose with apostrophes is not mangled


def test_jaas_config_key_masks_whole_value(captured):
    audit("remediation", changes_made={
        "sasl.jaas.config": "org.apache.kafka.common.security.plain.PlainLoginModule required username='a' password='hunter2';",
        "sasl.mechanism": "PLAIN",
    })
    rec = json.loads(captured[-1])["changes_made"]
    assert rec["sasl.jaas.config"] == "<REDACTED:secret>"
    assert rec["sasl.mechanism"] == "PLAIN"


def test_auth_scheme_at_end_of_line_keeps_the_next_line(captured):
    """Round-4 minor: `Bearer\\s+` crossed the newline and consumed the next
    line's first token as the credential."""
    audit("ai_query", _FakeReq(), question="Authorization: Bearer\nparallelism.default=4")
    rec = json.loads(captured[-1])
    assert rec["question"].endswith("\nparallelism.default=4")


def test_nested_changes_made_leaves_are_scrubbed(captured):
    # changes_made is intentionally NOT allowlisted, so its nested leaf values are
    # walked and sanitized — closing the latent F6 (a secret one level down).
    class _Result:
        remediation_type = "x"
        applied_by = "ai_agent_chat"
        success = True
        dry_run = False
        backup_created = "sp-1"
        changes_made = {"config": "token=ABCDEF1234567890", "nested": {"code_example": _SECRET}}  # gitleaks:allow — synthetic fixture exercising redaction

    audit_remediation(_Result())
    line = captured[-1]
    rec = json.loads(line)
    assert "ABCDEF1234567890" not in line and "hunter2" not in line
    assert "<REDACTED:secret>" in line
    assert set(rec["changes_made"].keys()) == {"config", "nested"}      # structure kept
    assert "code_example" in rec["changes_made"]["nested"]


def test_allowlisted_fields_are_byte_stable(captured):
    # Forensic values must NOT be mangled by masking — even when they look like data
    # (savepoint id with a long digit run the CC pattern would otherwise hit).
    audit("remediation",
          _FakeReq(headers={"x-forwarded-for": "203.0.113.7, 10.0.0.1, 10.0.0.2"}),
          savepoint_id="savepoint-trigger-0000111122223333", success=True, dry_run=False)
    rec = json.loads(captured[-1])
    assert rec["savepoint_id"] == "savepoint-trigger-0000111122223333"
    # forwarded_for is no longer allowlisted; a normal chain passes the scrubber
    # unchanged, so the forensic value is intact even though it is now sanitized.
    assert rec["forwarded_for"] == "203.0.113.7, 10.0.0.1, 10.0.0.2"
    assert rec["source_ip"] == "203.0.113.7"
    assert rec["success"] is True and rec["dry_run"] is False           # types preserved


def test_forwarded_for_is_bounded_and_masked(captured):
    # The raw XFF header is caller-controlled: an 8KB header must be truncated at
    # the sanitizer bound (2048 + marker), and an embedded secret must be masked —
    # it can no longer ride the allowlist into the durable sink verbatim.
    huge = "password=hunter2, " + "1.2.3.4, " * 1200
    assert len(huge) > 8000
    audit("ai_query", _FakeReq(headers={"x-forwarded-for": huge}))
    rec = json.loads(captured[-1])
    # Truncated at the sanitizer bound (small slack for mask expansion + marker).
    assert len(rec["forwarded_for"]) < 2048 + 100
    assert "...[truncated]" in rec["forwarded_for"]
    # The secret inside the truncation window is masked, not persisted.
    assert "hunter2" not in captured[-1]
    assert "<REDACTED:secret>" in rec["forwarded_for"]


def test_config_value_is_scrubbed_if_ever_passed(captured):
    # Defense in depth: the call site logs the key only, but if any path passes a
    # value, the central layer still masks it.
    audit("config_update", config_key="parallelism.default", config_value=_SECRET, success=True)
    rec = json.loads(captured[-1])
    assert "hunter2" not in captured[-1]
    assert rec["config_key"] == "parallelism.default"                  # key kept for forensics
    assert rec["success"] is True


def test_long_freetext_is_truncated(captured):
    audit("ai_query", _FakeReq(), question="A" * 5000)
    q = json.loads(captured[-1])["question"]
    assert len(q) < 5000 and q.endswith("...[truncated]")


def test_emitted_record_is_a_single_json_line(captured):
    # A newline in a value must not split one event into two malformed log lines.
    audit("ai_query", _FakeReq(), question="line1\nline2 " + _SECRET)
    assert len(captured) == 1
    assert "\n" not in captured[0]            # newline stays JSON-escaped
    json.loads(captured[0])                   # still one parseable object
    assert "hunter2" not in captured[0]


def test_redaction_failure_never_drops_the_line(captured):
    # A value whose str() raises must degrade to a placeholder, not lose the record —
    # the stdout line is the only durable store, so a dropped line is lost audit.
    class _Boom:
        def __str__(self):
            raise RuntimeError("boom")
        __repr__ = __str__

    audit("ai_query", _FakeReq(), question="hi", weird=_Boom())
    rec = json.loads(captured[-1])
    assert rec["event"] == "ai_query"
    assert rec["question"] == "hi"
    assert rec["weird"] == "<redaction-error>"


def test_model_controlled_config_key_is_scrubbed(captured):
    # config_key is model-controlled (arg-inversion / jailbreak could place a secret
    # there), so it is NOT allowlisted — a legitimate Flink key passes unchanged,
    # an injected secret is masked.
    audit("config_update", config_key="parallelism.default", success=True)
    assert json.loads(captured[-1])["config_key"] == "parallelism.default"
    audit("config_update", config_key="sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAA", success=True)
    assert "sk-ant-api03" not in captured[-1]


def test_bare_jwt_is_redacted(captured):
    jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpM"  # gitleaks:allow — synthetic fixture exercising redaction
    audit("ai_query", _FakeReq(), question=f"my token is {jwt}")
    assert jwt not in captured[-1]
    assert "<REDACTED:jwt>" in captured[-1]


def test_url_basic_auth_is_redacted(captured):
    audit("config_update", config_key="x", success=False,
          error="connect failed: https://admin:hunter2@k8s-api.internal:6443/api")
    line = captured[-1]
    assert "hunter2" not in line and "admin:hunter2" not in line
    assert "<REDACTED:url-auth>" in line


def test_trusted_proxy_hops_upper_bound(monkeypatch):
    # A misconfigured huge hop count is capped, so a long chain still selects a
    # bounded right-indexed entry rather than degrading to the spoofable leftmost.
    monkeypatch.setenv("AUDIT_TRUSTED_PROXY_HOPS", "99")
    parts = [f"10.0.0.{i}" for i in range(1, 12)]       # 11 entries
    ip = client_ip(_FakeReq(headers={"x-forwarded-for": ", ".join(parts)}))
    assert ip == parts[-10]          # capped at 10, not 99
    assert ip != parts[0]            # did not fall back to the spoofable leftmost


# ── _configure() must not be suppressed by a foreign handler ───────────────────
#
# Pitfall: _configure() used to set level (INFO) and propagate=False only when
# the logger had NO handlers. Anything that attached a handler to "app.audit"
# before this module was first imported — a test capture fixture in a subset
# run, an in-process log shipper — left the logger at NOTSET, inheriting the
# root WARNING threshold, so every INFO audit record was silently dropped.
# `pytest tests/test_audit_coverage.py` alone failed 7/11 for exactly this reason.

def test_configure_sets_level_and_propagate_even_when_a_foreign_handler_came_first():
    from app import audit as audit_mod

    logger = logging.getLogger("app.audit")
    saved = (logger.level, logger.propagate, list(logger.handlers))
    delivered = []

    class _Foreign(logging.Handler):
        def emit(self, record):
            delivered.append(record.getMessage())

    foreign = _Foreign()
    try:
        # Recreate the pre-import state with a foreign handler already attached.
        for h in list(logger.handlers):
            logger.removeHandler(h)
        logger.setLevel(logging.NOTSET)
        logger.propagate = True
        logger.addHandler(foreign)

        audit_mod._configure()

        assert logger.level == logging.INFO, (
            "audit logger must set its own INFO level — at NOTSET it inherits the "
            "root WARNING threshold and drops every audit record"
        )
        assert logger.propagate is False, "audit lines must not double-emit via the root formatter"
        own = [h for h in logger.handlers if getattr(h, audit_mod._OWN_HANDLER_MARK, False)]
        assert len(own) == 1, "exactly one owned stdout handler must be attached"
        assert foreign in logger.handlers, "the foreign handler must be left in place"

        audit("config_order_probe")
        assert any("config_order_probe" in line for line in delivered), (
            "INFO audit records must reach handlers attached to the app.audit logger"
        )

        # Idempotent: a second _configure() never stacks a second stdout handler.
        audit_mod._configure()
        own = [h for h in logger.handlers if getattr(h, audit_mod._OWN_HANDLER_MARK, False)]
        assert len(own) == 1
    finally:
        for h in list(logger.handlers):
            logger.removeHandler(h)
        for h in saved[2]:
            logger.addHandler(h)
        logger.setLevel(saved[0])
        logger.propagate = saved[1]
