# Copyright Yahoo, Licensed under the terms of the Apache 2.0 license. See LICENSE for terms.

"""Attribution tests for the remediation API.

`applied_by` is the trigger path (chat / REST / alert / system), never the human
user (see app/audit.py's module docstring on identity). It used to be a
caller-supplied request field, which let a REST caller write a human-looking name
(e.g. "sre-oncall") into an otherwise-anonymous audit record. The field was removed
from RemediationRequest: any `applied_by` key in the body is IGNORED and the route
always records the server-set constant "rest".

These tests encode the ticket's acceptance criteria:
  1. A caller-supplied `applied_by` never surfaces in the response, the audit
     event, or the remediation history — the server constant "rest" does.
  2. Two requests differing only in `applied_by` produce identical audit records
     (modulo timestamp / correlation id).
  3. The historical injection payloads (markup, log-control chars) no longer have
     a sink at all — they are dropped before validation could even matter.

Imports the FastAPI app, so it needs the app dependencies (fastapi, langchain, ...).
runs in CI (the built image does not contain tests/); in a bare local shell without those deps it
skips cleanly via importorskip — same pattern as test_cors.py.
"""
import importlib
import json
import logging

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402


class _FakeFlinkClient:
    """No running job → apply_remediation returns early, before any cluster call."""

    async def get_running_job_id(self):
        return None


def _client(monkeypatch, write_tools=False):
    monkeypatch.setenv("SECRET_PROVIDER", "env")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "dummy")
    # Several POSTs per test; the remediation routes' rate limit has its own test.
    monkeypatch.setenv("RATE_LIMIT_HEAVY_PER_MINUTE", "100")
    if write_tools:
        # Enable the write gate; DEPLOY_ENV unset ⇒ non-production, so the
        # one-way production hard-stop does not trip (see app/write_authz.py).
        monkeypatch.setenv("ENABLE_WRITE_TOOLS", "true")
        # The gate fails closed on a blank/unknown domain: a
        # positively-identified nonprod domain is required to enable writes.
        monkeypatch.setenv("DEPLOY_ENV", "nonprod")
    else:
        monkeypatch.delenv("ENABLE_WRITE_TOOLS", raising=False)
    import app.main as main
    importlib.reload(main)
    # Keep the remediator off the network: no running job ⇒ early return, but the
    # result (and its audit event) still carries the server-set applied_by.
    main.auto_remediator.flink_client = _FakeFlinkClient()
    main.auto_remediator.history.clear()
    return main, TestClient(main._app)


@pytest.fixture
def captured_audit():
    """Capture JSON lines emitted on the app.audit logger."""
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


def _apply(client, extra_body=None):
    body = {"type": "create_emergency_savepoint", "dry_run": True}
    body.update(extra_body or {})
    return client.post("/api/remediation/apply", json=body)


# ── the caller cannot assert attribution ──────────────────────────────────────

def test_applied_by_is_ignored_and_server_sets_rest(monkeypatch, captured_audit):
    # Core acceptance test: a human-looking caller-supplied
    # value must be dropped; the response, the audit event, and the history all
    # carry the server-set trigger path "rest".
    main, client = _client(monkeypatch, write_tools=True)
    resp = _apply(client, {"applied_by": "sre-oncall"})
    assert resp.status_code == 200
    assert resp.json()["applied_by"] == "rest"
    assert "sre-oncall" not in resp.text

    remediation_events = [json.loads(r) for r in captured_audit
                          if json.loads(r).get("event") == "remediation"]
    assert len(remediation_events) == 1
    assert remediation_events[0]["applied_by"] == "rest"
    assert "sre-oncall" not in captured_audit[-1]

    history = client.get("/api/remediation/history").json()["history"]
    assert history and all(h["applied_by"] == "rest" for h in history)


def test_audit_record_is_identical_regardless_of_applied_by(monkeypatch, captured_audit):
    # Ticket validation: re-run with a different applied_by and confirm the audit
    # record is identical apart from timestamp / correlation id.
    main, client = _client(monkeypatch, write_tools=True)
    _apply(client, {"applied_by": "sre-oncall"})
    _apply(client, {"applied_by": "anything"})

    events = [json.loads(r) for r in captured_audit
              if json.loads(r).get("event") == "remediation"]
    assert len(events) == 2
    for ev in events:
        ev.pop("ts", None)
        ev.pop("correlation_id", None)
        ev.pop("seq", None)  # per-record monotonic counter differs by design
        ev.pop("id", None)   # stable per-result id differs by design
    assert events[0] == events[1]


@pytest.mark.parametrize("value", [
    "<script>alert(1)</script>",   # historical DAST markup payload
    "alice\n2026 fake-event",      # log-line forgery attempt (CWE-117)
    "a" * 101,                     # formerly over-length
])
def test_injection_payloads_have_no_sink(monkeypatch, captured_audit, value):
    # These payloads used to be validation-rejected (422). Now the field itself is
    # gone: the request succeeds, the payload is dropped, and it never appears in
    # the audit stream or the remediation history.
    main, client = _client(monkeypatch, write_tools=True)
    resp = _apply(client, {"applied_by": value})
    assert resp.status_code == 200
    assert resp.json()["applied_by"] == "rest"
    assert value not in resp.text
    assert all(value not in line for line in captured_audit)
    assert value not in json.dumps(client.get("/api/remediation/history").json())


# ── the write-authz gate is unchanged ─────────────────────────────────────────

def test_write_gate_still_denies_when_disabled(monkeypatch):
    # Removing the field must not loosen the gate: with write tools disabled the
    # route still 403s, and a stray applied_by key changes nothing (no 422 either —
    # unknown keys are ignored, not rejected).
    # A savepoint-counting Flink stub (with a running job) proves the refusal
    # happens before the remediator touches the cluster, not merely that the
    # status code is 403.
    main, client = _client(monkeypatch, write_tools=False)
    flink = _RecordingFlink()
    main.auto_remediator.flink_client = flink
    assert _apply(client).status_code == 403
    assert _apply(client, {"applied_by": "sre-oncall"}).status_code == 403
    assert _apply(client, {"dry_run": False}).status_code == 403
    assert flink.savepoints == 0, "a refused request reached the cluster"


# ── safe-by-default dry_run + gated rollback route ─────────────────────────────
#
# 1. The live path fires a real savepoint against the running job, so acting
#    requires the caller to name it (dry_run=False). At the savepoint-triggering
#    sink (AutoRemediator.apply_remediation) dry_run is keyword-only with NO
#    default — omission is a TypeError. At the two surfaces where a caller can
#    actually omit the flag (the agent tool schema the model sees, and the REST
#    RemediationRequest model) omission PREVIEWS.
# 2. POST /api/remediation/rollback must carry the same write gate as its sibling
#    /api/remediation/apply. rollback() is a pure lookup today, but the gate must
#    not depend on that staying true.


def _run(coro):
    import asyncio
    return asyncio.new_event_loop().run_until_complete(coro)


class _RecordingFlink:
    """Counts savepoints so the negative tests fail if the control is inactive."""

    def __init__(self):
        self.savepoints = 0

    async def get_running_job_id(self):
        return "job-abc"

    async def trigger_savepoint(self, job_id):
        self.savepoints += 1
        return {"request-id": f"sp-{self.savepoints}"}

    async def get_savepoint_status(self, job_id, trigger_id):
        return {"status": {"id": "COMPLETED"}, "operation": {"location": "file:///sp"}}


def test_method_requires_explicit_dry_run_and_omission_takes_no_savepoint():
    # Core acceptance test (negative): the sink has no default — omitting dry_run
    # is a TypeError raised at call time, before any cluster call. Before the fix
    # omission silently created a real savepoint.
    ar = pytest.importorskip("app.auto_remediator")
    flink = _RecordingFlink()
    remediator = ar.AutoRemediator(flink_client=flink, k8s_client=None)
    action = remediator.create_action(ar.RemediationType.INCREASE_CHECKPOINT_TIMEOUT)

    with pytest.raises(TypeError, match="dry_run"):
        remediator.apply_remediation(action, applied_by="test")  # no dry_run
    # ...and it cannot be smuggled in positionally either.
    with pytest.raises(TypeError):
        remediator.apply_remediation(action, "test", False)

    assert flink.savepoints == 0, "omitting dry_run fired a real savepoint"

    # Explicit preview: success-shaped, but no savepoint and no backup id.
    result = _run(remediator.apply_remediation(action, applied_by="test", dry_run=True))
    assert result.dry_run is True
    assert result.success is True
    assert result.backup_created is None, "a savepoint trigger id was recorded on a preview"
    assert flink.savepoints == 0


def test_explicit_dry_run_false_still_applies_and_takes_savepoint():
    # The explicit path must keep working — the fix must not disable the feature.
    ar = pytest.importorskip("app.auto_remediator")
    flink = _RecordingFlink()
    remediator = ar.AutoRemediator(flink_client=flink, k8s_client=None)
    applied = {}

    async def _fake_apply(config_changes):
        applied.update(config_changes)

    remediator._apply_config_via_k8s = _fake_apply
    action = remediator.create_action(ar.RemediationType.INCREASE_CHECKPOINT_TIMEOUT)

    result = _run(remediator.apply_remediation(action, applied_by="test", dry_run=False))

    assert result.dry_run is False
    assert result.success is True
    assert flink.savepoints == 1, "the savepoint-before-remediation invariant broke"
    assert result.backup_created == "sp-1"
    assert applied == {"execution.checkpointing.timeout": "600000"}


def test_agent_tool_defaults_to_preview(monkeypatch):
    # The tool-schema default is what the model sees; invoking without dry_run
    # must preview and take no savepoint. The docstring is load-bearing: it must
    # tell the model to pass dry_run=False explicitly to apply.
    pytest.importorskip("langchain_core")
    ar = pytest.importorskip("app.auto_remediator")
    monkeypatch.setenv("SECRET_PROVIDER", "env")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "dummy")
    monkeypatch.setenv("ENABLE_WRITE_TOOLS", "true")
    monkeypatch.setenv("DEPLOY_ENV", "nonprod")
    from app import langgraph_agent as lga

    agent = object.__new__(lga.LangGraphAgent)
    agent.flink_client = None
    agent.k8s_client = None
    agent.postgres_reader = None
    flink = _RecordingFlink()
    agent.auto_remediator = ar.AutoRemediator(flink_client=flink, k8s_client=None)
    agent.slack_client = None
    agent.github_client = None
    tools = agent._create_tools()
    tool = next(t for t in tools if t.name == "apply_remediation")

    schema = tool.tool_call_schema.model_json_schema()
    assert schema["properties"]["dry_run"].get("default") is True, (
        "the model-visible schema default must be preview"
    )
    assert "dry_run=False" in tool.description, (
        "the docstring must instruct the model to opt in explicitly to apply"
    )

    raw = _run(tool.ainvoke({"remediation_type": "increase_checkpoint_timeout"}))
    result = json.loads(lga._unfenced(raw))  # tool returns are provenance-fenced
    assert result["dry_run"] is True
    assert result["success"] is True
    assert result["backup_created"] is None
    assert flink.savepoints == 0
    # The tool response carries the stable history id (review round 3, minor),
    # and the docstring tells the model ids are per-pod: (instance, id) joins.
    assert result["id"] == 0
    assert "(instance, id)" in tool.description


def test_system_prompt_treats_preview_as_not_a_write(monkeypatch):
    # The prompt sections that consume apply_remediation results must not
    # assume apply-by-default: a preview returns success: true, so the stop
    # rule, the Response Template and the alert-triggered strategy each need
    # the dry_run distinction, and the capabilities block must say the tool
    # previews by default. Deterministic proxy for model behaviour; live
    # adherence is checked by the runtime probe.
    pytest.importorskip("langchain_core")
    monkeypatch.setenv("SECRET_PROVIDER", "env")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "dummy")
    monkeypatch.setenv("ENABLE_WRITE_TOOLS", "true")
    monkeypatch.setenv("DEPLOY_ENV", "nonprod")
    from app import langgraph_agent as lga

    prompt = lga.SYSTEM_PROMPT
    stop_rule = prompt.split("## Iteration Discipline")[1].split("## Key Principle")[0]
    assert '"dry_run": true' in stop_rule and "PREVIEW" in stop_rule
    assert "does NOT satisfy this stop rule" in stop_rule

    action_section = prompt.split("## Action\n")[1].split("## Next steps")[0]
    assert "Previewed" in action_section and '"dry_run": true' in action_section
    assert "never ACTION TAKEN" in action_section

    strategy = prompt.split("### Action types")[1].split("For interactive operator")[0]
    assert "dry_run=false" in strategy, "alert-triggered runs must opt in to act"

    caps = lga._build_capabilities_block()
    assert "Previews by default" in caps and "dry_run=false" in caps
    assert "dry_run=false" in lga._WRITE_CAPABILITIES


def test_rest_apply_omission_previews_and_explicit_false_applies(monkeypatch):
    # The human-driven REST surface follows the same omission semantics as the
    # agent tool: a body without dry_run previews; "dry_run": false applies.
    main, client = _client(monkeypatch, write_tools=True)
    flink = _RecordingFlink()
    main.auto_remediator.flink_client = flink

    resp = client.post("/api/remediation/apply", json={"type": "create_emergency_savepoint"})
    assert resp.status_code == 200
    assert resp.json()["dry_run"] is True
    assert flink.savepoints == 0, "a REST body without dry_run fired a real savepoint"

    resp = client.post("/api/remediation/apply",
                       json={"type": "create_emergency_savepoint", "dry_run": False})
    assert resp.status_code == 200
    assert resp.json()["dry_run"] is False
    # Live path for this type = the emergency savepoint itself, waited on until
    # COMPLETED (no separate backup savepoint: the action IS the savepoint).
    assert flink.savepoints == 1, "explicit dry_run=false must still act"


def test_rollback_route_denied_when_write_tools_disabled(monkeypatch, captured_audit):
    # Core acceptance test: with the gate off, rollback 403s exactly like its
    # sibling /apply (before the fix it returned 200), and the denial is audited.
    _, client = _client(monkeypatch, write_tools=False)
    resp = client.post("/api/remediation/rollback", json={"id": 7})
    assert resp.status_code == 403
    assert _apply(client).status_code == 403, "the sibling routes must agree"

    denials = [json.loads(r) for r in captured_audit
               if json.loads(r).get("event") == "remediation_denied"]
    # Filter to the ROLLBACK denial specifically — the sibling /apply call above
    # also emits remediation_denied, so an unfiltered "any denial" assertion would
    # stay green even if the rollback route's audit call were deleted.
    rollback_denials = [d for d in denials if d.get("requested_action") == "rollback"]
    assert len(rollback_denials) == 1, denials
    assert rollback_denials[0]["reason"] == "write_tools_disabled"
    # The audit field is the stable ``id``, the same key the
    # body carries; the positional ``index`` key is rejected (see below).
    assert rollback_denials[0]["id"] == 7
    # And the /apply denial is still the separately-shaped event it always was.
    apply_denials = [d for d in denials if d.get("requested_type") == "create_emergency_savepoint"]
    assert len(apply_denials) == 1


def test_rollback_route_still_works_when_enabled(monkeypatch):
    # The gate must not break the feature: enabled, the route behaves as before.
    main, client = _client(monkeypatch, write_tools=True)

    # Empty history → invalid id, but NOT a 403.
    resp = client.post("/api/remediation/rollback", json={"id": 0})
    assert resp.status_code == 200
    assert resp.json() == {"success": False, "message": "Invalid remediation id"}

    # A real apply (savepoint taken, patch faked) → its savepoint info comes back
    # unchanged when addressed by the stable id the apply reported.
    ar = pytest.importorskip("app.auto_remediator")
    remediator = main.auto_remediator
    remediator.flink_client = _RecordingFlink()

    async def _no_patch(config_changes):
        return None

    remediator._apply_config_via_k8s = _no_patch
    action = remediator.create_action(ar.RemediationType.INCREASE_CHECKPOINT_TIMEOUT)
    real = _run(remediator.apply_remediation(action, applied_by="test", dry_run=False))
    assert real.id == 0

    resp = client.post("/api/remediation/rollback", json={"id": 0})
    assert resp.status_code == 200
    body = resp.json()
    assert body["success"] is True
    assert body["savepoint_info"] == {"savepoint_trigger_id": "sp-1", "job_id": "job-abc"}


def test_rollback_route_rejects_positional_index_with_pointer(monkeypatch):
    # API contract change (review round 3): ``{"index": N}`` is 422, not an
    # alias for ``id`` — after eviction the alias rolled back the WRONG entry
    # with success: true. The 422 message must point the caller at history[].id,
    # and an ambiguous body carrying both keys is rejected the same way.
    _, client = _client(monkeypatch, write_tools=True)

    for body in ({"index": 60}, {"id": 5, "index": 60}):
        resp = client.post("/api/remediation/rollback", json=body)
        assert resp.status_code == 422, body
        detail = json.dumps(resp.json())
        assert "history[].id" in detail, detail
        assert "'index' is no longer accepted" in detail, detail

    # Missing id altogether is the ordinary field-required 422.
    assert client.post("/api/remediation/rollback", json={}).status_code == 422
    # ...and the correct key still works (empty history → clean rejection, 200).
    resp = client.post("/api/remediation/rollback", json={"id": 60})
    assert resp.status_code == 200
    assert resp.json() == {"success": False, "message": "Invalid remediation id"}


def test_history_route_remains_read_only_and_ungated(monkeypatch):
    # Explicitly out of scope for the gate: /history is genuinely read-only and
    # must keep answering with write tools disabled.
    _, client = _client(monkeypatch, write_tools=False)
    resp = client.get("/api/remediation/history")
    assert resp.status_code == 200
    assert resp.json() == {"history": []}


# ── A live remediation waits for a COMPLETED savepoint, or stops ──────────────

class _SavepointFlink:
    def __init__(self, trigger=None, statuses=None, raise_on_trigger=False):
        self.trigger = {"request-id": "sp-1"} if trigger is None else trigger
        self.statuses = list(statuses or [])
        self.raise_on_trigger = raise_on_trigger
        self.polls = 0

    async def get_running_job_id(self):
        return "job-abc"

    async def trigger_savepoint(self, job_id):
        if self.raise_on_trigger:
            raise RuntimeError("savepoint REST call failed")
        return self.trigger

    async def get_savepoint_status(self, job_id, trigger_id):
        self.polls += 1
        if len(self.statuses) > 1:
            return self.statuses.pop(0)
        return self.statuses[0] if self.statuses else {"status": {"id": "IN_PROGRESS"}}


_IN_PROGRESS = {"status": {"id": "IN_PROGRESS"}}
_FAILED = {"status": {"id": "COMPLETED"}, "operation": {"failure-cause": {"class": "x"}}}
_DONE = {"status": {"id": "COMPLETED"}, "operation": {"location": "s3://bucket/sp-1"}}


@pytest.mark.parametrize("flink,expect_patch", [
    (_SavepointFlink(raise_on_trigger=True), False),                  # (a) trigger raises
    (_SavepointFlink(trigger={}), False),                             # (b) no request id
    (_SavepointFlink(statuses=[_IN_PROGRESS, _FAILED]), False),       # (c) completed with failure
    (_SavepointFlink(statuses=[_IN_PROGRESS]), False),                # never completes (timeout)
    (_SavepointFlink(statuses=[_IN_PROGRESS, _DONE]), True),          # (d) completed with location
])
def test_live_remediation_patches_only_after_completed_savepoint(monkeypatch, flink, expect_patch):
    ar = pytest.importorskip("app.auto_remediator")
    monkeypatch.setenv("SAVEPOINT_POLL_INTERVAL_SECONDS", "0.01")
    monkeypatch.setenv("SAVEPOINT_COMPLETION_TIMEOUT_SECONDS", "1")
    remediator = ar.AutoRemediator(flink_client=flink, k8s_client=None)
    patches = []

    async def _fake_apply(config_changes):
        patches.append(dict(config_changes))

    remediator._apply_config_via_k8s = _fake_apply
    action = remediator.create_action(ar.RemediationType.INCREASE_CHECKPOINT_TIMEOUT)
    result = _run(remediator.apply_remediation(action, applied_by="test", dry_run=False))

    if expect_patch:
        assert patches == [{"execution.checkpointing.timeout": "600000"}]
        assert result.success is True and result.backup_created == "sp-1"
    else:
        assert patches == [], "the job was patched without a completed savepoint"
        assert result.success is False
        assert result.backup_created is None
        assert "savepoint" in result.message.lower()


def test_emergency_savepoint_reports_failure_when_it_does_not_complete(monkeypatch):
    ar = pytest.importorskip("app.auto_remediator")
    monkeypatch.setenv("SAVEPOINT_POLL_INTERVAL_SECONDS", "0.01")
    monkeypatch.setenv("SAVEPOINT_COMPLETION_TIMEOUT_SECONDS", "1")
    remediator = ar.AutoRemediator(flink_client=_SavepointFlink(statuses=[_FAILED]), k8s_client=None)
    action = remediator.create_action(ar.RemediationType.CREATE_EMERGENCY_SAVEPOINT)
    result = _run(remediator.apply_remediation(action, applied_by="test", dry_run=False))
    assert result.success is False

    remediator = ar.AutoRemediator(flink_client=_SavepointFlink(statuses=[_DONE]), k8s_client=None)
    result = _run(remediator.apply_remediation(action, applied_by="test", dry_run=False))
    assert result.success is True
