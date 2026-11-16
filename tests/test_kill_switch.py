"""Runtime kill switch + poller lifecycle.

Covers the three code-level gaps behind the finding:
1. agent_halted() — file-backed flag that is mutable in a running container,
   enforced per operation (each agent write tool body + the REST write routes),
   NOT inside write_tools_enabled(): that gate runs at agent construction, so a
   halt there would be baked into the graph and outlive the release.
2. GrafanaAlertPoller.stop() — prompt (task retained and cancelled), and the
   poll loop idles while the switch is engaged.
3. shutdown_event() — actually reaches and stops the module-scope poller.

No pytest-asyncio in this suite: async paths run via the same
new_event_loop().run_until_complete idiom the sibling tests use.
"""

import asyncio
import logging
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
import yaml

from app import write_authz


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


# ── agent_halted / write_tools_enabled ──────────────────────────────────────


def _set_kill_file(monkeypatch, tmp_path, content):
    kill_file = tmp_path / "kill-switch"
    if content is not None:
        kill_file.write_text(content)
    monkeypatch.setenv("AGENT_KILL_SWITCH_FILE", str(kill_file))
    return kill_file


@pytest.mark.parametrize("content,expected", [
    ("true", True),
    ("TRUE\n", True),
    ("1", True),
    ("halt", True),
    ("false", False),
    ("0", False),
    ("", False),
    (None, False),  # file absent -> fail open (containment, not authz)
])
def test_agent_halted_values(monkeypatch, tmp_path, content, expected):
    _set_kill_file(monkeypatch, tmp_path, content)
    assert write_authz.agent_halted() is expected


def test_agent_halted_fails_open_on_unreadable_path(monkeypatch, tmp_path, caplog):
    # A directory raises OSError (non-ENOENT) on read_text -> fail open by
    # design, but NOT silently: the failure is logged once per episode.
    monkeypatch.setenv("AGENT_KILL_SWITCH_FILE", str(tmp_path))
    monkeypatch.setattr(write_authz, "_halt_read_error_warned", False)
    with caplog.at_level(logging.WARNING, logger="app.write_authz"):
        assert write_authz.agent_halted() is False
        assert write_authz.agent_halted() is False  # second call: latched
    warnings = [r for r in caplog.records if "failing OPEN" in r.getMessage()]
    assert len(warnings) == 1  # latched within one failure episode


def test_agent_halted_warning_latch_resets_after_recovery(monkeypatch, tmp_path, caplog):
    """Round-2 minor: the unreadable-file warning was a once-per-PROCESS latch,
    so a file that broke, was repaired, and broke again warned only for the
    first episode. Sequence: fail -> warn once; recover -> read works and the
    latch re-arms; fail again -> warn again."""
    kill_file = tmp_path / "kill-switch"
    monkeypatch.setenv("AGENT_KILL_SWITCH_FILE", str(kill_file))
    monkeypatch.setattr(write_authz, "_halt_read_error_warned", False)

    def _warnings():
        return [r for r in caplog.records
                if r.levelno == logging.WARNING and "failing OPEN" in r.getMessage()]

    with caplog.at_level(logging.INFO, logger="app.write_authz"):
        # Episode 1: binaryData-shaped content -> unreadable, warn once.
        kill_file.write_bytes(_BINARY_KILL_CONTENT)
        assert write_authz.agent_halted() is False
        assert write_authz.agent_halted() is False
        assert len(_warnings()) == 1

        # Recovery: the file reads again; the real value is returned and the
        # recovery is announced once.
        kill_file.write_text("true")
        assert write_authz.agent_halted() is True
        assert write_authz.agent_halted() is True
        recovered = [r for r in caplog.records if "readable again" in r.getMessage()]
        assert len(recovered) == 1
        assert write_authz._halt_read_error_warned is False

        # Episode 2: breaks again -> a SECOND warning (not swallowed).
        kill_file.write_bytes(_BINARY_KILL_CONTENT)
        assert write_authz.agent_halted() is False
        assert len(_warnings()) == 2
        assert write_authz.agent_halted() is False
        assert len(_warnings()) == 2  # still once per episode

    # An absent file is the normal not-mounted state: neither a failure that
    # warns nor a recovery that re-arms. The latch from episode 2 stays set.
    kill_file.unlink()
    assert write_authz.agent_halted() is False
    assert write_authz._halt_read_error_warned is True


_BINARY_KILL_CONTENT = b"\xff\xfe\x00\x01halt"  # ConfigMap binaryData, not UTF-8


def _set_kill_bytes(monkeypatch, tmp_path, content: bytes):
    kill_file = tmp_path / "kill-switch"
    kill_file.write_bytes(content)
    monkeypatch.setenv("AGENT_KILL_SWITCH_FILE", str(kill_file))
    monkeypatch.setattr(write_authz, "_halt_read_error_warned", False)
    return kill_file


def test_agent_halted_binary_file_fails_open_and_warns(monkeypatch, tmp_path, caplog):
    """Review point 2: a non-UTF-8 kill file (binaryData) raised
    UnicodeDecodeError out of agent_halted() — only OSError was caught. It must
    fail OPEN like any other unreadable file, and say so once."""
    _set_kill_bytes(monkeypatch, tmp_path, _BINARY_KILL_CONTENT)
    with caplog.at_level(logging.WARNING, logger="app.write_authz"):
        assert write_authz.agent_halted() is False  # no exception, fail open
        assert write_authz.agent_halted() is False
    warnings = [r.getMessage() for r in caplog.records if "failing OPEN" in r.getMessage()]
    assert len(warnings) == 1
    assert "UnicodeDecodeError" in warnings[0]


def test_kill_switch_state_binary_file_is_unreadable_not_released(monkeypatch, tmp_path):
    """The startup arming check must neither crash nor report 'released'."""
    _set_kill_bytes(monkeypatch, tmp_path, _BINARY_KILL_CONTENT)
    assert write_authz.kill_switch_state() == "unreadable"


@pytest.mark.parametrize("content,expected", [
    (b"true", True),                 # binaryData carrying a valid value engages
    (b"\xef\xbb\xbftrue\r\n", True),  # UTF-8 BOM + CRLF from a Windows editor
    (b"halt\x00", False),            # embedded NUL is not whitespace: not a match
    (b"", False),
])
def test_agent_halted_byte_shapes(monkeypatch, tmp_path, content, expected):
    _set_kill_bytes(monkeypatch, tmp_path, content)
    assert write_authz.agent_halted() is expected


def test_agent_halted_oversized_file_fails_open(monkeypatch, tmp_path, caplog):
    """A mis-targeted mount handing us a large file is 'unreadable', never
    'engaged' or 'released', and the read is bounded (no slurp)."""
    _set_kill_bytes(monkeypatch, tmp_path, b"true" + b" " * 4096)
    with caplog.at_level(logging.WARNING, logger="app.write_authz"):
        assert write_authz.agent_halted() is False
    assert write_authz.kill_switch_state() == "unreadable"
    assert any("larger than" in r.getMessage() for r in caplog.records)


def test_kill_switch_armed_reflects_mount(monkeypatch, tmp_path):
    kill_file = _set_kill_file(monkeypatch, tmp_path, "false")
    assert write_authz.kill_switch_armed() is True
    kill_file.unlink()
    assert write_authz.kill_switch_armed() is False  # not mounted -> inoperable


def test_kill_switch_state_three_valued(monkeypatch, tmp_path):
    """Arming EVIDENCE must not collapse 'unreadable' into 'released'."""
    kill_file = _set_kill_file(monkeypatch, tmp_path, "true")
    assert write_authz.kill_switch_state() == "engaged"
    kill_file.write_text("false")
    assert write_authz.kill_switch_state() == "released"
    kill_file.unlink()
    assert write_authz.kill_switch_state() == "not-mounted"
    # A directory raises a non-ENOENT OSError on read_text -> 'unreadable'.
    monkeypatch.setenv("AGENT_KILL_SWITCH_FILE", str(tmp_path))
    assert write_authz.kill_switch_state() == "unreadable"


def test_write_tools_enabled_is_independent_of_kill_switch(monkeypatch, tmp_path):
    """The authorization gate must NOT consult the kill switch (review point 1):
    it is evaluated at agent construction, where a halt would be baked into the
    compiled graph and outlive the operator's release. Containment is enforced
    per operation instead (tool bodies + REST routes, tested below)."""
    monkeypatch.setenv("ENABLE_WRITE_TOOLS", "true")
    monkeypatch.setenv("DEPLOY_ENV", "nonprod")
    kill_file = _set_kill_file(monkeypatch, tmp_path, "true")
    assert write_authz.agent_halted() is True
    assert write_authz.write_tools_enabled() is True  # authz unchanged by the halt

    kill_file.write_text("false")
    assert write_authz.write_tools_enabled() is True

    # And the halt never turns writes ON either: gate off stays off.
    monkeypatch.setenv("ENABLE_WRITE_TOOLS", "false")
    kill_file.write_text("true")
    assert write_authz.write_tools_enabled() is False


def test_write_authz_source_does_not_reference_the_halt():
    """Structural guard for the same point: write_tools_enabled() must not call
    agent_halted(), or the construction-time leak comes back silently."""
    import ast
    import inspect
    import textwrap

    tree = ast.parse(textwrap.dedent(inspect.getsource(write_authz.write_tools_enabled)))
    called = {
        n.func.id for n in ast.walk(tree)
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
    }
    assert "agent_halted" not in called


def _build_full_agent(monkeypatch):
    """Construct a REAL LangGraphAgent (constructor path, not object.__new__)
    with the model and graph compilation stubbed, capturing what the graph was
    compiled with — i.e. exactly what a pod recreated while halted bakes in."""
    from app import langgraph_agent as la

    compiled = {}

    def _fake_react(model, tools, prompt):
        compiled["tools"] = tools
        compiled["prompt"] = prompt
        return object()

    monkeypatch.setattr(la, "create_react_agent", _fake_react)
    monkeypatch.setattr(la, "ChatAnthropic", lambda **kw: object())
    monkeypatch.setattr(la.secret_provider, "get_api_key", lambda: "test-key")
    agent = la.LangGraphAgent(
        AsyncMock(), AsyncMock(), AsyncMock(), AsyncMock(), AsyncMock(), github_client=None,
    )
    return agent, compiled


def test_agent_built_while_halted_recovers_on_release(monkeypatch, tmp_path):
    """Runbook step 3 (delete the pod while the switch is engaged): the recreated
    sidecar builds its agent with the switch ON. It must still register the write
    tools and describe itself as write-enabled; the tools refuse while halted and
    WORK again once the operator releases the switch — without a rebuild."""
    monkeypatch.setenv("ENABLE_WRITE_TOOLS", "true")
    monkeypatch.setenv("DEPLOY_ENV", "nonprod")
    kill_file = _set_kill_file(monkeypatch, tmp_path, "true")

    agent, compiled = _build_full_agent(monkeypatch)
    names = [t.name for t in compiled["tools"]]
    assert {"update_flink_config", "restart_flink_job", "apply_remediation"} <= set(names)
    assert "WRITE TOOLS ENABLED" in compiled["prompt"]
    assert "READ-ONLY MODE" not in compiled["prompt"]

    apply_tool = next(t for t in compiled["tools"] if t.name == "apply_remediation")
    call = {"remediation_type": "increase_checkpoint_timeout", "dry_run": False}

    # Still engaged: the baked-in tool refuses at call time, cluster untouched.
    assert "halted" in _run(apply_tool.ainvoke(call))
    agent.auto_remediator.apply_remediation.assert_not_called()

    # Operator releases the switch in place -> the SAME agent instance works
    # again: a live apply is recorded as a proposal awaiting human approval.
    kill_file.write_text("false")
    assert '"proposed": true' in _run(apply_tool.ainvoke(call))
    agent.auto_remediator.apply_remediation.assert_not_called()


def test_agent_built_while_halted_read_only_when_gate_off(monkeypatch, tmp_path):
    """Symmetry: the halt must not make a read-only deployment look writable."""
    monkeypatch.delenv("ENABLE_WRITE_TOOLS", raising=False)
    _set_kill_file(monkeypatch, tmp_path, "true")
    _, compiled = _build_full_agent(monkeypatch)
    assert "apply_remediation" not in [t.name for t in compiled["tools"]]
    assert "READ-ONLY MODE" in compiled["prompt"]


# ── REST routes: halt checked per request, audited as agent_halted ──────────


@pytest.fixture
def captured_audit():
    """JSON lines emitted on the app.audit logger."""
    import json

    records = []

    class _H(logging.Handler):
        def emit(self, record):
            records.append(json.loads(record.getMessage()))

    audit_logger = logging.getLogger("app.audit")
    handler = _H()
    audit_logger.addHandler(handler)
    try:
        yield records
    finally:
        audit_logger.removeHandler(handler)


def _rest_client(monkeypatch, tmp_path, write_tools: bool, kill_content: str):
    """TestClient for app.main with the gate and the kill file set as given.
    Reloads app.main so the module reads the patched environment."""
    pytest.importorskip("fastapi")
    import importlib
    from fastapi.testclient import TestClient

    monkeypatch.setenv("SECRET_PROVIDER", "env")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "dummy")
    if write_tools:
        monkeypatch.setenv("ENABLE_WRITE_TOOLS", "true")
        monkeypatch.setenv("DEPLOY_ENV", "nonprod")
    else:
        monkeypatch.delenv("ENABLE_WRITE_TOOLS", raising=False)
    kill_file = _set_kill_file(monkeypatch, tmp_path, kill_content)
    monkeypatch.setenv("RATE_LIMIT_HEAVY_PER_MINUTE", "100")  # repeated write-route POSTs
    import app.main as main
    importlib.reload(main)
    main.auto_remediator = AsyncMock()
    return main, TestClient(main._app), kill_file


def test_rest_apply_and_rollback_403_while_halted_audit_as_agent_halted(
    monkeypatch, tmp_path, captured_audit,
):
    """With writes legitimately enabled, an engaged switch 403s both write routes
    and the denial is its own audit event (agent_halted), not the authorization
    event remediation_denied/write_tools_disabled (review minor)."""
    main, client, kill_file = _rest_client(monkeypatch, tmp_path, True, "true")

    resp = client.post("/api/remediation/apply",
                       json={"type": "increase_parallelism", "dry_run": False})
    assert resp.status_code == 403
    assert "kill switch" in resp.json()["detail"]
    resp = client.post("/api/remediation/rollback", json={"id": 7})
    assert resp.status_code == 403
    main.auto_remediator.apply_remediation.assert_not_called()
    main.auto_remediator.rollback.assert_not_called()

    halted = [e for e in captured_audit if e["event"] == "agent_halted"]
    assert sorted(e["route"] for e in halted) == ["apply", "rollback"]
    assert next(e for e in halted if e["route"] == "apply")["requested_type"] == "increase_parallelism"
    assert next(e for e in halted if e["route"] == "rollback")["id"] == 7
    assert not [e for e in captured_audit if e["event"] == "remediation_denied"]

    # Release in place: the same process serves the write again (no restart).
    kill_file.write_text("false")
    main.auto_remediator.rollback.return_value = {"success": True}
    resp = client.post("/api/remediation/rollback", json={"id": 7})
    assert resp.status_code == 200
    main.auto_remediator.rollback.assert_awaited_once_with(7)


def test_rest_halt_denial_precedes_authz_denial(monkeypatch, tmp_path, captured_audit):
    """Gate off AND halted: containment is reported, not authorization, so the
    responder sees the switch working even on a read-only deployment."""
    _, client, _ = _rest_client(monkeypatch, tmp_path, False, "true")
    assert client.post("/api/remediation/apply",
                       json={"type": "increase_parallelism"}).status_code == 403
    events = [e["event"] for e in captured_audit]
    assert "agent_halted" in events
    assert "remediation_denied" not in events


def test_rest_authz_denial_unchanged_when_released(monkeypatch, tmp_path, captured_audit):
    """Regression guard for the existing contract: released + gate off is still
    remediation_denied/write_tools_disabled (tests/test_audit_coverage.py)."""
    _, client, _ = _rest_client(monkeypatch, tmp_path, False, "false")
    assert client.post("/api/remediation/apply",
                       json={"type": "increase_parallelism"}).status_code == 403
    denied = [e for e in captured_audit if e["event"] == "remediation_denied"]
    assert len(denied) == 1 and denied[0]["reason"] == "write_tools_disabled"
    assert not [e for e in captured_audit if e["event"] == "agent_halted"]


# ── agent write tools re-check the switch at CALL time ──────────────────────


def _build_tools(monkeypatch, tmp_path):
    """Build the agent toolset with writes enabled and the switch released."""
    from app.langgraph_agent import LangGraphAgent

    monkeypatch.setenv("ENABLE_WRITE_TOOLS", "true")
    monkeypatch.setenv("DEPLOY_ENV", "nonprod")
    kill_file = _set_kill_file(monkeypatch, tmp_path, "false")

    agent = object.__new__(LangGraphAgent)
    agent.flink_client = AsyncMock()
    agent.k8s_client = AsyncMock()
    agent.postgres_reader = AsyncMock()
    agent.auto_remediator = AsyncMock()
    agent.slack_client = AsyncMock()
    agent.github_client = None
    tools = agent._create_tools()
    return tools, kill_file, agent


def test_write_tool_refuses_after_switch_trips(monkeypatch, tmp_path):
    """The baked-into-graph scenario: tools registered while un-halted must
    refuse once the file flips, without touching the cluster."""
    tools, kill_file, agent = _build_tools(monkeypatch, tmp_path)
    names = [t.name for t in tools]
    assert "apply_remediation" in names  # registered: switch was off at build

    kill_file.write_text("true")  # operator trips the switch mid-flight

    async def _invoke_all():
        apply_tool = next(t for t in tools if t.name == "apply_remediation")
        restart_tool = next(t for t in tools if t.name == "restart_flink_job")
        config_tool = next(t for t in tools if t.name == "update_flink_config")
        return (
            await apply_tool.ainvoke(
                {"remediation_type": "increase_checkpoint_timeout", "dry_run": False}
            ),
            await restart_tool.ainvoke({}),
            await config_tool.ainvoke(
                {"config_key": "execution.checkpointing.interval", "config_value": "60s"}
            ),
        )

    apply_res, restart_res, config_res = _run(_invoke_all())
    assert "halted" in apply_res
    assert "halted" in restart_res
    assert "halted" in config_res
    agent.auto_remediator.apply_remediation.assert_not_called()
    agent.k8s_client.patch_flink_config.assert_not_called()
    agent.k8s_client.restart_flink_job.assert_not_called()


def test_send_to_slack_refuses_while_halted(monkeypatch, tmp_path):
    """Slack is external egress: containment must stop outbound posts too."""
    tools, kill_file, agent = _build_tools(monkeypatch, tmp_path)
    kill_file.write_text("true")

    slack_tool = next(t for t in tools if t.name == "send_to_slack")
    result = _run(slack_tool.ainvoke({"message": "analysis text"}))
    assert "halted" in result
    agent.slack_client.send_message.assert_not_called()


# ── poller lifecycle ─────────────────────────────────────────────────────────


def test_poller_stop_is_prompt(monkeypatch, tmp_path):
    """stop() cancels the retained task instead of waiting out the sleep."""
    from app.grafana_poller import GrafanaAlertPoller

    _set_kill_file(monkeypatch, tmp_path, "false")
    monkeypatch.setenv("FLINK_DEPLOYMENT_NAME", "test-deployment")
    # The poller has no built-in Grafana host; start() is a no-op without one.
    monkeypatch.setenv("GRAFANA_URL", "https://grafana.example.com")
    monkeypatch.setenv("GRAFANA_POLL_INTERVAL", "3600")  # stop must NOT wait this out

    async def _main():
        poller = GrafanaAlertPoller(AsyncMock(), AsyncMock())
        with patch("app.grafana_poller.secret_provider.get_grafana_sa_token",
                   return_value="tok"):
            with patch.object(poller, "_poll_once", new=AsyncMock()):
                await poller.start()
                assert poller._task is not None
                await asyncio.wait_for(poller.stop(), timeout=5)
        return poller

    poller = _run(_main())
    assert poller._task is None
    assert poller._running is False


def test_poll_loop_idles_while_halted(monkeypatch, tmp_path, caplog):
    """While the switch is engaged the loop never calls _poll_once and logs the
    engagement line once (validation criterion of the finding)."""
    from app.grafana_poller import GrafanaAlertPoller

    _set_kill_file(monkeypatch, tmp_path, "true")
    monkeypatch.setenv("FLINK_DEPLOYMENT_NAME", "test-deployment")
    monkeypatch.setenv("GRAFANA_POLL_INTERVAL", "0")

    poller = GrafanaAlertPoller(AsyncMock(), AsyncMock())
    poller._running = True
    poll_once = AsyncMock()

    async def _main():
        with patch.object(poller, "_poll_once", new=poll_once):
            task = asyncio.ensure_future(poller._poll_loop())
            await asyncio.sleep(0.05)  # several zero-interval cycles
            poller._running = False
            await asyncio.wait_for(task, timeout=5)

    with caplog.at_level(logging.INFO, logger="app.grafana_poller"):
        _run(_main())

    poll_once.assert_not_called()
    engaged_lines = [
        r for r in caplog.records
        if "Grafana poller idle — operator kill switch is engaged" in r.getMessage()
    ]
    assert len(engaged_lines) == 1  # logged on the transition, not per cycle


def _drive_poll_loop(poller, poll_once, cycles_seconds=0.05):
    """Run _poll_loop for a moment with _poll_once stubbed; return the task."""
    async def _main():
        with patch.object(poller, "_poll_once", new=poll_once):
            task = asyncio.ensure_future(poller._poll_loop())
            await asyncio.sleep(cycles_seconds)
            alive = not task.done()
            poller._running = False
            if alive:
                await asyncio.wait_for(task, timeout=5)
            return alive, task

    return _run(_main())


def test_poll_loop_survives_binary_kill_file(monkeypatch, tmp_path, caplog):
    """Review point 2, poller side: a binaryData kill file killed the poller task
    silently (UnicodeDecodeError escaped the loop). Now the probe fails open,
    the loop keeps polling, and nothing dies."""
    from app.grafana_poller import GrafanaAlertPoller

    _set_kill_bytes(monkeypatch, tmp_path, _BINARY_KILL_CONTENT)
    monkeypatch.setenv("FLINK_DEPLOYMENT_NAME", "test-deployment")
    monkeypatch.setenv("GRAFANA_POLL_INTERVAL", "0")

    poller = GrafanaAlertPoller(AsyncMock(), AsyncMock())
    poller._running = True
    poll_once = AsyncMock()
    with caplog.at_level(logging.WARNING):
        alive, task = _drive_poll_loop(poller, poll_once)

    assert alive, "poller task died"
    assert task.exception() is None
    assert poll_once.await_count > 0  # fail open: polling continued
    assert any("failing OPEN" in r.getMessage() for r in caplog.records)


def test_poll_loop_survives_kill_switch_probe_raising(monkeypatch, tmp_path, caplog):
    """Defence in depth at the poll boundary: even if agent_halted() itself
    raised (it is documented never to), the loop logs and continues instead of
    dying — the check now runs inside the per-cycle try."""
    from app import grafana_poller as gp

    _set_kill_file(monkeypatch, tmp_path, "false")
    monkeypatch.setenv("FLINK_DEPLOYMENT_NAME", "test-deployment")
    monkeypatch.setenv("GRAFANA_POLL_INTERVAL", "0")

    calls = {"n": 0}

    def _flaky_probe():
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("probe exploded")
        return False

    monkeypatch.setattr(gp, "agent_halted", _flaky_probe)
    poller = gp.GrafanaAlertPoller(AsyncMock(), AsyncMock())
    poller._running = True
    poll_once = AsyncMock()
    with caplog.at_level(logging.ERROR, logger="app.grafana_poller"):
        alive, task = _drive_poll_loop(poller, poll_once)

    assert alive and task.exception() is None
    assert calls["n"] > 1 and poll_once.await_count > 0  # recovered on the next cycle
    assert any("RuntimeError: probe exploded" in r.getMessage() for r in caplog.records)


class _FakeAlertsResponse:
    """aiohttp response stand-in for the alertmanager GET inside _poll_once."""
    status = 200

    def __init__(self, alerts):
        self._alerts = alerts

    async def json(self):
        return self._alerts

    async def text(self):
        return ""

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


class _FakeSession:
    def __init__(self, alerts):
        self._alerts = alerts

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    def get(self, *args, **kwargs):
        return _FakeAlertsResponse(self._alerts)


def test_fan_out_stops_at_first_analysis_when_switch_trips_mid_cycle(
    monkeypatch, tmp_path, captured_audit, caplog,
):
    """Round-2 blocker, reproduced then fixed: one cycle with 6 new alerts fans
    out 6 analyses. The halt was checked per cycle and before each Slack post,
    but not before each alert's LLM analysis, so a switch tripped during the
    first analyze() still let the other 5 analyses (5 LLM invocations) run.
    Now _bounded_analyze probes the switch right before each analysis begins:
    exactly 1 analysis runs, the other 5 are skipped without an LLM call and
    audited as ai_query_skipped. After release, the skipped alerts are picked
    up on the very next cycle (their dedup entries were dropped), while the
    one that WAS analysed stays deduplicated."""
    from app import grafana_poller as gp

    kill_file = _set_kill_file(monkeypatch, tmp_path, "false")
    monkeypatch.setenv("FLINK_DEPLOYMENT_NAME", "test-deployment")
    monkeypatch.setenv("GRAFANA_MAX_ANALYSES_PER_CYCLE", "10")  # all 6 in one cycle

    alerts = [
        {
            "fingerprint": f"fp{i}",
            "startsAt": "2026-10-01T00:00:00Z",
            "labels": {"alertname": f"Alert{i}", "job": "test-deployment"},
            "annotations": {"summary": "s", "description": "d"},
        }
        for i in range(6)
    ]

    analysed = []

    async def _analyze(question, history):
        analysed.append(question)
        if len(analysed) == 1:
            # The operator trips the switch while the FIRST analysis is in
            # flight — before this coroutine yields, so every sibling that
            # starts afterwards sees the engaged switch.
            kill_file.write_text("true")
        return {"answer": "## TL;DR\nfine", "tool_calls_made": 0, "iterations": 1}

    agent = AsyncMock()
    agent.analyze = _analyze
    poller = gp.GrafanaAlertPoller(agent, AsyncMock())

    with patch("app.grafana_poller.secret_provider.get_grafana_sa_token", return_value="tok"), \
         patch.object(gp.aiohttp, "ClientSession", lambda *a, **kw: _FakeSession(alerts)), \
         caplog.at_level(logging.INFO, logger="app.grafana_poller"):
        _run(poller._poll_once())

        assert len(analysed) == 1, f"{len(analysed)} analyses ran; the switch should have stopped the fan-out at 1"
        skipped = [e for e in captured_audit if e["event"] == "ai_query_skipped"]
        assert len(skipped) == 5
        assert {e["reason"] for e in skipped} == {"agent_halted"}
        assert {e["trigger"] for e in skipped} == {"grafana_poller"}
        assert sorted(e["alert_name"] for e in skipped) == [f"Alert{i}" for i in range(1, 6)]
        # The one analysis that ran is a normal audited run whose Slack post
        # was suppressed by the in-flight check.
        assert len([e for e in captured_audit if e["event"] == "ai_query"]) == 1
        assert len([e for e in captured_audit if e["event"] == "ai_query_result"]) == 1
        assert [e for e in captured_audit if e["event"] == "slack_send"][0]["error"] == "agent_halted"
        skip_lines = [r for r in caplog.records
                      if "Alert analysis skipped — operator kill switch is engaged" in r.getMessage()]
        assert len(skip_lines) == 5
        # Skipped alerts are not "seen": only the analysed one is deduplicated.
        assert set(poller._seen) == {("fp0", "2026-10-01T00:00:00Z")}

        # Operator releases the switch: the next cycle analyses exactly the 5
        # skipped alerts (fp0 is still inside its re-eval window).
        kill_file.write_text("false")
        _run(poller._poll_once())
        assert len(analysed) == 6
        assert len(poller._seen) == 6
        assert len([e for e in captured_audit if e["event"] == "ai_query_skipped"]) == 5  # no new skips


def test_cancelled_analysis_emits_ai_query_result_cancelled(monkeypatch, tmp_path, captured_audit):
    """Review minor: stop() cancelling an in-flight analysis left an ai_query
    entry event with no completion event (CancelledError bypasses `except
    Exception`). The run must close with status=cancelled and still unwind."""
    from app.grafana_poller import GrafanaAlertPoller

    _set_kill_file(monkeypatch, tmp_path, "false")
    monkeypatch.setenv("FLINK_DEPLOYMENT_NAME", "test-deployment")

    started = asyncio.Event()

    async def _hang(question, history):
        started.set()
        await asyncio.Event().wait()  # never completes on its own

    agent = AsyncMock()
    agent.analyze = _hang
    poller = GrafanaAlertPoller(agent, AsyncMock())
    alert = {"labels": {"alertname": "CheckpointFailing"}, "annotations": {}}

    async def _main():
        task = asyncio.ensure_future(poller._analyze_alert(alert))
        await asyncio.wait_for(started.wait(), timeout=5)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task  # cancellation still propagates after auditing

    _run(_main())

    results = [e for e in captured_audit if e["event"] == "ai_query_result"]
    assert len(results) == 1
    assert results[0]["status"] == "cancelled"
    assert results[0]["alert_name"] == "CheckpointFailing"
    assert results[0]["trigger"] == "grafana_poller"
    # One entry, one completion: the pair a responder joins on.
    assert len([e for e in captured_audit if e["event"] == "ai_query"]) == 1


def test_shutdown_event_stops_poller(monkeypatch):
    """shutdown_event() must reach the module-scope poller and await stop()."""
    from app import main as app_main

    poller = AsyncMock()
    monkeypatch.setattr(app_main, "grafana_poller", poller)
    monkeypatch.setattr(app_main, "metrics_collector", AsyncMock())
    monkeypatch.setattr(app_main, "postgres_reader", AsyncMock())
    _run(app_main.shutdown_event())
    poller.stop.assert_awaited_once()


def test_shutdown_event_tolerates_absent_poller(monkeypatch):
    """No poller (token not configured) must not break shutdown."""
    from app import main as app_main

    monkeypatch.setattr(app_main, "grafana_poller", None)
    monkeypatch.setattr(app_main, "metrics_collector", AsyncMock())
    monkeypatch.setattr(app_main, "postgres_reader", AsyncMock())
    _run(app_main.shutdown_event())


# ── manifest wiring ──────────────────────────────────────────────────────────


_REPO_ROOT = Path(__file__).resolve().parents[1]


def _runbook_volume_contract() -> dict:
    """The YAML block under the runbook's 'Volume contract' heading.

    The example manifest is illustrative; the rendered contract lives in the
    runbook and this test holds it to the code."""
    runbook = (_REPO_ROOT / "docs" / "AI_INCIDENT_RESPONSE.md").read_text()
    _, _, after_heading = runbook.partition("#### Volume contract")
    assert after_heading, "runbook lacks the 'Volume contract' section"
    _, _, after_fence = after_heading.partition("```yaml\n")
    block, _, _ = after_fence.partition("```")
    assert block.strip(), "runbook 'Volume contract' has no yaml block"
    return yaml.safe_load(block)


def test_runbook_volume_contract_mounts_kill_switch_without_subpath():
    """The rendered contract must mount the kill-switch ConfigMap as a
    whole-volume, read-only, optional mount at the directory the code reads:
    a subPath mount never receives ConfigMap updates (silently disabling the
    control) and a required volume would block pod startup when the ConfigMap
    is absent."""
    spec = _runbook_volume_contract()

    volumes = {v["name"]: v for v in spec["volumes"]}
    assert "ai-debugger-kill-switch" in volumes
    cm = volumes["ai-debugger-kill-switch"]["configMap"]
    assert cm["name"] == "flink-ai-debugger-kill-switch"
    assert cm.get("optional") is True  # absence must not block pod startup

    sidecar = next(c for c in spec["containers"] if c["name"] == "ai-debugger-sidecar")
    mounts = [m for m in sidecar["volumeMounts"] if m["name"] == "ai-debugger-kill-switch"]
    assert len(mounts) == 1
    mount = mounts[0]
    assert mount.get("readOnly") is True
    assert "subPath" not in mount  # subPath mounts never see ConfigMap updates

    # Tie the contract to the code, not to a hand-copied string: the mount
    # directory plus the ConfigMap key must be exactly the file agent_halted()
    # reads, and the ConfigMap the volume names must be the one shipped.
    default_file = Path(write_authz._DEFAULT_KILL_SWITCH_FILE)
    assert mount["mountPath"] == str(default_file.parent)
    shipped_cm = yaml.safe_load(
        (_REPO_ROOT / "k8s" / "flink-ai-debugger-kill-switch-configmap.yaml").read_text()
    )
    assert shipped_cm["metadata"]["name"] == cm["name"]
    assert default_file.name in shipped_cm["data"]


def test_kill_switch_configmap_defaults_to_released():
    cm = yaml.safe_load(
        (_REPO_ROOT / "k8s" / "flink-ai-debugger-kill-switch-configmap.yaml").read_text()
    )
    assert cm["metadata"]["name"] == "flink-ai-debugger-kill-switch"
    assert cm["data"]["kill-switch"] == "false"
    assert "binaryData" not in cm  # a binaryData value is 'unreadable' to the app
    assert cm["metadata"]["labels"]["app"] == "flink-ai-debugger-kill-switch"


# ── docs drift (docs are code for the validator) ─────────────────────────────


def test_readme_documents_kill_switch_env_with_code_default():
    """AGENT_KILL_SWITCH_FILE must appear in the README env table with the
    default read from the code, not a hand-copied string (review minor)."""
    readme = (_REPO_ROOT / "README.md").read_text()
    row = next(
        (line for line in readme.splitlines()
         if line.startswith("| `AGENT_KILL_SWITCH_FILE`")), None,
    )
    assert row is not None, "AGENT_KILL_SWITCH_FILE row missing from README env table"
    assert f"`{write_authz._DEFAULT_KILL_SWITCH_FILE}`" in row
    for value in sorted(write_authz._HALT_VALUES):
        assert f"`{value}`" in row


def test_runbook_states_both_switch_scopes_and_blast_radius():
    """Review point 3: the runbook must document the namespace-wide switch AND
    the per-deployment switch, each with its blast radius, and name the env
    var and default path the code actually reads."""
    runbook = (_REPO_ROOT / "docs" / "AI_INCIDENT_RESPONSE.md").read_text()
    assert "AGENT_KILL_SWITCH_FILE" in runbook
    assert write_authz._DEFAULT_KILL_SWITCH_FILE in runbook
    assert "Blast radius" in runbook
    # Namespace-wide: the default ConfigMap name, stated to halt every sidecar.
    assert "flink-ai-debugger-kill-switch" in runbook
    assert "Namespace-wide" in runbook and "**every** AI debugger sidecar" in runbook
    # Per-deployment: the name pattern a per-job renderer produces, stated to halt one.
    assert "<deployment>-kill-switch" in runbook
    assert "Per-deployment" in runbook and "**only** the sidecar of that FlinkDeployment" in runbook
    # The REST 403 audit name documented matches the code.
    assert "`agent_halted`" in runbook


# ── the switch stops GitHub source reads too ────────────────────────────────

def test_github_reads_refuse_while_halted(monkeypatch, tmp_path):
    """Source reads are egress to the model provider: containment stops them."""
    from unittest.mock import MagicMock
    from app.langgraph_agent import LangGraphAgent

    monkeypatch.setenv("ENABLE_WRITE_TOOLS", "true")
    monkeypatch.setenv("DEPLOY_ENV", "nonprod")
    kill_file = _set_kill_file(monkeypatch, tmp_path, "false")
    github = MagicMock()
    github.enabled = True
    github.default_repo = "owner/repo"
    github.read_file = AsyncMock(return_value={"success": True, "content": "x", "path": "src/A.java"})
    github.list_files = AsyncMock(return_value={"success": True, "files": []})
    agent = object.__new__(LangGraphAgent)
    agent.flink_client = AsyncMock()
    agent.k8s_client = AsyncMock()
    agent.postgres_reader = AsyncMock()
    agent.auto_remediator = AsyncMock()
    agent.slack_client = AsyncMock()
    agent.github_client = github
    tools = {t.name: t for t in agent._create_tools()}
    assert "list_github_files" in tools and "read_github_file" in tools

    kill_file.write_text("true")
    assert "halted" in _run(tools["list_github_files"].ainvoke({}))
    assert "halted" in _run(tools["read_github_file"].ainvoke({"file_path": "src/A.java"}))
    github.read_file.assert_not_called()
    github.list_files.assert_not_called()


def test_example_manifest_mounts_the_kill_switch_per_the_runbook_contract():
    """Adopters copy the example: it must carry the same volume and mount as
    the runbook contract, or the documented stop does nothing on their pods."""
    contract = _runbook_volume_contract()
    manifest = yaml.safe_load((_REPO_ROOT / "k8s" / "example-flink-deployment.yaml").read_text())
    pod = manifest["spec"]["jobManager"]["podTemplate"]["spec"]

    want_vol = next(v for v in contract["volumes"] if v["name"] == "ai-debugger-kill-switch")
    have_vol = next(v for v in pod["volumes"] if v["name"] == "ai-debugger-kill-switch")
    assert have_vol == want_vol

    want_sidecar = next(c for c in contract["containers"] if c["name"] == "ai-debugger-sidecar")
    have_sidecar = next(c for c in pod["containers"] if c["name"] == "ai-debugger-sidecar")
    want_mount = next(m for m in want_sidecar["volumeMounts"] if m["name"] == "ai-debugger-kill-switch")
    have_mount = next(m for m in have_sidecar["volumeMounts"] if m["name"] == "ai-debugger-kill-switch")
    assert have_mount == want_mount
    assert "subPath" not in have_mount

    # Writable /tmp beside the read-only root filesystem.
    tmp_vol = next(v for v in pod["volumes"] if v["name"] == "tmp")
    assert "emptyDir" in tmp_vol
    assert {"name": "tmp", "mountPath": "/tmp"} in have_sidecar["volumeMounts"]
