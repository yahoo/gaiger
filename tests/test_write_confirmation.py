# Copyright Yahoo, Licensed under the terms of the Apache 2.0 license. See LICENSE for terms.

"""Chat-triggered cluster writes wait for a human.

update_flink_config, restart_flink_job and apply_remediation(dry_run=False)
record a proposal and return; nothing reaches Kubernetes until a person POSTs
the proposal id to /api/remediation/approve (the UI's Approve button). The
model never sees the id and has no tool for the route. Proposals are single
use, expire, and every decision is audited.
"""
import asyncio
import importlib
import json
from unittest.mock import AsyncMock, MagicMock

import pytest

pytest.importorskip("langchain_core")
from fastapi.testclient import TestClient  # noqa: E402

_JSON = {"Content-Type": "application/json"}


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


@pytest.fixture
def env(monkeypatch, tmp_path):
    monkeypatch.setenv("SECRET_PROVIDER", "env")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "dummy")
    monkeypatch.setenv("ENABLE_WRITE_TOOLS", "true")
    monkeypatch.setenv("DEPLOY_ENV", "nonprod")
    monkeypatch.setenv("RATE_LIMIT_HEAVY_PER_MINUTE", "100")
    monkeypatch.setenv("AGENT_KILL_SWITCH_FILE", str(tmp_path / "kill-switch"))
    import app.main as main
    importlib.reload(main)
    from app import langgraph_agent as lga
    from app import write_proposals
    write_proposals.clear()

    k8s = MagicMock()
    k8s.patch_flink_config.return_value = {"success": True, "applied": {"parallelism.default": "8"}}
    k8s.restart_flink_job.return_value = {"success": True}
    monkeypatch.setattr(main, "k8s_client", k8s)

    events = []
    real_audit = main.audit

    def _capture(event, *a, **kw):
        events.append((event, kw))
        return real_audit(event, *a, **kw)

    monkeypatch.setattr(main, "audit", _capture)
    monkeypatch.setattr(lga, "audit", _capture)

    agent = object.__new__(lga.LangGraphAgent)
    agent.flink_client = AsyncMock()
    agent.k8s_client = k8s
    agent.postgres_reader = AsyncMock()
    agent.auto_remediator = main.auto_remediator
    agent.slack_client = AsyncMock()
    agent.github_client = None
    tools = {t.name: t for t in agent._create_tools()}
    return main, TestClient(main._app), tools, k8s, events, write_proposals


def _propose(tools, write_proposals, name, args):
    run = write_proposals.begin_run_tracking()
    out = json.loads(_run(tools[name].ainvoke(args)))
    return out, run


def test_tools_only_propose_and_the_model_never_sees_the_id(env):
    main, client, tools, k8s, events, wp = env
    out, run = _propose(tools, wp, "update_flink_config",
                        {"config_key": "parallelism.default", "config_value": "8"})
    assert out["proposed"] is True and "proposal_id" not in out
    out2, run2 = _propose(tools, wp, "restart_flink_job", {})
    assert out2["proposed"] is True
    k8s.patch_flink_config.assert_not_called()
    k8s.restart_flink_job.assert_not_called()
    assert len(run) == 1 and len(run2) == 1
    assert [e for e, _ in events].count("write_proposed") == 2


def test_approve_runs_exactly_once_and_replay_is_404(env):
    main, client, tools, k8s, events, wp = env
    _, run = _propose(tools, wp, "update_flink_config",
                      {"config_key": "parallelism.default", "config_value": "8"})
    pid = run[0]["proposal_id"]
    k8s.patch_flink_config.assert_not_called()

    first = client.post("/api/remediation/approve", json={"proposal_id": pid})
    assert first.status_code == 200 and first.json()["success"] is True
    k8s.patch_flink_config.assert_called_once_with({"parallelism.default": "8"})

    again = client.post("/api/remediation/approve", json={"proposal_id": pid})
    assert again.status_code == 404
    assert k8s.patch_flink_config.call_count == 1
    approved = [kw for e, kw in events if e == "write_approved"]
    assert len(approved) == 1 and approved[0]["success"] is True


def test_restart_runs_only_on_approve(env):
    main, client, tools, k8s, events, wp = env
    _, run = _propose(tools, wp, "restart_flink_job", {})
    k8s.restart_flink_job.assert_not_called()
    assert client.post("/api/remediation/approve",
                       json={"proposal_id": run[0]["proposal_id"]}).status_code == 200
    k8s.restart_flink_job.assert_called_once()


def test_live_remediation_is_proposed_and_preview_still_runs(env, monkeypatch):
    main, client, tools, k8s, events, wp = env
    applied = []

    async def _apply(action, applied_by, *, dry_run):
        applied.append((action.type.value, applied_by, dry_run))
        return MagicMock(success=True, to_dict=lambda: {"success": True}, id=1,
                         remediation_type=action.type.value, applied_by=applied_by,
                         dry_run=dry_run, backup_created=None, changes_made={})

    monkeypatch.setattr(main.auto_remediator, "apply_remediation", _apply)
    out, run = _propose(tools, wp, "apply_remediation",
                        {"remediation_type": "increase_checkpoint_timeout", "dry_run": False})
    assert out["proposed"] is True and applied == []
    resp = client.post("/api/remediation/approve", json={"proposal_id": run[0]["proposal_id"]})
    assert resp.status_code == 200
    assert applied == [("increase_checkpoint_timeout", "approved_chat", False)]

    # A preview is not a write: it runs at once and records no proposal.
    run = wp.begin_run_tracking()
    _run(tools["apply_remediation"].ainvoke(
        {"remediation_type": "increase_checkpoint_timeout", "dry_run": True}))
    assert run == []
    assert applied[-1] == ("increase_checkpoint_timeout", "ai_agent_chat", True)


def test_reject_drops_without_acting(env):
    main, client, tools, k8s, events, wp = env
    _, run = _propose(tools, wp, "restart_flink_job", {})
    pid = run[0]["proposal_id"]
    assert client.post("/api/remediation/reject", json={"proposal_id": pid}).status_code == 200
    assert client.post("/api/remediation/approve", json={"proposal_id": pid}).status_code == 404
    k8s.restart_flink_job.assert_not_called()
    assert any(e == "write_rejected" for e, _ in events)


def test_expired_proposal_is_refused(env, monkeypatch):
    main, client, tools, k8s, events, wp = env
    _, run = _propose(tools, wp, "restart_flink_job", {})
    clock = [wp.time.monotonic() + 10_000]
    monkeypatch.setattr(wp.time, "monotonic", lambda: clock[0])
    assert client.post("/api/remediation/approve",
                       json={"proposal_id": run[0]["proposal_id"]}).status_code == 404
    k8s.restart_flink_job.assert_not_called()


def test_unknown_id_and_gates(env, monkeypatch, tmp_path):
    main, client, tools, k8s, events, wp = env
    assert client.post("/api/remediation/approve", json={"proposal_id": "nope"}).status_code == 404
    _, run = _propose(tools, wp, "restart_flink_job", {})
    pid = run[0]["proposal_id"]
    # Cross-site browser POST refused before the route.
    assert client.post("/api/remediation/approve", json={"proposal_id": pid},
                       headers={"Sec-Fetch-Site": "cross-site"}).status_code == 403
    # Kill switch engaged: refused, proposal kept.
    (tmp_path / "kill-switch").write_text("true")
    assert client.post("/api/remediation/approve", json={"proposal_id": pid}).status_code == 403
    (tmp_path / "kill-switch").write_text("false")
    # Write gate off: refused.
    monkeypatch.setenv("ENABLE_WRITE_TOOLS", "false")
    assert client.post("/api/remediation/approve", json={"proposal_id": pid}).status_code == 403
    k8s.restart_flink_job.assert_not_called()


def test_failed_patch_is_audited_as_failure(env):
    main, client, tools, k8s, events, wp = env
    k8s.patch_flink_config.return_value = {"error": "Configuration value not permitted."}
    _, run = _propose(tools, wp, "update_flink_config",
                      {"config_key": "parallelism.default", "config_value": "8"})
    client.post("/api/remediation/approve", json={"proposal_id": run[0]["proposal_id"]})
    updates = [kw for e, kw in events if e == "config_update"]
    assert len(updates) == 1 and updates[0]["success"] is False
    assert updates[0]["error"] == "Configuration value not permitted."
    approved = [kw for e, kw in events if e == "write_approved"]
    assert approved[0]["success"] is False


def test_bad_value_never_becomes_a_proposal(env):
    main, client, tools, k8s, events, wp = env
    out, run = _propose(tools, wp, "update_flink_config",
                        {"config_key": "parallelism.default", "config_value": "1\nenv.java.opts.all: -Dx"})
    assert out["success"] is False and run == []


def test_ui_renders_approve_and_reject_without_innerhtml():
    from pathlib import Path
    html = (Path(__file__).resolve().parent.parent / "app" / "ui" / "index.html").read_text()
    assert "function buildPendingActionsElement" in html
    assert "'api/remediation/' + verb" in html
    body = html.split("function buildPendingActionsElement", 1)[1].split("\nfunction ", 1)[0]
    assert "innerHTML" not in body
    assert "'Content-Type': 'application/json'" in body


def test_both_agent_entry_points_return_the_runs_proposals():
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "app" / "langgraph_agent.py").read_text()
    assert src.count('parsed["pending_actions"] = write_proposals.run_proposals()') == 2
    assert src.count("write_proposals.begin_run_tracking()") == 2
