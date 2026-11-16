# Copyright Yahoo, Licensed under the terms of the Apache 2.0 license. See LICENSE for terms.

"""create_github_pr waits for a human, in chat and alert runs alike.

The tool validates its arguments and records a proposal; no branch is pushed
and no pull request is opened until a person POSTs the proposal id to
/api/remediation/approve. Proposals are single use, expire, are audited, and
the daily PR cap is applied when the PR is actually opened. Alert-triggered
runs register the tool only with ENABLE_ALERT_FLOW_PRS=true, and even then it
only proposes: the alert's Slack post says a change awaits approval, and the
UI lists it through GET /api/remediation/pending.
"""
import asyncio
import importlib
import json
from unittest.mock import AsyncMock

import pytest

pytest.importorskip("langchain_core")
from fastapi.testclient import TestClient  # noqa: E402


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


class _FakeGitHub:
    enabled = True
    default_repo = "example-org/flink-job"

    def __init__(self):
        self.calls = []

    async def open_pr_with_file_change(self, **kwargs):
        self.calls.append(kwargs)
        return {"success": True, "pr_url": "https://github.com/example-org/flink-job/pull/7",
                "pr_number": 7, "branch": kwargs["branch_name"], "repo": self.default_repo}


_PR_ARGS = {
    "branch_name": "ai-debugger/skew-fix",
    "file_path": "src/main/java/Job.java",
    "new_content": "public class Job { /* fixed */ }",
    "pr_title": "Fix data skew",
    "pr_body": "root cause + fix",
}


def _agent(lga, github, alert_flow=False):
    agent = object.__new__(lga.LangGraphAgent)
    agent.flink_client = AsyncMock()
    agent.k8s_client = None
    agent.postgres_reader = AsyncMock()
    agent.auto_remediator = None
    agent.slack_client = AsyncMock()
    agent.github_client = github
    agent.alert_flow = alert_flow
    return agent


@pytest.fixture
def env(monkeypatch, tmp_path):
    monkeypatch.setenv("SECRET_PROVIDER", "env")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "dummy")
    monkeypatch.setenv("ENABLE_WRITE_TOOLS", "true")
    monkeypatch.setenv("DEPLOY_ENV", "nonprod")
    monkeypatch.setenv("RATE_LIMIT_HEAVY_PER_MINUTE", "100")
    monkeypatch.setenv("AGENT_KILL_SWITCH_FILE", str(tmp_path / "kill-switch"))
    monkeypatch.delenv("GITHUB_PR_MAX_PER_DAY", raising=False)       # shipped default
    monkeypatch.delenv("ENABLE_ALERT_FLOW_PRS", raising=False)
    import app.main as main
    importlib.reload(main)
    from app import langgraph_agent as lga
    from app import write_proposals
    write_proposals.clear()
    monkeypatch.setattr(lga, "_pr_attempts", lga.deque())

    github = _FakeGitHub()
    monkeypatch.setattr(main, "github_client", github)
    events = []
    real_audit = main.audit

    def _capture(event, *a, **kw):
        events.append((event, kw))
        return real_audit(event, *a, **kw)

    monkeypatch.setattr(main, "audit", _capture)
    monkeypatch.setattr(lga, "audit", _capture)
    return main, lga, write_proposals, TestClient(main._app), github, events


def _tools(lga, github, alert_flow=False):
    return {t.name: t for t in _agent(lga, github, alert_flow)._create_tools()}


def _propose(tool, wp, args=None):
    run = wp.begin_run_tracking()
    out = json.loads(_run(tool.ainvoke(dict(args or _PR_ARGS))))
    return out, run


def test_chat_pr_is_only_proposed_and_opens_once_on_approve(env):
    main, lga, wp, client, github, events = env
    out, run = _propose(_tools(lga, github)["create_github_pr"], wp)
    assert out["success"] is True and out["proposed"] is True
    assert "proposal_id" not in out and "pr_url" not in out
    assert github.calls == []
    assert [kw["action"] for e, kw in events if e == "write_proposed"] == ["create_github_pr"]
    assert len(run) == 1 and run[0]["action"] == "create_github_pr"
    # The approver sees what would be committed.
    assert "public class Job { /* fixed */ }" in run[0]["detail"]
    assert "src/main/java/Job.java" in run[0]["summary"]

    pid = run[0]["proposal_id"]
    first = client.post("/api/remediation/approve", json={"proposal_id": pid})
    assert first.status_code == 200 and first.json()["pr_number"] == 7
    assert len(github.calls) == 1
    assert github.calls[0]["repo"] == "example-org/flink-job"
    assert github.calls[0]["new_content"] == _PR_ARGS["new_content"]

    replay = client.post("/api/remediation/approve", json={"proposal_id": pid})
    assert replay.status_code == 404 and len(github.calls) == 1     # single use
    approved = [kw for e, kw in events if e == "write_approved"]
    assert approved == [approved[0]] and approved[0]["action"] == "create_github_pr"
    assert approved[0]["success"] is True
    pr_events = [kw for e, kw in events if e == "github_pr"]
    assert len(pr_events) == 1 and pr_events[0]["applied_by"] == "approved"
    # Bounded metadata only in the audit sink.
    assert "fixed" not in json.dumps(pr_events + approved, default=str)


def test_rejected_or_expired_pr_is_never_opened(env, monkeypatch):
    main, lga, wp, client, github, events = env
    tool = _tools(lga, github)["create_github_pr"]
    _, run = _propose(tool, wp)
    pid = run[0]["proposal_id"]
    assert client.post("/api/remediation/reject", json={"proposal_id": pid}).status_code == 200
    assert client.post("/api/remediation/approve", json={"proposal_id": pid}).status_code == 404

    _, run = _propose(tool, wp, {**_PR_ARGS, "branch_name": "ai-debugger/second"})
    clock = [wp.time.monotonic() + 10_000]
    monkeypatch.setattr(wp.time, "monotonic", lambda: clock[0])
    assert client.post("/api/remediation/approve",
                       json={"proposal_id": run[0]["proposal_id"]}).status_code == 404
    assert github.calls == []


def test_approval_respects_the_kill_switch_and_write_gate(env, monkeypatch, tmp_path):
    main, lga, wp, client, github, events = env
    _, run = _propose(_tools(lga, github)["create_github_pr"], wp)
    pid = run[0]["proposal_id"]
    (tmp_path / "kill-switch").write_text("true")
    assert client.post("/api/remediation/approve", json={"proposal_id": pid}).status_code == 403
    (tmp_path / "kill-switch").write_text("false")
    monkeypatch.setenv("ENABLE_WRITE_TOOLS", "false")
    assert client.post("/api/remediation/approve", json={"proposal_id": pid}).status_code == 403
    assert github.calls == []


def test_daily_cap_counts_approved_prs_not_proposals(env, monkeypatch):
    main, lga, wp, client, github, events = env
    monkeypatch.setenv("GITHUB_PR_MAX_PER_DAY", "1")
    tool = _tools(lga, github)["create_github_pr"]
    _, run1 = _propose(tool, wp)
    _, run2 = _propose(tool, wp, {**_PR_ARGS, "branch_name": "ai-debugger/second"})
    assert client.post("/api/remediation/approve",
                       json={"proposal_id": run1[0]["proposal_id"]}).json()["success"] is True
    second = client.post("/api/remediation/approve", json={"proposal_id": run2[0]["proposal_id"]})
    assert second.json()["success"] is False and len(github.calls) == 1
    assert [kw["reason"] for e, kw in events if e == "github_pr_rejected"] == ["daily_cap"]


def test_alert_flow_does_not_register_pr_tools_by_default(env):
    main, lga, wp, client, github, events = env
    tools = _tools(lga, github, alert_flow=True)
    assert not {"create_github_pr", "read_github_file", "list_github_files"} & set(tools)


def test_alert_flow_with_prs_enabled_still_only_proposes(env, monkeypatch):
    main, lga, wp, client, github, events = env
    monkeypatch.setenv("ENABLE_ALERT_FLOW_PRS", "true")
    tools = _tools(lga, github, alert_flow=True)
    assert "create_github_pr" in tools
    out, run = _propose(tools["create_github_pr"], wp)
    assert out["proposed"] is True and github.calls == []

    # No chat exists for an alert run: the UI lists pending proposals.
    listed = client.get("/api/remediation/pending")
    assert listed.status_code == 200
    pending = listed.json()["pending"]
    assert [p["action"] for p in pending] == ["create_github_pr"]
    assert pending[0]["proposal_id"] == run[0]["proposal_id"]
    assert client.post("/api/remediation/approve",
                       json={"proposal_id": pending[0]["proposal_id"]}).status_code == 200
    assert len(github.calls) == 1
    assert client.get("/api/remediation/pending").json()["pending"] == []


def test_pending_list_is_gated_like_approve(env, monkeypatch, tmp_path):
    main, lga, wp, client, github, events = env
    (tmp_path / "kill-switch").write_text("true")
    assert client.get("/api/remediation/pending").status_code == 403
    (tmp_path / "kill-switch").write_text("false")
    monkeypatch.setenv("ENABLE_WRITE_TOOLS", "false")
    assert client.get("/api/remediation/pending").status_code == 403


def test_alert_slack_post_says_changes_await_approval_without_the_id(env):
    pytest.importorskip("aiohttp")
    from app import grafana_poller as gp
    main, lga, wp, client, github, events = env

    class _Slack:
        enabled = True

        def __init__(self):
            self.sent = []

        async def send_message(self, **kw):
            self.sent.append(kw)
            return {"success": True, "ts": "1.1", "channel": "c"}

    class _Agent:
        async def analyze(self, question, history):
            return {"answer": "## Action\nProposed a fix.", "tool_calls_made": 1, "iterations": 1,
                    "pending_actions": [{"proposal_id": "SECRET-CAPABILITY-ID",
                                         "action": "create_github_pr", "summary": "s"}]}

    poller = object.__new__(gp.GrafanaAlertPoller)
    poller._agent = _Agent()
    poller._slack = _Slack()
    _run(poller._analyze_alert({"labels": {"alertname": "HighBackpressure"}, "annotations": {},
                                "startsAt": "2026-08-01T00:00:00Z"}))
    sent = json.dumps(poller._slack.sent, default=str)
    assert "await approval in the debugger UI" in sent
    assert "SECRET-CAPABILITY-ID" not in sent


def test_pr_too_long_to_review_in_full_is_refused_not_cut(env):
    main, lga, wp, client, github, events = env
    big = "public class Job {}\n// " + "x" * wp.DETAIL_MAX_CHARS + "\n// planted tail\n"
    out, run = _propose(_tools(lga, github)["create_github_pr"], wp,
                        {**_PR_ARGS, "new_content": big})
    assert out["success"] is False and "review in full" in out["error"]
    assert run == [] and wp.pending() == []
    assert any(e == "github_pr_rejected" and kw.get("reason") == "too_large_to_review"
               for e, kw in events)
    assert github.calls == []


def test_pr_the_chat_filter_would_hide_is_refused(env):
    main, lga, wp, client, github, events = env
    quoted = [ln.strip() for ln in lga.SYSTEM_PROMPT.splitlines()
              if any(p.search(ln) for p in lga.LEAKAGE_PATTERNS)][:5]
    content = "\n".join(f"// {ln}" for ln in quoted) + "\npublic class Job {}\n"
    assert lga.redact_leakage(content).withheld
    out, run = _propose(_tools(lga, github)["create_github_pr"], wp,
                        {**_PR_ARGS, "new_content": content})
    assert out["success"] is False and "instructions" in out["error"]
    assert run == [] and wp.pending() == []
    assert any(e == "github_pr_rejected" and kw.get("reason") == "unreviewable"
               for e, kw in events)
    assert github.calls == []


def test_pr_with_direction_control_characters_is_refused(env):
    main, lga, wp, client, github, events = env
    content = ("public class Job {\n  // \u202e } \u2066if (isAdmin)\u2069 \u2067{\u2068\n"
               "  if (isAdmin) { grant(); }\n}\n")
    out, run = _propose(_tools(lga, github)["create_github_pr"], wp,
                        {**_PR_ARGS, "new_content": content})
    assert out["success"] is False and "direction-control" in out["error"]
    assert run == [] and wp.pending() == []
    assert any(e == "github_pr_rejected" and kw.get("reason") == "hidden_characters"
               for e, kw in events)
    assert github.calls == []


def test_approver_sees_the_whole_body_and_file(env):
    main, lga, wp, client, github, events = env
    body = "b" * 19000
    content = "public class Job {}\n// " + "y" * 30000 + "\n// end of file\n"
    out, run = _propose(_tools(lga, github)["create_github_pr"], wp,
                        {**_PR_ARGS, "pr_body": body, "new_content": content})
    assert out["success"] is True
    detail = run[0]["detail"]
    assert detail.startswith(body) and detail.endswith(content)
    assert wp.pending()[0]["detail"] == detail


def test_propose_never_truncates_detail(env):
    _, _, wp, *_ = env
    with pytest.raises(wp.DetailTooLong):
        wp.propose("create_github_pr", {}, "s", detail="z" * (wp.DETAIL_MAX_CHARS + 1))
    assert wp.pending() == []
