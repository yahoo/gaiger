"""Tool-LEVEL egress tests: the validators have their own unit
tests, but nothing exercised the registered tool closures end to end —
invoking create_github_pr / read_github_file / list_github_files /
send_to_slack with model-shaped arguments and asserting that a refused call
never reaches the client, that the refusal is audited, and that the accepted
call carries the governed arguments (no channel, trusted PR link, listing
predicate).

Builds only the tool closures (no LangGraphAgent.__init__, which needs an
Anthropic client) — same pattern as tests/test_audit_coverage.py. Needs
langchain_core (present in the built image / venv); skips in a bare shell.
"""

import asyncio
import json
from unittest.mock import patch

import pytest

pytest.importorskip("langchain_core")

from app import langgraph_agent as lga  # noqa: E402


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


class _FakeGitHub:
    enabled = True
    default_repo = "example-org/flink-job"

    def __init__(self, read_result=None, list_files=None):
        self.calls = []
        self.read_result = read_result or {
            "success": True, "content": "public class Job {}", "sha": "abc",
            "path": "src/main/java/Job.java", "size": 19, "ref": "main",
        }
        self.list_result_files = list_files if list_files is not None else ["src/main/java/Job.java"]

    async def open_pr_with_file_change(self, **kwargs):
        self.calls.append(("open_pr", kwargs))
        return {"success": True, "pr_url": "https://github.com/example-org/flink-job/pull/7",
                "pr_number": 7, "branch": kwargs["branch_name"], "repo": self.default_repo}

    async def read_file(self, repo, file_path, ref="main"):
        self.calls.append(("read_file", {"repo": repo, "file_path": file_path, "ref": ref}))
        return dict(self.read_result)

    async def list_files(self, repo, path_filter=None, ref="main", path_allowed=None):
        self.calls.append(("list_files", {"repo": repo, "path_filter": path_filter,
                                          "ref": ref, "path_allowed": path_allowed}))
        files = [p for p in self.list_result_files if path_allowed is None or path_allowed(p)]
        return {"success": True, "repo": repo, "ref": ref, "path_filter": path_filter,
                "count": len(files), "truncated": False, "files": files}


class _FakeSlack:
    enabled = True

    def __init__(self):
        self.sends = []

    def format_analysis_as_blocks(self, analysis, title="Flink AI Analysis"):
        return [{"type": "section", "text": {"type": "mrkdwn", "verbatim": True, "text": analysis}}]

    async def send_message(self, **kwargs):
        self.sends.append(kwargs)
        return {"success": True, "channel": "my-team-alerts", "ts": "1.2"}


@pytest.fixture
def toolset(monkeypatch):
    """(tools-by-name, audit events, fake github, fake slack) with write tools
    and the GitHub tool set registered."""
    monkeypatch.setenv("ENABLE_WRITE_TOOLS", "true")
    monkeypatch.setenv("DEPLOY_ENV", "nonprod")
    events = []
    monkeypatch.setattr(lga, "audit", lambda event, **kw: events.append((event, kw)))

    github, slack = _FakeGitHub(), _FakeSlack()
    agent = object.__new__(lga.LangGraphAgent)
    agent.flink_client = None
    agent.k8s_client = None
    agent.postgres_reader = None
    agent.auto_remediator = None
    agent.slack_client = slack
    agent.github_client = github
    tools = {t.name: t for t in agent._create_tools()}
    for name in ("create_github_pr", "read_github_file", "list_github_files", "send_to_slack"):
        assert name in tools, f"{name} not registered under the write gate"
    return tools, events, github, slack


def _events(events, name):
    return [kw for ev, kw in events if ev == name]


def _propose(tool, args):
    """Invoke create_github_pr; return (tool output, proposal id or None)."""
    from app import write_proposals
    run = write_proposals.begin_run_tracking()
    before = len(run)
    raw = _run(tool.ainvoke(args))
    out = json.loads(lga._unfenced(raw))
    pid = run[-1]["proposal_id"] if len(run) > before else None
    return out, pid


def _approve(github, pid):
    """What POST /api/remediation/approve does for a create_github_pr proposal."""
    from app import write_proposals
    proposal = write_proposals.take(pid)
    assert proposal is not None and proposal["action"] == "create_github_pr"
    return _run(lga.execute_approved_pr(github, proposal["args"]))


_PR_ARGS = {
    "branch_name": "ai-debugger/skew-celebrity-key",
    "file_path": "src/main/java/Job.java",
    "new_content": "public class Job { /* fixed */ }",
    "pr_title": "Fix data skew",
    "pr_body": "root cause + fix",
}


# ── create_github_pr: refused BEFORE any GitHub call ────────────────────────────

@pytest.mark.parametrize("override,reason", [
    ({"branch_name": "main"}, "branch_name_not_allowed"),                # commit-on-main primitive
    ({"branch_name": "fix/skew"}, "branch_name_not_allowed"),            # outside the namespace
    ({"branch_name": "ai-debugger/x", "base_branch": "ai-debugger/x"}, "branch_name_not_allowed"),
    ({"base_branch": "a..b"}, "branch_name_not_allowed"),                # bad base ref
    ({"file_path": ".github/workflows/deploy.yml"}, "path_not_allowed"),
    ({"file_path": "a/../k8s/rbac.yaml"}, "path_not_allowed"),
    ({"file_path": "infra/terraform/main.tf"}, "path_not_allowed"),
    ({"file_path": 'src/a.java\n{"event":"forged"}'}, "path_not_allowed"),
])
def test_create_github_pr_refuses_before_any_api_call(toolset, override, reason):
    tools, events, github, _ = toolset
    out = json.loads(_run(tools["create_github_pr"].ainvoke({**_PR_ARGS, **override})))
    assert out["success"] is False
    assert github.calls == [], "the GitHub client must not be reached on a refused argument"
    rejected = _events(events, "github_pr_rejected")
    assert len(rejected) == 1 and rejected[0]["reason"] == reason
    assert _events(events, "github_pr") == []


def test_create_github_pr_only_proposes_and_opens_on_approval(toolset):
    tools, events, github, _ = toolset
    out, pid = _propose(tools["create_github_pr"], dict(_PR_ARGS))
    assert out["success"] is True and out["proposed"] is True
    assert "pr_number" not in out and pid is not None
    assert github.calls == [], "nothing reaches GitHub before a person approves"
    assert _events(events, "github_pr") == []
    assert _events(events, "write_proposed")[0]["action"] == "create_github_pr"
    assert pid not in json.dumps(out)                                   # id never enters model context

    result = _approve(github, pid)
    assert result["success"] is True and result["pr_number"] == 7
    assert [c[0] for c in github.calls] == ["open_pr"]
    assert github.calls[0][1]["repo"] == "example-org/flink-job"          # repo pinned, never model-chosen
    pr_event = _events(events, "github_pr")[0]
    assert pr_event["success"] is True and pr_event["applied_by"] == "approved"


# ── send_to_slack: no destination parameter, trusted PR link from the tool result

def test_send_to_slack_has_no_channel_and_links_no_merely_proposed_pr(toolset):
    tools, events, _, slack = toolset
    lga._begin_pr_tracking()
    _run(tools["create_github_pr"].ainvoke(dict(_PR_ARGS)))         # proposed, not opened
    out = json.loads(lga._unfenced(_run(tools["send_to_slack"].ainvoke({
        "message": "Drafted PR: https://evil.example/pull/1 <!channel>", "title": "t"}))))
    assert out["success"] is True
    assert len(slack.sends) == 1
    sent = slack.sends[0]
    assert sent["channel"] is None                                    # sink resolves the destination
    assert sent["trusted_links"] == []                                # no PR exists to link
    assert "channel" not in tools["send_to_slack"].args
    assert _events(events, "slack_send")[0]["success"] is True


def test_send_to_slack_without_a_pr_this_run_passes_no_links(toolset):
    tools, _, _, slack = toolset
    lga._begin_pr_tracking()
    _run(tools["send_to_slack"].ainvoke({"message": "hello"}))
    assert slack.sends[0]["trusted_links"] == []


def test_pr_tracking_is_per_run_context():
    """Two concurrent analyze() runs must not see each other's PRs."""
    async def run_a():
        lga._begin_pr_tracking()
        lga._record_created_pr({"pr_url": "https://github.com/o/r/pull/1", "pr_number": 1})
        await asyncio.sleep(0.01)
        return lga._created_pr_links()

    async def run_b():
        lga._begin_pr_tracking()
        await asyncio.sleep(0.005)
        return lga._created_pr_links()

    async def both():
        return await asyncio.gather(asyncio.create_task(run_a()), asyncio.create_task(run_b()))

    a, b = _run(both())
    assert a == [("https://github.com/o/r/pull/1", "PR #1")]
    assert b == []


def test_record_created_pr_ignores_malformed_results():
    lga._begin_pr_tracking()
    lga._record_created_pr({"pr_url": "https://x/1"})                 # no number
    lga._record_created_pr({"pr_url": None, "pr_number": 1})
    lga._record_created_pr({"pr_url": "https://x/1", "pr_number": "1"})  # number must be int
    assert lga._created_pr_links() == []


# ── read_github_file ────────────────────────────────────────────────────────────

@pytest.mark.parametrize("args,reason", [
    ({"file_path": "k8s/rbac.yaml"}, "path_not_allowed"),
    ({"file_path": ".netrc"}, "path_not_allowed"),
    ({"file_path": "certs/apns.p8"}, "path_not_allowed"),
    ({"file_path": "src/Job.java", "ref": "a..b"}, "ref_not_allowed"),
])
def test_read_github_file_refuses_before_any_api_call(toolset, args, reason):
    tools, events, github, _ = toolset
    out = json.loads(_run(tools["read_github_file"].ainvoke(args)))
    assert out["success"] is False
    assert github.calls == []
    assert _events(events, "github_read_rejected")[0]["reason"] == reason


def test_read_github_file_passes_source_through_verbatim(toolset):
    tools, events, github, _ = toolset
    # Non-ASCII, a ZWJ (emoji sequence) and fullwidth CJK punctuation: the edit
    # path must neither redact nor normalize (the untrusted-input fence wraps it with
    # normalize=False so what the model writes back is what it read).
    github.read_result["content"] = "kafka.sasl.password = ${KAFKA_PASSWORD}\né \"👨\u200d👩\"，\n" * 3
    raw = _run(tools["read_github_file"].ainvoke({"file_path": "src/main/java/Job.java"}))
    assert raw.startswith('<untrusted_data source="github_repository">\n')
    out = json.loads(lga._unfenced(raw))
    assert out["success"] is True
    assert out["content"] == github.read_result["content"]           # no redaction / normalization on the edit path
    assert _events(events, "github_read")[0]["success"] is True


def test_read_github_file_refuses_credential_material(toolset):
    tools, events, github, _ = toolset
    github.read_result["content"] = "config:\n-----BEGIN RSA PRIVATE KEY-----\nMIIE..."
    out = json.loads(_run(tools["read_github_file"].ainvoke({"file_path": "src/main/resources/x.yaml"})))
    assert out["success"] is False and "credential" in out["error"]
    assert "BEGIN RSA" not in json.dumps(out)
    assert _events(events, "github_read_rejected")[0]["reason"] == "credential_material"
    assert _events(events, "github_read") == []


def test_read_github_file_oversize_refusal_is_audited_as_rejection(toolset, monkeypatch):
    """Round-2 review: the `github_read` event was emitted with success=True
    BEFORE passthrough_for_edit refused the oversize file, so the audit trail
    claimed an egress that never happened."""
    from app import egress_governance as eg
    monkeypatch.setattr(eg, "MAX_EDITABLE_FILE_CHARS", 100)
    monkeypatch.setattr(lga, "_content_too_large_for_edit",
                        lambda result: eg.content_too_large_for_edit(result, 100))
    monkeypatch.setattr(lga, "_passthrough_for_edit",
                        lambda result: eg.passthrough_for_edit(result, 100))
    tools, events, github, _ = toolset
    github.read_result["content"] = "x" * 101
    out = json.loads(_run(tools["read_github_file"].ainvoke({"file_path": "src/main/java/Job.java"})))
    assert out["success"] is False and "too large" in out["error"]
    assert "x" * 101 not in json.dumps(out)
    assert _events(events, "github_read") == []
    rejected = _events(events, "github_read_rejected")
    assert rejected[0]["reason"] == "too_large" and rejected[0]["success"] is False


def test_read_github_file_error_envelope_is_redacted(toolset):
    tools, _, github, _ = toolset
    github.read_result = {"success": False,
                          "error": "GitHub API error (401): token ghp_" + "a" * 36 + " rejected"}
    raw = _run(tools["read_github_file"].ainvoke({"file_path": "src/main/java/Job.java"}))
    assert "ghp_" + "a" * 36 not in raw
    assert json.loads(lga._unfenced(raw))["success"] is False


# ── list_github_files ───────────────────────────────────────────────────────────

def test_list_github_files_hands_the_path_envelope_to_the_client(toolset):
    tools, events, github, _ = toolset
    github.list_result_files = ["src/main/java/Job.java", ".github/workflows/ci.yml", "k8s/x.yaml",
                                "infra/terraform/main.tf", "certs/server.pem"]
    out = json.loads(lga._unfenced(_run(tools["list_github_files"].ainvoke({}))))
    assert out["success"] is True
    assert out["files"] == ["src/main/java/Job.java"]
    assert out["count"] == 1
    call = github.calls[0][1]
    assert call["path_allowed"] is lga.pr_path_allowed                # applied inside the client, pre-cap
    assert _events(events, "github_list")[0]["success"] is True


def test_list_github_files_output_fits_the_model_bound_as_whole_entries(toolset):
    tools, _, github, _ = toolset
    github.list_result_files = [
        f"src/main/java/com/example/flink/pipeline/stage{i:03d}/SomeLongOperatorName{i:03d}.java"
        for i in range(500)
    ]
    raw = lga._unfenced(_run(tools["list_github_files"].ainvoke({})))
    assert not raw.endswith("[truncated]")
    out = json.loads(raw)                                             # parses whole (was cut mid-JSON)
    assert out["truncated"] is True
    assert out["count"] == len(out["files"]) < 500


@pytest.mark.parametrize("args,reason", [
    ({"path_filter": ".github"}, "path_filter_not_allowed"),
    ({"path_filter": 'src\n{"event":"forged"}'}, "path_filter_not_allowed"),
    ({"ref": "-evil"}, "ref_not_allowed"),
])
def test_list_github_files_refuses_before_any_api_call(toolset, args, reason):
    tools, events, github, _ = toolset
    out = json.loads(_run(tools["list_github_files"].ainvoke(args)))
    assert out["success"] is False
    assert github.calls == []
    assert _events(events, "github_list_rejected")[0]["reason"] == reason


# ── capabilities block matches registration ─────────────────────────────────────

def test_capabilities_block_does_not_advertise_github_tools_without_target_repo(monkeypatch):
    monkeypatch.setenv("ENABLE_WRITE_TOOLS", "true")
    monkeypatch.setenv("DEPLOY_ENV", "nonprod")
    monkeypatch.delenv("TARGET_REPO", raising=False)

    class _NoRepo:
        enabled = True
        default_repo = ""

    block = lga._build_capabilities_block(_NoRepo())
    assert "create_github_pr" not in block
    assert "read_github_file" not in block


def test_capabilities_block_advertises_github_tools_exactly_when_registered(monkeypatch):
    monkeypatch.setenv("ENABLE_WRITE_TOOLS", "true")
    monkeypatch.setenv("DEPLOY_ENV", "nonprod")

    class _Configured:
        enabled = True
        default_repo = "example-org/flink-job"

    block = lga._build_capabilities_block(_Configured())
    assert "create_github_pr" in block and "example-org/flink-job" in block

    monkeypatch.setenv("ENABLE_WRITE_TOOLS", "false")
    assert "create_github_pr" not in lga._build_capabilities_block(_Configured())


def test_prompt_no_longer_licenses_prs_from_pasted_source():
    assert "using only source the operator supplied" not in lga.SYSTEM_PROMPT
    assert "diff was not verified against the current file" not in lga.SYSTEM_PROMPT
    # round-2: the tool-routing table still carried the pasted-source fallback
    assert "source the operator supplied" not in lga.SYSTEM_PROMPT
    assert "do not offer to open a PR" in lga.SYSTEM_PROMPT
    assert "never open a PR from source you did not read in this run" in lga.SYSTEM_PROMPT


# ── poller: Slack delivery is audited and counted ───────────────────────────────

def _poller(agent, slack):
    pytest.importorskip("aiohttp")
    from app import grafana_poller as gp
    poller = object.__new__(gp.GrafanaAlertPoller)
    poller._agent = agent
    poller._slack = slack
    return poller


_ALERT = {"labels": {"alertname": "HighBackpressure"}, "annotations": {},
          "startsAt": "2026-08-01T00:00:00Z"}
_ANSWER = "🔴 verdict\n## Action\nOpened a PR.\n## Evidence\nlots"


class _Agent:
    def __init__(self, prs):
        self.prs = prs

    async def analyze(self, question, history):
        return {"answer": _ANSWER, "tool_calls_made": 3, "iterations": 2, "pull_requests": self.prs}


class _RefusingSlack(_FakeSlack):
    async def send_message(self, **kwargs):
        self.sends.append(kwargs)
        return {"success": False, "error": "destination channel is not permitted by this deployment"}


def test_poller_audits_both_sends_and_passes_trusted_pr_links(monkeypatch):
    from app import grafana_poller as gp
    events, outcomes = [], []
    monkeypatch.setattr(gp, "audit", lambda event, **kw: events.append((event, kw)))
    monkeypatch.setattr(gp.telemetry, "record_webhook", lambda src, outcome: outcomes.append(outcome))
    monkeypatch.setenv("GRAFANA_ALERT_SLACK_CHANNEL", "my-team-alerts")

    slack = _FakeSlack()
    prs = [{"pr_url": "https://github.com/example-org/flink-job/pull/7", "pr_number": 7}]
    _run(_poller(_Agent(prs), slack)._analyze_alert(dict(_ALERT)))

    assert len(slack.sends) == 2                                      # main post + thread reply
    assert slack.sends[0]["trusted_links"] == [(prs[0]["pr_url"], "PR #7")]
    assert slack.sends[1]["thread_ts"] == "1.2"
    sends = _events(events, "slack_send")
    assert len(sends) == 2 and all(s["success"] is True for s in sends)
    assert all(s["trigger"] == "grafana_poller" for s in sends)
    assert outcomes == ["ok"]


def test_poller_refused_send_is_audited_and_not_counted_as_ok(monkeypatch):
    from app import grafana_poller as gp
    events, outcomes = [], []
    monkeypatch.setattr(gp, "audit", lambda event, **kw: events.append((event, kw)))
    monkeypatch.setattr(gp.telemetry, "record_webhook", lambda src, outcome: outcomes.append(outcome))

    slack = _RefusingSlack()
    _run(_poller(_Agent([]), slack)._analyze_alert(dict(_ALERT)))

    assert len(slack.sends) == 1                                      # no thread reply after a refusal
    sends = _events(events, "slack_send")
    assert len(sends) == 1 and sends[0]["success"] is False
    assert "not permitted" in sends[0]["error"]
    assert outcomes == ["delivery_failed"]
    assert _events(events, "ai_query_result")[0]["status"] == "ok"   # the analysis itself was fine


def test_poller_analysis_error_keeps_precedence_over_delivery(monkeypatch):
    from app import grafana_poller as gp
    outcomes = []
    monkeypatch.setattr(gp, "audit", lambda event, **kw: None)
    monkeypatch.setattr(gp.telemetry, "record_webhook", lambda src, outcome: outcomes.append(outcome))

    class _ErrAgent:
        async def analyze(self, question, history):
            return {"answer": "Analysis failed", "tool_calls_made": 0, "iterations": 0, "error": True}

    _run(_poller(_ErrAgent(), _RefusingSlack())._analyze_alert(dict(_ALERT)))
    assert outcomes == ["error"]


class _DisabledSlack(_FakeSlack):
    enabled = False


@pytest.mark.parametrize("slack", [None, _DisabledSlack()])
def test_poller_unconfigured_slack_is_not_counted_as_ok(monkeypatch, slack):
    """slack_ok started at True, so a deployment with no Slack reported every
    run as "ok" while nobody received the diagnosis (round-3 review). The
    outcome is now its own label and the non-send is audited like the tool's."""
    from app import grafana_poller as gp
    events, outcomes = [], []
    monkeypatch.setattr(gp, "audit", lambda event, **kw: events.append((event, kw)))
    monkeypatch.setattr(gp.telemetry, "record_webhook", lambda src, outcome: outcomes.append(outcome))

    _run(_poller(_Agent([]), slack)._analyze_alert(dict(_ALERT)))

    assert outcomes == ["delivery_skipped"]
    sends = _events(events, "slack_send")
    assert len(sends) == 1 and sends[0]["success"] is False
    assert sends[0]["error"] == "slack_not_configured"
    assert _events(events, "ai_query_result")[0]["status"] == "ok"   # the analysis itself was fine


# ── alert-flow PR switch, daily cap, path-prefix allowlist ───────────────────

def _alert_toolset(monkeypatch, enabled):
    monkeypatch.setenv("ENABLE_WRITE_TOOLS", "true")
    monkeypatch.setenv("DEPLOY_ENV", "nonprod")
    if enabled is None:
        monkeypatch.delenv("ENABLE_ALERT_FLOW_PRS", raising=False)
    else:
        monkeypatch.setenv("ENABLE_ALERT_FLOW_PRS", enabled)
    agent = object.__new__(lga.LangGraphAgent)
    agent.flink_client = None
    agent.k8s_client = None
    agent.postgres_reader = None
    agent.auto_remediator = None
    agent.slack_client = _FakeSlack()
    agent.github_client = _FakeGitHub()
    agent.alert_flow = True
    return {t.name for t in agent._create_tools()}


def test_alert_flow_has_no_pr_tool_unless_opted_in(monkeypatch):
    names = _alert_toolset(monkeypatch, None)                 # (a) unset
    assert "create_github_pr" not in names
    assert "read_github_file" not in names
    assert "create_github_pr" not in _alert_toolset(monkeypatch, "false")
    assert "create_github_pr" in _alert_toolset(monkeypatch, "true")   # (b)


def test_chat_flow_keeps_the_pr_tool_without_the_alert_switch(toolset):
    tools, _, _, _ = toolset
    assert "create_github_pr" in tools


def test_daily_pr_cap_refuses_after_the_limit(toolset, monkeypatch):    # (c)
    tools, events, github, _ = toolset
    monkeypatch.setenv("GITHUB_PR_MAX_PER_DAY", "1")
    monkeypatch.setattr(lga, "_pr_attempts", lga.deque())
    _, pid1 = _propose(tools["create_github_pr"], dict(_PR_ARGS))
    _, pid2 = _propose(tools["create_github_pr"], {**_PR_ARGS, "branch_name": "ai-debugger/second"})
    first, second = _approve(github, pid1), _approve(github, pid2)    # cap applies at execution
    assert first["success"] is True
    assert second["success"] is False
    assert [c[0] for c in github.calls] == ["open_pr"]
    rejected = _events(events, "github_pr_rejected")
    assert rejected and rejected[-1]["reason"] == "daily_cap"


def test_path_prefix_allowlist(toolset, monkeypatch):
    tools, events, github, _ = toolset
    monkeypatch.setattr(lga, "_pr_attempts", lga.deque())
    monkeypatch.setenv("GITHUB_PR_ALLOWED_PREFIXES", "src/main/")
    out = json.loads(_run(tools["create_github_pr"].ainvoke({**_PR_ARGS, "file_path": "pom.xml"})))
    assert out["success"] is False and github.calls == []
    assert _events(events, "github_pr_rejected")[-1]["reason"] == "path_not_allowed"
    _, pid = _propose(tools["create_github_pr"], {**_PR_ARGS, "file_path": "src/main/java/Job.java"})
    _approve(github, pid)
    assert [c[0] for c in github.calls] == ["open_pr"]
    # Unset: pom.xml is accepted again.
    monkeypatch.delenv("GITHUB_PR_ALLOWED_PREFIXES")
    _, pid = _propose(tools["create_github_pr"], {**_PR_ARGS, "file_path": "pom.xml",
                                                  "branch_name": "ai-debugger/pom"})
    _approve(github, pid)
    assert [c[0] for c in github.calls] == ["open_pr", "open_pr"]


def test_prefix_allowlist_is_rechecked_at_approval(toolset, monkeypatch):
    tools, events, github, _ = toolset
    monkeypatch.setattr(lga, "_pr_attempts", lga.deque())
    _, pid = _propose(tools["create_github_pr"], {**_PR_ARGS, "file_path": "pom.xml"})
    monkeypatch.setenv("GITHUB_PR_ALLOWED_PREFIXES", "src/main/")     # tightened while pending
    result = _approve(github, pid)
    assert result["success"] is False and github.calls == []
    assert _events(events, "github_pr_rejected")[-1]["reason"] == "path_not_allowed"
