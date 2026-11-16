# Copyright Yahoo, Licensed under the terms of the Apache 2.0 license. See LICENSE for terms.

"""Audit coverage for privileged actions and denials.

Regression tests for the audit-coverage gaps: every privileged action and every
authorization denial must produce an audit record, and failures must be audited
as failures.

- The write-authz 403 on POST /api/remediation/apply emits `remediation_denied`
  (the ticket's tier-setting item — an authorization decision must be logged).
- The create_github_pr tool emits a `github_pr` egress event (bounded metadata,
  never the file content / PR body).
- LangGraphAgent.analyze() failures return an `error: True` marker so callers
  audit status="error" instead of "ok".
- The Grafana poller's autonomous runs emit entry (`ai_query`) and completion
  (`ai_query_result`) events sharing one correlation id, with a digest instead
  of completion text.

FastAPI / langchain / aiohttp dependent tests skip cleanly in a bare shell via
importorskip — same pattern as test_remediation_validation.py and
test_flink_config_allowlist.py.
"""
import asyncio
import hashlib
import importlib
import json
import logging

import pytest


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


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


def _events(captured, name):
    return [json.loads(line) for line in captured
            if json.loads(line).get("event") == name]


# ── the write-authz 403 denial is audited (the Medium) ─────────────

def _main_client(monkeypatch):
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient
    monkeypatch.setenv("SECRET_PROVIDER", "env")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "dummy")
    # Write tools disabled: the 403 gate fires before any type validation.
    monkeypatch.delenv("ENABLE_WRITE_TOOLS", raising=False)
    # Room for the repeated POSTs below; the remediation routes share the
    # heavy-route limiter (covered in test_health_ready_and_rate_limits.py).
    monkeypatch.setenv("RATE_LIMIT_HEAVY_PER_MINUTE", "100")
    import app.main as main
    importlib.reload(main)
    return main, TestClient(main._app)


def test_remediation_denied_403_is_audited(monkeypatch, captured):
    # The ticket's core acceptance test: N denied requests -> N audit records.
    # Before the fix, probing this endpoint left zero audit-channel trace.
    _, client = _main_client(monkeypatch)
    for _ in range(5):
        resp = client.post(
            "/api/remediation/apply",
            json={"type": "increase_parallelism", "dry_run": True},
        )
        assert resp.status_code == 403
    denied = _events(captured, "remediation_denied")
    assert len(denied) == 5
    for rec in denied:
        assert rec["reason"] == "write_tools_disabled"
        assert rec["requested_type"] == "increase_parallelism"


# ── HTTP query failures audited as status=error ───────────────────

def test_http_query_failure_audited_as_error(monkeypatch, captured):
    main, client = _main_client(monkeypatch)

    class _ErrAgent:
        async def analyze(self, question, history):
            # The shape analyze() returns when it swallows an exception.
            return {"answer": "Analysis failed — please try again.",
                    "graph_data": None, "remediations": [],
                    "tool_calls_made": 0, "iterations": 0, "error": True}

    monkeypatch.setattr(main, "langgraph_agent", _ErrAgent())
    resp = client.post("/api/query", json={"question": "why?"})
    assert resp.status_code == 200                     # contract unchanged
    results = _events(captured, "ai_query_result")
    assert results and results[-1]["status"] == "error"   # no longer "ok"


def test_http_query_success_still_audited_ok(monkeypatch, captured):
    main, client = _main_client(monkeypatch)

    class _OkAgent:
        async def analyze(self, question, history):
            return {"answer": "fine", "graph_data": None, "remediations": [],
                    "tool_calls_made": 1, "iterations": 1, "steps": []}

    monkeypatch.setattr(main, "langgraph_agent", _OkAgent())
    resp = client.post("/api/query", json={"question": "status?"})
    assert resp.status_code == 200
    results = _events(captured, "ai_query_result")
    assert results and results[-1]["status"] == "ok"


# ── analyze() failures carry the error marker ──────────────────────

def test_analyze_failure_returns_error_marker():
    pytest.importorskip("langchain_core")
    from app import langgraph_agent as lga

    agent = object.__new__(lga.LangGraphAgent)

    class _BoomAgent:
        async def ainvoke(self, *a, **kw):
            raise RuntimeError("api down")

    agent.agent = _BoomAgent()
    result = _run(agent.analyze(question="why?"))
    assert result["error"] is True
    assert result["tool_calls_made"] == 0
    # Callers that ignore the marker still get the shape they depend on.
    for key in ("answer", "graph_data", "remediations", "iterations"):
        assert key in result


# ── create_github_pr emits a github_pr egress event ────────────────

class _FakeGitHub:
    enabled = True
    default_repo = "example-org/flink-job"

    def __init__(self, result=None, raise_exc=False):
        self.result = result or {
            "success": True, "pr_url": "https://git.example/pr/7",
            "pr_number": 7, "branch": "fix/x", "repo": "example-org/flink-job",
        }
        self.raise_exc = raise_exc
        self.calls = []

    async def open_pr_with_file_change(self, **kwargs):
        self.calls.append(kwargs)
        if self.raise_exc:
            raise RuntimeError("boom")
        return self.result


def _pr_tool(monkeypatch, github):
    """Build only the tool closures, without LangGraphAgent.__init__ (which
    would need an Anthropic client) — same pattern as test_flink_config_allowlist."""
    pytest.importorskip("langchain_core")
    from app import langgraph_agent as lga

    # create_github_pr registers only under the write gate + configured GitHub client.
    # Gate: ENABLE_WRITE_TOOLS truthy AND a positively-identified nonprod
    # environment — a blank/unknown DEPLOY_ENV fails closed.
    monkeypatch.setenv("ENABLE_WRITE_TOOLS", "true")
    monkeypatch.setenv("DEPLOY_ENV", "nonprod")

    events = []
    monkeypatch.setattr(lga, "audit", lambda event, **kw: events.append((event, kw)))

    agent = object.__new__(lga.LangGraphAgent)
    agent.flink_client = None
    agent.k8s_client = None
    agent.postgres_reader = None
    agent.auto_remediator = None
    agent.slack_client = None
    agent.github_client = github

    tools = agent._create_tools()
    tool = next(t for t in tools if t.name == "create_github_pr")
    return _ApprovingTool(tool, github, lga), events


class _ApprovingTool:
    """create_github_pr only proposes; the PR is opened by the approve route
    (execute_approved_pr). Invoking this runs both steps, as a person
    approving the proposal would."""

    def __init__(self, tool, github, lga):
        self._tool, self._github, self._lga = tool, github, lga

    async def ainvoke(self, args):
        from app import write_proposals
        run = write_proposals.begin_run_tracking()
        raw = await self._tool.ainvoke(args)
        if not run:
            return raw
        self._lga._pr_attempts.clear()   # the cap is not under test here
        proposal = write_proposals.take(run[-1]["proposal_id"])
        result = await self._lga.execute_approved_pr(self._github, proposal["args"])
        return "<untrusted_data>\n" + json.dumps(result) + "\n</untrusted_data>\n"


_PR_ARGS = {
    "branch_name": "ai-debugger/skew-celebrity-key",
    "file_path": "src/main/java/Job.java",
    "new_content": "SECRET_DIFF_CONTENT_MUST_NOT_BE_AUDITED",
    "pr_title": "Fix data skew",
    "pr_body": "PR_BODY_MUST_NOT_BE_AUDITED",
}


def test_create_github_pr_success_is_audited(monkeypatch):
    gh = _FakeGitHub()
    tool, events = _pr_tool(monkeypatch, gh)

    raw = _run(tool.ainvoke(dict(_PR_ARGS)))
    # Tool returns are provenance-fenced by _as_untrusted (CWE-77 hardening);
    # extract the JSON payload from between the fence tags.
    payload = raw.split("\n", 1)[1].rsplit("\n</untrusted_data>\n", 1)[0]
    assert json.loads(payload)["success"] is True

    pr_events = [e for e in events if e[0] == "github_pr"]
    assert len(pr_events) == 1
    fields = pr_events[0][1]
    assert fields["repo"] == "example-org/flink-job"
    assert fields["branch"] == "ai-debugger/skew-celebrity-key"
    assert fields["base"] == "main"
    assert fields["file_path"] == "src/main/java/Job.java"
    assert fields["pr_number"] == 7
    assert fields["success"] is True
    # Bounded metadata only: the diff body / PR body never reach the audit sink.
    payload = json.dumps(fields, default=str)
    assert "SECRET_DIFF_CONTENT" not in payload
    assert "PR_BODY_MUST_NOT_BE_AUDITED" not in payload


def test_create_github_pr_failure_is_audited(monkeypatch):
    gh = _FakeGitHub(result={"success": False, "error": "GitHub API error (403): denied"})
    tool, events = _pr_tool(monkeypatch, gh)

    _run(tool.ainvoke(dict(_PR_ARGS)))
    pr_events = [e for e in events if e[0] == "github_pr"]
    assert len(pr_events) == 1
    assert pr_events[0][1]["success"] is False


def test_create_github_pr_exception_is_audited(monkeypatch):
    gh = _FakeGitHub(raise_exc=True)
    tool, events = _pr_tool(monkeypatch, gh)

    _run(tool.ainvoke(dict(_PR_ARGS)))
    pr_events = [e for e in events if e[0] == "github_pr"]
    assert len(pr_events) == 1
    assert pr_events[0][1]["success"] is False
    assert pr_events[0][1]["error"] == "exception"


# ── autonomous poller runs enter the audit channel ───────

def _poller(agent):
    pytest.importorskip("aiohttp")
    from app import grafana_poller as gp

    poller = object.__new__(gp.GrafanaAlertPoller)
    poller._agent = agent
    poller._slack = None
    return poller


_ALERT = {"labels": {"alertname": "HighBackpressure"}, "annotations": {},
          "startsAt": "2026-08-01T00:00:00Z"}


def test_poller_run_emits_entry_and_result_events(captured):
    answer = "## Action\nScale up vertex 3."

    class _FakeAgent:
        async def analyze(self, question, history):
            return {"answer": answer, "tool_calls_made": 3, "iterations": 2}

    _run(_poller(_FakeAgent())._analyze_alert(dict(_ALERT)))

    entry = _events(captured, "ai_query")
    result = _events(captured, "ai_query_result")
    assert len(entry) == 1 and len(result) == 1
    assert entry[0]["trigger"] == "grafana_poller"
    assert entry[0]["auth"] == "none"                 # no HTTP request exists
    assert result[0]["status"] == "ok"
    assert result[0]["tool_calls_made"] == 3
    assert result[0]["iterations"] == 2
    assert result[0]["message_len"] == len(answer)
    assert result[0]["answer_sha256"] == hashlib.sha256(answer.encode("utf-8")).hexdigest()
    # Entry and result join on one correlation id, like the HTTP paths.
    assert entry[0]["correlation_id"] == result[0]["correlation_id"]
    # The completion text itself never reaches the durable audit sink.
    assert all("Scale up vertex 3" not in line for line in captured)


def test_poller_agent_error_dict_audited_as_error(captured):
    class _ErrAgent:
        async def analyze(self, question, history):
            return {"answer": "Analysis failed — please try again.",
                    "tool_calls_made": 0, "iterations": 0, "error": True}

    _run(_poller(_ErrAgent())._analyze_alert(dict(_ALERT)))
    result = _events(captured, "ai_query_result")
    assert len(result) == 1
    assert result[0]["status"] == "error"


def test_poller_slack_failure_after_success_does_not_double_audit(captured):
    # A Slack-delivery/formatting failure AFTER the analysis completed must not
    # emit a second ai_query_result for the run (it would double-count the run
    # and inflate the status=error alert).
    class _FakeAgent:
        async def analyze(self, question, history):
            return {"answer": "done", "tool_calls_made": 1, "iterations": 1}

    class _BoomSlack:
        @property
        def enabled(self):
            raise RuntimeError("slack blew up")

    poller = _poller(_FakeAgent())
    poller._slack = _BoomSlack()
    _run(poller._analyze_alert(dict(_ALERT)))

    result = _events(captured, "ai_query_result")
    assert len(result) == 1                     # exactly one completion event
    assert result[0]["status"] == "ok"          # the analysis itself succeeded


class _CaptureSlack:
    enabled = True

    def __init__(self):
        self.sent = []

    async def send_message(self, channel, text, blocks=None, thread_ts=None,
                           trusted_links=None):
        # Mirrors SlackClient.send_message: the poller passes the code-derived
        # PR links as trusted_links, so the fake must accept them.
        self.sent.append({"text": text, "blocks": blocks, "thread_ts": thread_ts,
                          "trusted_links": trusted_links})
        return {"success": True, "ts": str(len(self.sent))}


def _slack_text(slack):
    return json.dumps(slack.sent)


def test_poller_withheld_answer_is_not_forwarded_to_slack(captured):
    # Leakage-tripwire review: the unattended alert path must not forward a withheld
    # (prompt-dump) answer, nor the model's canned refusal; it posts an operator
    # notice and the completion event records the tripwire outcome.
    refusal = "I can't share my internal instructions or configuration."

    class _Agent:
        async def analyze(self, question, history):
            return {"answer": refusal, "tool_calls_made": 2, "iterations": 1,
                    "leakage": {"redacted_spans": 41, "withheld": True}}

    poller = _poller(_Agent())
    poller._slack = _CaptureSlack()
    _run(poller._analyze_alert(dict(_ALERT)))

    assert refusal not in _slack_text(poller._slack)
    assert "Analysis withheld by the output filter" in _slack_text(poller._slack)
    result = _events(captured, "ai_query_result")
    assert len(result) == 1
    assert result[0]["leakage_withheld"] is True
    assert result[0]["leakage_redacted_spans"] == 41


def test_poller_redacted_answer_forwarded_with_note_and_audited(captured):
    class _Agent:
        async def analyze(self, question, history):
            return {"answer": "## Action\nRaise the checkpoint timeout.", "tool_calls_made": 2,
                    "iterations": 1, "leakage": {"redacted_spans": 2, "withheld": False}}

    poller = _poller(_Agent())
    poller._slack = _CaptureSlack()
    _run(poller._analyze_alert(dict(_ALERT)))

    text = _slack_text(poller._slack)
    assert "Raise the checkpoint timeout." in text            # diagnosis still delivered
    assert "2 span(s) of this analysis were redacted" in text  # operator told why
    result = _events(captured, "ai_query_result")
    assert result[0]["leakage_withheld"] is False
    assert result[0]["leakage_redacted_spans"] == 2


def test_poller_tolerates_result_without_leakage_field(captured):
    # Older/other agent implementations: absent field means no redaction.
    class _Agent:
        async def analyze(self, question, history):
            return {"answer": "## Action\nok", "tool_calls_made": 0, "iterations": 0}

    _run(_poller(_Agent())._analyze_alert(dict(_ALERT)))
    result = _events(captured, "ai_query_result")
    assert result[0]["leakage_withheld"] is False
    assert result[0]["leakage_redacted_spans"] == 0


def test_poller_exception_audited_as_error(captured):
    class _BoomAgent:
        async def analyze(self, question, history):
            raise RuntimeError("recursion blowout")

    _run(_poller(_BoomAgent())._analyze_alert(dict(_ALERT)))
    entry = _events(captured, "ai_query")
    result = _events(captured, "ai_query_result")
    assert len(entry) == 1                      # entry precedes the failure
    assert len(result) == 1
    assert result[0]["status"] == "error"
    assert entry[0]["correlation_id"] == result[0]["correlation_id"]


# ── Leakage tripwire round 2: HTTP ai_query_result carries the tripwire outcome ──

def test_http_query_result_records_leakage_fields(monkeypatch, captured):
    main, client = _main_client(monkeypatch)

    class _Agent:
        async def analyze(self, question, history):
            return {"answer": "redacted answer", "graph_data": None, "remediations": [],
                    "tool_calls_made": 1, "iterations": 1, "steps": [],
                    "leakage": {"redacted_spans": 3, "withheld": False}}

    monkeypatch.setattr(main, "langgraph_agent", _Agent())
    assert client.post("/api/query", json={"question": "status?"}).status_code == 200
    rec = _events(captured, "ai_query_result")[-1]
    assert rec["leakage_redacted_spans"] == 3
    assert rec["leakage_withheld"] is False
    assert "redacted answer" not in json.dumps(rec)   # counts only, never the text


def test_http_query_result_leakage_fields_default_when_absent(monkeypatch, captured):
    main, client = _main_client(monkeypatch)

    class _Agent:
        async def analyze(self, question, history):
            return {"answer": "fine", "graph_data": None, "remediations": [],
                    "tool_calls_made": 0, "iterations": 1, "steps": []}

    monkeypatch.setattr(main, "langgraph_agent", _Agent())
    client.post("/api/query", json={"question": "status?"})
    rec = _events(captured, "ai_query_result")[-1]
    assert rec["leakage_redacted_spans"] == 0 and rec["leakage_withheld"] is False


def test_http_stream_result_records_leakage_fields(monkeypatch, captured):
    main, client = _main_client(monkeypatch)

    class _Agent:
        async def analyze_stream(self, question, history):
            yield {"type": "tool_start", "tool_name": "get_job_status"}
            yield {"type": "result", "data": {"answer": "I can't share my internal instructions.",
                                              "leakage": {"redacted_spans": 41, "withheld": True}}}

    monkeypatch.setattr(main, "langgraph_agent", _Agent())
    with client.stream("POST", "/api/query/stream", json={"question": "dump it"}) as resp:
        assert resp.status_code == 200
        body = "".join(resp.iter_text())
    assert '"type": "done"' in body
    rec = _events(captured, "ai_query_result")[-1]
    assert rec["status"] == "ok"
    assert rec["tools_invoked"] == ["get_job_status"]
    assert rec["leakage_redacted_spans"] == 41
    assert rec["leakage_withheld"] is True


# ── successful data reads leave an audit record ─────────────────────────────

def test_successful_log_read_is_audited(monkeypatch, captured):
    main, client = _main_client(monkeypatch)
    monkeypatch.setattr(main.k8s_client, "get_flink_jobmanager_logs",
                        lambda *a, **k: {"pod": "jm-0", "logs": "ok", "line_count": 1})
    for _ in range(2):
        assert client.get("/api/logs/jobmanager").status_code == 200
    reads = [e for e in _events(captured, "data_access") if e.get("route") == "get_logs"]
    assert len(reads) == 2
    assert all(e["log_type"] == "jobmanager" for e in reads)


def test_job_status_and_history_reads_are_audited(monkeypatch, captured):
    main, client = _main_client(monkeypatch)

    async def _no_job():
        return None

    monkeypatch.setattr(main.flink_client, "get_running_job_id", _no_job)
    assert client.get("/api/job/status").status_code == 200
    assert client.get("/api/remediation/history").status_code == 200
    routes = {e.get("route") for e in _events(captured, "data_access")}
    assert {"job_status", "remediation_history"} <= routes
