# Copyright Yahoo, Licensed under the terms of the Apache 2.0 license. See LICENSE for terms.

"""System-prompt leakage filter + prompt hardening (CWE-200).

The output filter `is_leakage_attempt()` must flag distinctive system-prompt content while
NOT firing on the answer-template headings the prompt instructs the model to emit, and the
Trust Boundary / confidentiality directive must sit at the top of the prompt.

Imports app.langgraph_agent (which pulls langchain); skips cleanly in a bare shell and runs
in CI (the built image does not contain tests/) — same pattern as the other agent-level tests.
"""
import asyncio
import json
import re

import pytest

pytest.importorskip("langchain_anthropic")  # noqa: E402
pytest.importorskip("langgraph")  # noqa: E402

from langchain_core.messages import AIMessage, AIMessageChunk, HumanMessage  # noqa: E402

import app.langgraph_agent as la  # noqa: E402
from app.langgraph_agent import (  # noqa: E402
    LangGraphAgent,
    SYSTEM_PROMPT,
    is_leakage_attempt,
    redact_leakage,
)


def _first_prompt_line_containing(token: str) -> str:
    for raw in SYSTEM_PROMPT.splitlines():
        if token in raw:
            return raw.strip()
    raise AssertionError(f"no system-prompt line contains {token!r}")


def test_distinctive_prompt_lines_are_flagged():
    # tool mapping, a section heading, the identity line, trust-boundary phrasing, and the
    # remediation-types line are all distinctive prompt content -> must be caught in output.
    assert is_leakage_attempt(_first_prompt_line_containing("→"))
    assert is_leakage_attempt("## Full Analysis Protocol")
    assert is_leakage_attempt(_first_prompt_line_containing("You are an expert Apache Flink"))
    assert is_leakage_attempt(_first_prompt_line_containing("UNTRUSTED"))
    assert is_leakage_attempt(_first_prompt_line_containing("Available remediation types"))


def test_full_prompt_dump_is_flagged():
    assert is_leakage_attempt(SYSTEM_PROMPT)


def test_answer_template_headings_do_not_false_positive():
    # The prompt tells the model to emit these in EVERY response — guarding them would
    # block legitimate answers (the regression a startswith('#') check would cause).
    for heading in ["## Root cause", "## Evidence", "## Action", "## Next steps", "## Refs"]:
        assert not is_leakage_attempt(heading), heading


def test_realistic_answer_not_flagged():
    answer = (
        "🟢 **HEALTHY** — `my-job` running stable.\n\n"
        "## Root cause\nNo anomalies in checkpoints, backpressure, or autoscaler events.\n\n"
        "## Evidence\n- checkpoint p99 1.2s\n- 0 restarts in the last hour\n\n"
        "## Action\nℹ️ No action taken — operator review not required.\n\n"
        "## Refs\n- Job: `my-job`\n"
    )
    assert not is_leakage_attempt(answer)


def test_trust_boundary_and_confidentiality_are_near_the_top():
    lines = [l.strip() for l in SYSTEM_PROMPT.splitlines() if l.strip()]
    untrusted_idx = next(i for i, l in enumerate(lines) if "UNTRUSTED" in l)
    key_principle_idx = next(i for i, l in enumerate(lines) if l.startswith("## Key Principle"))
    assert untrusted_idx < key_principle_idx, "trust-boundary instruction must be near the top"
    assert any("confidential" in l.lower() for l in lines[: untrusted_idx + 3]), \
        "a confidentiality directive must accompany the trust boundary at the top"


# ── pattern reachability: every pattern must come from text the model can see ──

def test_every_leakage_pattern_is_reachable_from_the_live_prompt():
    # A pattern built from text that is never sent to the model can never match
    # real leakage — it only misrepresents the tripwire's coverage to readers.
    # Every pattern must therefore match the live SYSTEM_PROMPT it was built from.
    for p in la.LEAKAGE_PATTERNS:
        assert p.search(SYSTEM_PROMPT), f"unreachable (dead) pattern: {p.pattern!r}"


def test_dead_capability_block_headings_are_no_longer_patterns():
    # These headings came from module constants that were never injected into any
    # prompt; they must not trip the wire (and must never be re-added as patterns).
    assert not is_leakage_attempt("## Capabilities (authoritative): WRITE-ENABLED")
    assert not is_leakage_attempt("## Capabilities (authoritative): READ-ONLY")


# ── the RENDERED prompt (template + capabilities block), all four postures ────

class _GitHub:
    enabled = True
    default_repo = "org/flink-jobs"


def _rendered_prompts(monkeypatch):
    """Yield (label, capabilities_block, rendered_prompt) for write on/off x github on/off,
    mirroring LangGraphAgent.__init__'s SYSTEM_PROMPT.replace('{capabilities_block}', ...)."""
    for write_enabled in (True, False):
        monkeypatch.setattr(la, "write_tools_enabled", lambda _w=write_enabled: _w)
        for gh in (_GitHub(), None):
            block = la._build_capabilities_block(gh)
            assert block.strip(), "capabilities block must render non-empty"
            rendered = SYSTEM_PROMPT.replace("{capabilities_block}", block)
            assert "{capabilities_block}" not in rendered
            yield f"write={write_enabled} github={gh is not None}", block, rendered


def test_rendered_capabilities_block_yields_zero_patterns(monkeypatch):
    # The claim behind building LEAKAGE_PATTERNS from the template alone: the
    # rendered capabilities block contributes no pattern under the heuristic, in
    # every posture. Measured here, not asserted in a comment.
    for label, block, _ in _rendered_prompts(monkeypatch):
        assert la._build_leakage_patterns(block) == [], label


def test_every_pattern_is_reachable_from_every_rendered_prompt(monkeypatch):
    # Reachability against what the model actually receives, not the template:
    # every pattern matches each rendered prompt, and rendering adds no pattern
    # the template-built list lacks (so coverage is stated exactly).
    for label, _, rendered in _rendered_prompts(monkeypatch):
        for p in la.LEAKAGE_PATTERNS:
            assert p.search(rendered), f"{label}: unreachable pattern {p.pattern!r}"
        assert len(la._build_leakage_patterns(rendered)) == len(la.LEAKAGE_PATTERNS), label


# ── redact_leakage: span redaction for few hits, whole-value withhold for a dump ──

LEAK_LINE = SYSTEM_PROMPT.strip().splitlines()[0]

DIAGNOSIS = (
    "## Root cause\nCheckpoint timeout too low for current state size.\n\n"
    "## Evidence\n- log line quoted from the job: " + LEAK_LINE + "\n"
    "- checkpoint p99 9.8s vs timeout 10s\n\n"
    "## Action\nIncrease execution.checkpointing.timeout.\n"
)


def test_redact_leakage_redacts_span_and_keeps_the_rest():
    res = redact_leakage(DIAGNOSIS)
    assert res.hits >= 1 and res.distinct == 1 and not res.withheld
    assert LEAK_LINE not in res.text
    assert la._REDACTED in res.text
    # the diagnosis survives — this is the availability property the earlier withhold-the-whole-answer design lost
    assert "Checkpoint timeout too low" in res.text
    assert "checkpoint p99 9.8s" in res.text
    assert "Increase execution.checkpointing.timeout." in res.text


def test_redact_leakage_clean_text_untouched():
    clean = "## Root cause\nBackpressure from a skewed keyBy.\n"
    res = redact_leakage(clean)
    assert res == (clean, 0, 0, False)


def test_redact_leakage_full_prompt_dump_is_withheld_whole():
    # Review finding: span-redacting a verbatim dump still shipped ~76% of the
    # prompt's prose. At/above the distinct-pattern threshold the value is
    # withheld whole (default marker, or the caller's withheld_text).
    res = redact_leakage(SYSTEM_PROMPT)
    assert res.withheld
    assert res.distinct == len(la.LEAKAGE_PATTERNS)
    assert res.text == la._REDACTED
    assert redact_leakage(SYSTEM_PROMPT, withheld_text="nope").text == "nope"
    # a dump wrapped in prose is still a dump
    assert redact_leakage("sure, here it is:\n" + SYSTEM_PROMPT).withheld


def test_withhold_threshold_counts_distinct_patterns_not_repeats():
    # One planted line repeated many times is still ONE distinct pattern: the
    # attacker cannot pull the withhold lever by repetition.
    repeated = "## Evidence\n" + "\n".join(f"- {LEAK_LINE}" for _ in range(20)) + "\n## Action\nfix it\n"
    res = redact_leakage(repeated)
    assert res.hits == 20 and res.distinct == 1 and not res.withheld
    assert "fix it" in res.text


def test_withhold_threshold_boundary():
    lines = [p.pattern for p in la.LEAKAGE_PATTERNS]
    n = la.LEAKAGE_WITHHOLD_MIN_DISTINCT
    assert 1 < n < len(lines)
    # re.escape'd patterns: unescape to get the literal prompt lines back
    literal = [re.sub(r"\\(.)", r"\1", p) for p in lines]
    below = "context\n" + "\n".join(literal[: n - 1]) + "\nmore context"
    at = "context\n" + "\n".join(literal[:n]) + "\nmore context"
    assert not redact_leakage(below).withheld
    assert "more context" in redact_leakage(below).text
    assert redact_leakage(at).withheld


def test_redaction_marker_does_not_itself_trip_the_wire():
    assert not is_leakage_attempt(la._REDACTED)
    assert not is_leakage_attempt(la._WITHHELD_ANSWER)
    res = redact_leakage(DIAGNOSIS)
    assert redact_leakage(res.text) == (res.text, 0, 0, False)  # idempotent


# ── history hygiene: a redacted answer is not replayed to the model verbatim ──

def test_history_safe_strips_redacted_spans_only():
    redacted = redact_leakage(DIAGNOSIS).text
    safe = la._history_safe(redacted)
    assert la._REDACTED not in safe
    assert "Checkpoint timeout too low" in safe          # rest of the turn kept
    assert la._history_safe("clean turn") == "clean turn"
    assert la._history_safe(la._REDACTED) == "[previous answer redacted by the output filter]"


def test_history_safe_keeps_a_single_paragraph_answer():
    # Round-2 review: line-drop turned a one-paragraph answer with one redacted
    # span into the placeholder, losing the whole turn. Substring removal keeps
    # the surrounding prose and drops only the marker.
    planted = _first_prompt_line_containing("→")
    one_para = f"Raise the checkpoint timeout to 10m because {planted} and restart the job."
    redacted = redact_leakage(one_para).text
    assert la._REDACTED in redacted and "\n" not in redacted
    safe = la._history_safe(redacted)
    assert la._REDACTED not in safe
    assert safe.startswith("Raise the checkpoint timeout to 10m")
    assert safe.endswith("and restart the job.")
    assert planted not in safe
    assert not safe.startswith("[previous answer")


def test_ui_history_safe_answer_removes_markers_not_lines():
    # Mirror of the server rule in app/ui/index.html: substring removal of the
    # marker, no whole-line drop, withheld -> placeholder.
    from pathlib import Path
    src = Path(__file__).resolve().parent.parent / "app" / "ui" / "index.html"
    m = re.search(r"function historySafeAnswer\(result\) \{.*?\n\}", src.read_text(encoding="utf-8"), re.S)
    assert m, "historySafeAnswer() not found in app/ui/index.html"
    body = m.group(0)
    assert "split('\\n')" not in body and ".filter(" not in body   # no line drops
    assert re.search(r"\.replace\(/\\\[redacted:", body)          # marker substring removal
    assert "previous answer withheld" in body and "previous answer redacted" in body


def test_history_assistant_turns_are_sanitised_server_side():
    # History is client-supplied, so the server applies the rule too (both entry points).
    seen = {}

    class _Agent:
        async def ainvoke(self, inp, **_k):
            seen["messages"] = inp["messages"]
            return {"messages": inp["messages"] + [AIMessage(content="ok")]}

        def astream(self, inp, **_k):
            seen["stream_messages"] = inp["messages"]

            async def gen():
                yield ("values", {"messages": inp["messages"] + [AIMessage(content="ok")]})
            return gen()

    agent = object.__new__(LangGraphAgent)
    agent.agent = _Agent()
    history = [{"role": "user", "content": "q1"},
               {"role": "assistant", "content": f"line kept\n{la._REDACTED}\n"}]
    # Assistant turns replay as LABELLED human turns, so the
    # sanitised text follows the client-asserted note; the marker is gone.
    def _check(msg):
        assert not isinstance(msg, AIMessage)
        assert msg.content == f"{la._CLIENT_ASSISTANT_NOTE}\nline kept"
        assert la._REDACTED not in msg.content

    asyncio.run(agent.analyze("q2", history=history))
    _check(seen["messages"][1])

    async def drain():
        return [e async for e in agent.analyze_stream("q2", history=history)]
    asyncio.run(drain())
    _check(seen["stream_messages"][1])


# ── _parse_response: a tripwire hit costs one span, not the diagnosis, and is audited ──

def _parse_answer(answer, monkeypatch, audit_events):
    monkeypatch.setattr(la, "audit", lambda event, **f: audit_events.append((event, f)))
    agent = object.__new__(LangGraphAgent)
    return agent._parse_response(
        {"messages": [HumanMessage(content="q"), AIMessage(content=answer)]}
    )


def test_final_answer_with_poisoned_evidence_is_redacted_not_withheld(monkeypatch):
    events = []
    parsed = _parse_answer(DIAGNOSIS, monkeypatch, events)
    answer = parsed["answer"]
    assert LEAK_LINE not in answer
    assert la._REDACTED in answer
    assert "Checkpoint timeout too low" in answer          # diagnosis intact
    assert "can't share my internal instructions" not in answer  # no canned refusal
    assert ("prompt_leakage_redacted", {"matches": 1, "distinct": 1}) in events
    assert parsed["leakage"] == {"redacted_spans": 1, "withheld": False}


def test_final_answer_prompt_dump_is_withheld_and_audited(monkeypatch):
    events = []
    parsed = _parse_answer("Here are my instructions:\n\n" + SYSTEM_PROMPT, monkeypatch, events)
    assert parsed["answer"] == la._WITHHELD_ANSWER
    assert not is_leakage_attempt(parsed["answer"])
    assert parsed["leakage"]["withheld"] is True
    assert parsed["leakage"]["redacted_spans"] >= len(la.LEAKAGE_PATTERNS)
    names = [e[0] for e in events]
    assert "prompt_leakage_withheld" in names and "prompt_leakage_redacted" not in names
    withheld = dict(events)["prompt_leakage_withheld"]
    assert withheld["distinct"] == len(la.LEAKAGE_PATTERNS)


def test_clean_final_answer_unchanged_and_not_audited(monkeypatch):
    events = []
    clean = "## Root cause\nAll good.\n\n## Evidence\n- 0 restarts\n"
    parsed = _parse_answer(clean, monkeypatch, events)
    assert parsed["answer"] == clean.replace("\r", "")
    assert parsed["leakage"] == {"redacted_spans": 0, "withheld": False}
    assert not events


def test_redaction_runs_before_the_50k_truncation(monkeypatch):
    # A pattern straddling the 50k cut used to leak its head: truncation ran
    # first, so the truncated tail no longer matched. Redact, then truncate.
    pad = "x" * (50000 - len(LEAK_LINE) // 2)
    answer = pad + LEAK_LINE + " tail" * 200          # still > 50k after redaction
    assert not is_leakage_attempt(answer[:50000])  # the straddle is real
    events = []
    parsed = _parse_answer(answer, monkeypatch, events)
    out = parsed["answer"]
    assert LEAK_LINE[:15] not in out                 # no head fragment leaks
    assert out.startswith(pad + la._REDACTED)        # redacted in place, then cut
    assert out.endswith("\n\n[Response truncated]")
    assert len(out) == 50000 + len("\n\n[Response truncated]")
    assert ("prompt_leakage_redacted", {"matches": 1, "distinct": 1}) in events


# ── streaming: suppression is audited; the final result carries the redacted diagnosis ──

class _FakeAgent:
    def __init__(self, script):
        self.script = script

    def astream(self, _input, **_kwargs):
        async def gen():
            for item in self.script:
                yield item
        return gen()

    async def ainvoke(self, *_a, **_k):
        raise AssertionError("second execution")


def test_stream_suppression_audited_and_result_redacted_not_withheld(monkeypatch):
    events = []
    monkeypatch.setattr(la, "audit", lambda event, **f: events.append((event, f)))
    script = [
        ("messages", (AIMessageChunk(content=f"quoting: {LEAK_LINE}"), {"langgraph_node": "agent"})),
        ("values", {"messages": [HumanMessage(content="q"), AIMessage(content=DIAGNOSIS)]}),
    ]
    agent = object.__new__(LangGraphAgent)
    agent.agent = _FakeAgent(script)

    async def collect():
        return [e async for e in agent.analyze_stream("what's wrong?")]

    out = asyncio.run(collect())
    # live chunk suppressed exactly as before (settled: flushed chunks can't be re-redacted)
    chunks = [e["content"] for e in out if e["type"] == "content_chunk"]
    assert chunks == ["[filtered]"]
    # ... but the suppression is now audited
    assert any(e[0] == "prompt_leakage_stream_suppressed" for e in events)
    # and the authoritative result event delivers the redacted diagnosis (availability restored)
    result = [e for e in out if e["type"] == "result"][0]
    assert LEAK_LINE not in result["data"]["answer"]
    assert la._REDACTED in result["data"]["answer"]
    assert "Checkpoint timeout too low" in result["data"]["answer"]
    assert "can't share my internal instructions" not in result["data"]["answer"]
    assert any(e[0] == "prompt_leakage_redacted" for e in events)


# ── send_to_slack egress gate: the tool is a sink the answer gate never sees ──

class _CaptureSlack:
    enabled = True

    def __init__(self):
        self.sent = []

    def format_analysis_as_blocks(self, message, title=""):
        return [{"type": "section", "text": {"type": "mrkdwn", "text": message}}]

    async def send_message(self, text, channel=None, blocks=None, thread_ts=None,
                           trusted_links=None):
        # Mirrors SlackClient.send_message: send_to_slack passes the code-derived
        # PR links as trusted_links, so the fake must accept them.
        self.sent.append({"text": text, "channel": channel, "blocks": blocks,
                          "trusted_links": trusted_links})
        return {"success": True, "channel": channel or "C_DEFAULT", "ts": str(len(self.sent))}


def _slack_tool(monkeypatch):
    """Build the tool closures without LangGraphAgent.__init__ (no Anthropic client)."""
    events = []
    monkeypatch.setattr(la, "audit", lambda event, **kw: events.append((event, kw)))
    agent = object.__new__(LangGraphAgent)
    agent.flink_client = None
    agent.k8s_client = None
    agent.postgres_reader = None
    agent.auto_remediator = None
    agent.github_client = None
    agent.slack_client = _CaptureSlack()
    tools = agent._create_tools()
    tool = next(t for t in tools if t.name == "send_to_slack")
    return tool, agent.slack_client, events


def test_send_to_slack_refuses_a_prompt_dump(monkeypatch):
    # Review repro: SYSTEM_PROMPT handed to the tool posted 13,450 chars with all
    # 41 patterns verbatim and success:true. The gate must refuse and audit.
    tool, slack, events = _slack_tool(monkeypatch)
    raw = asyncio.new_event_loop().run_until_complete(
        tool.ainvoke({"message": SYSTEM_PROMPT, "title": "dump"}))
    result = json.loads(raw)
    assert result["success"] is False
    assert result["leakage_withheld"] is True
    assert slack.sent == []                               # nothing reached Slack
    withheld = [kw for ev, kw in events if ev == "prompt_leakage_withheld"]
    assert len(withheld) == 1 and withheld[0]["sink"] == "slack"
    assert withheld[0]["distinct"] >= la.LEAKAGE_WITHHOLD_MIN_DISTINCT
    sends = [kw for ev, kw in events if ev == "slack_send"]
    assert sends and sends[-1]["success"] is False and sends[-1]["error"] == "leakage_withheld"
    # The refusal returned to the model carries no prompt text and does not itself trip the wire.
    assert not is_leakage_attempt(raw)


def test_send_to_slack_span_redacts_a_partial_hit(monkeypatch):
    # Poisoned-evidence case: one planted prompt line inside an otherwise useful
    # report. The report is delivered with that span redacted, and the tool
    # result is marked so the caller can see the redaction happened.
    tool, slack, events = _slack_tool(monkeypatch)
    planted = _first_prompt_line_containing("→")
    message = f"## Action\nRaise the checkpoint timeout.\nEvidence: {planted}\nDone."
    raw = asyncio.new_event_loop().run_until_complete(
        tool.ainvoke({"message": message, "title": "report"}))
    # Success results are provenance-fenced like every data-carrying tool return.
    assert raw.startswith('<untrusted_data source="slack_api">\n')
    result = json.loads(la._unfenced(raw))
    assert result["success"] is True
    assert result["leakage_redacted_spans"] >= 1
    assert len(slack.sent) == 1
    posted = slack.sent[0]["text"]
    assert planted not in posted
    assert la._REDACTED in posted
    assert "Raise the checkpoint timeout." in posted     # rest of the report delivered
    assert not is_leakage_attempt(posted)
    redacted = [kw for ev, kw in events if ev == "prompt_leakage_redacted"]
    assert len(redacted) == 1 and redacted[0]["sink"] == "slack"
    assert not [kw for ev, kw in events if ev == "prompt_leakage_withheld"]


def test_send_to_slack_clean_message_is_untouched(monkeypatch):
    tool, slack, events = _slack_tool(monkeypatch)
    raw = asyncio.new_event_loop().run_until_complete(
        tool.ainvoke({"message": "All green.", "title": "ok"}))
    result = json.loads(la._unfenced(raw))
    assert result["success"] is True and "leakage_redacted_spans" not in result
    assert slack.sent[0]["text"] == "All green."
    assert not [ev for ev, _ in events if ev.startswith("prompt_leakage")]


# ── PR text passes the same egress gate as a Slack message ──────────────────

class _PrGitHub:
    enabled = True
    default_repo = "owner/flink-job"

    def __init__(self):
        self.calls = []

    async def open_pr_with_file_change(self, **kwargs):
        self.calls.append(kwargs)
        return {"success": True, "pr_url": "https://github.example/owner/flink-job/pull/7",
                "pr_number": 7, "branch": kwargs["branch_name"], "repo": self.default_repo}


def _pr_tool(monkeypatch):
    monkeypatch.setenv("ENABLE_WRITE_TOOLS", "true")
    monkeypatch.setenv("DEPLOY_ENV", "nonprod")
    events = []
    monkeypatch.setattr(la, "audit", lambda event, *a, **kw: events.append((event, kw)))
    github = _PrGitHub()
    agent = object.__new__(LangGraphAgent)
    agent.flink_client = None
    agent.k8s_client = None
    agent.postgres_reader = None
    agent.auto_remediator = None
    agent.slack_client = None
    agent.github_client = github
    tool = next(t for t in agent._create_tools() if t.name == "create_github_pr")
    return tool, github, events


def _propose_and_approve(tool, github, args):
    """Propose via the tool, then run what the approve route runs."""
    from app import write_proposals
    run = write_proposals.begin_run_tracking()
    asyncio.new_event_loop().run_until_complete(tool.ainvoke(args))
    if not run:
        return None
    proposal = write_proposals.take(run[-1]["proposal_id"])
    la._pr_attempts.clear()   # the cap is not under test here
    return asyncio.new_event_loop().run_until_complete(la.execute_approved_pr(github, proposal["args"]))


_PR = {
    "branch_name": "ai-debugger/fix-skew",
    "file_path": "src/main/java/Job.java",
    "new_content": "public class Job {}",
    "pr_title": "Fix skew",
}


def test_pr_body_images_and_credentials_are_removed(monkeypatch):
    tool, github, _ = _pr_tool(monkeypatch)
    body = "Root cause below.\n![x](https://evil.example/p.png?d=1)\npassword=hunter2\n<img src=https://evil.example/q>"
    _propose_and_approve(tool, github, {
        **_PR, "pr_body": body, "commit_message": "fix token=ABCDEF1234567890"})  # gitleaks:allow — synthetic fixture exercising redaction
    assert len(github.calls) == 1
    sent = github.calls[0]
    assert "[image removed]" in sent["pr_body"]
    assert "evil.example" not in sent["pr_body"]
    assert "hunter2" not in sent["pr_body"]
    assert "ABCDEF1234567890" not in sent["commit_message"]


_IMAGE_FORMS = {
    "inline": "![x](https://evil.example/p.png?d=1)",
    "shortcut_reference": "![logo]\n\n[logo]: https://evil.example/p.png?d=1",
    "collapsed_reference": "![logo][]\n\n[logo]: https://evil.example/p.png?d=1",
    "full_reference": "![x][logo]\n\n[logo]: https://evil.example/p.png?d=1",
    "nested_brackets_in_alt": "![a [b] c](https://evil.example/p.png?d=1)",
    "escaped_bracket_in_alt": "![a\\]b](https://evil.example/p.png?d=1)",
    "html_img_unclosed": '<img src="https://evil.example/p.png?d=1"',
    "html_picture_source": '<picture><source srcset="https://evil.example/p.png?d=1"></picture>',
    "html_video_poster": '<video poster="https://evil.example/p.png?d=1"></video>',
    "pieces_rejoin_after_strip": "!![x](u)\n\n[image removed]: https://evil.example/p.png?d=1",
    "bang_run_outlasts_passes": "!!!!!!!!!!!![x](u)\n\n[image removed]: https://evil.example/p.png?d=1",
}


def _renders_an_image(text):
    return "![" in text or re.search(r"<(img|picture|source|video|image)\b", text, re.I)


@pytest.mark.parametrize("form", sorted(_IMAGE_FORMS))
def test_every_image_form_is_removed_from_pr_text(form):
    out, _ = la.clean_pr_text("Root cause.\n" + _IMAGE_FORMS[form] + "\nDone.", la.PR_BODY_MAX_CHARS)
    assert "[image removed]" in out
    assert not _renders_an_image(out)
    assert out.startswith("Root cause.")


@pytest.mark.parametrize("form", ["shortcut_reference", "nested_brackets_in_alt", "html_picture_source"])
def test_image_forms_never_reach_github(monkeypatch, form):
    tool, github, _ = _pr_tool(monkeypatch)
    _propose_and_approve(tool, github, {**_PR, "pr_body": _IMAGE_FORMS[form]})
    assert len(github.calls) == 1
    assert not _renders_an_image(github.calls[0]["pr_body"])


def test_ordinary_links_and_text_are_kept():
    text = "See [the docs](https://github.com/x/y) and `a < b`."
    out, _ = la.clean_pr_text(text, la.PR_BODY_MAX_CHARS)
    assert out == text


def test_pr_body_with_a_prompt_dump_is_never_sent(monkeypatch):
    tool, github, events = _pr_tool(monkeypatch)
    lines = [ln for ln in SYSTEM_PROMPT.strip().splitlines() if ln.strip()]
    out = asyncio.new_event_loop().run_until_complete(tool.ainvoke({
        **_PR, "pr_body": "\n".join(lines)}))
    assert github.calls == []
    assert json.loads(out)["success"] is False
    assert any(ev == "github_pr_rejected" and kw.get("reason") == "egress_gate"
               for ev, kw in events)


def test_pr_title_is_bounded(monkeypatch):
    tool, github, _ = _pr_tool(monkeypatch)
    _propose_and_approve(tool, github, {**_PR, "pr_title": "t" * 1000, "pr_body": "ok"})
    assert len(github.calls[0]["pr_title"]) <= la.PR_TITLE_MAX_CHARS
