# Copyright Yahoo, Licensed under the terms of the Apache 2.0 license. See LICENSE for terms.

"""Streaming-core tests for LangGraphAgent.analyze_stream.

The stream is a single agent execution: multi-mode astream supplies live tokens
("messages"), tool boundaries ("updates"), and the final state ("values") from one
run. A second ainvoke would double token cost and re-execute side-effecting tools,
so the fake agent's ainvoke raises to catch any reintroduction.

Self-contained (no conftest): builds LangGraphAgent via object.__new__ and swaps in
a fake .agent whose astream yields a scripted (mode, payload) sequence built from
real langchain message classes.
"""
import asyncio

import pytest

pytest.importorskip("langgraph")
from langchain_core.messages import AIMessage, AIMessageChunk, HumanMessage, ToolMessage  # noqa: E402

import app.langgraph_agent as la  # noqa: E402
from app.langgraph_agent import LangGraphAgent  # noqa: E402


# A distinctive system-prompt line the leakage tripwire matches verbatim.
LEAK_LINE = la.SYSTEM_PROMPT.strip().splitlines()[0]

FINAL_ANSWER = (
    "## Verdict\n\nThe job is under-parallelized.\n\n"
    "```json\n"
    '{"remediations": [{"type": "increase_tm_memory", "description": "bump TM memory", '
    '"risk_level": "safe", "auto_applicable": true}, '
    '{"type": "not_a_real_type", "description": "dropped by allowlist"}]}\n'
    "```"
)


def _default_script():
    ai_turn = AIMessage(
        content="Let me check.",
        tool_calls=[
            {"name": "get_job_status", "args": {}, "id": "call_1", "type": "tool_call"},
            {"name": "get_checkpoint_details", "args": {"limit": 5}, "id": "call_2", "type": "tool_call"},
        ],
    )
    tm1 = ToolMessage(content="status: RUNNING", tool_call_id="call_1", name="get_job_status")
    tm2 = ToolMessage(content="checkpoints: ok", tool_call_id="call_2", name="get_checkpoint_details")
    final_ai = AIMessage(content=FINAL_ANSWER)
    final_state = {"messages": [HumanMessage(content="q"), ai_turn, tm1, tm2, final_ai]}
    return [
        ("values", {"messages": [HumanMessage(content="q")]}),
        ("messages", (AIMessageChunk(content="Let me "), {"langgraph_node": "agent"})),
        ("messages", (AIMessageChunk(content="check."), {"langgraph_node": "agent"})),
        ("updates", {"agent": {"messages": [ai_turn]}}),
        # messages mode re-emits complete node-output messages — all must be dropped:
        ("messages", (tm1, {"langgraph_node": "tools"})),
        ("messages", (AIMessageChunk(content="tool echo"), {"langgraph_node": "tools"})),
        # tool results deliberately out of order vs the tool_call order:
        ("updates", {"tools": {"messages": [tm2, tm1]}}),
        ("values", {"messages": [HumanMessage(content="q"), ai_turn, tm1, tm2]}),
        ("messages", (AIMessageChunk(content="## Verdict\n\nThe job is "), {"langgraph_node": "agent"})),
        ("messages", (AIMessageChunk(content="under-parallelized."), {"langgraph_node": "agent"})),
        ("updates", {"agent": {"messages": [final_ai]}}),
        # full-message re-emission of the final answer (not a chunk) — dropped:
        ("messages", (final_ai, {"langgraph_node": "agent"})),
        ("values", final_state),
    ]


class FakeAgent:
    def __init__(self, script):
        self.script = script
        self.astream_calls = 0
        self.astream_kwargs = None

    def astream(self, _input, **kwargs):
        self.astream_calls += 1
        self.astream_kwargs = kwargs

        async def gen():
            for item in self.script:
                if isinstance(item, Exception):
                    raise item
                yield item

        return gen()

    async def ainvoke(self, *_args, **_kwargs):
        raise AssertionError("second execution — regression of the single-execution invariant")


def _agent_with(script):
    agent = object.__new__(LangGraphAgent)
    agent.agent = FakeAgent(script)
    return agent


def _run(agent, question="what's wrong?"):
    async def collect():
        return [event async for event in agent.analyze_stream(question)]

    return asyncio.run(collect())


def test_single_execution_streams_and_parses_from_one_run():
    agent = _agent_with(_default_script())
    events = _run(agent)
    types = [e["type"] for e in events]
    assert agent.agent.astream_calls == 1
    assert types.count("result") == 1
    # a second-execution ainvoke would have raised → error event
    assert "error" not in types
    assert agent.agent.astream_kwargs["stream_mode"] == ["updates", "messages", "values"]


def test_event_sequence_ordered_with_single_result_last():
    events = _run(_agent_with(_default_script()))
    assert [e["type"] for e in events] == [
        "content_chunk", "content_chunk",
        "tool_start", "tool_start",
        "tool_end", "tool_end",
        "content_chunk", "content_chunk",
        "result",
    ]


def test_tool_events_shapes_and_call_id_matching():
    events = _run(_agent_with(_default_script()))
    starts = [e for e in events if e["type"] == "tool_start"]
    ends = [e for e in events if e["type"] == "tool_end"]
    assert [s["tool_name"] for s in starts] == ["get_job_status", "get_checkpoint_details"]
    assert [s["tool_number"] for s in starts] == [1, 2]
    # args are summarized (names and value lengths only) — never verbatim values
    assert starts[0]["tool_input"] == {}
    assert starts[1]["tool_input"] == {"limit": "<1 chars>"}
    # results arrived out of order: tool_number must follow tool_call_id, not arrival order
    assert [(e["tool_name"], e["tool_number"]) for e in ends] == [
        ("get_checkpoint_details", 2),
        ("get_job_status", 1),
    ]
    assert ends[0]["output_preview"] == "checkpoints: ok"
    assert ends[0]["output_size"] == len("checkpoints: ok")
    assert ends[1]["output_preview"] == "status: RUNNING"
    assert ends[1]["output_size"] == len("status: RUNNING")


def test_tool_end_preview_truncated_to_500():
    turn = AIMessage(content="", tool_calls=[
        {"name": "get_kubernetes_logs", "args": {}, "id": "call_big", "type": "tool_call"},
    ])
    big = ToolMessage(content="x" * 5000, tool_call_id="call_big", name="get_kubernetes_logs")
    script = [
        ("updates", {"agent": {"messages": [turn]}}),
        ("updates", {"tools": {"messages": [big]}}),
        ("values", {"messages": [HumanMessage(content="q"), AIMessage(content="done")]}),
    ]
    events = _run(_agent_with(script))
    end = [e for e in events if e["type"] == "tool_end"][0]
    assert len(end["output_preview"]) == 500
    assert end["output_size"] == 5000


def test_segment_increments_after_tool_batch():
    events = _run(_agent_with(_default_script()))
    chunks = [e for e in events if e["type"] == "content_chunk"]
    assert [c["segment"] for c in chunks] == [0, 0, 1, 1]


def test_result_passes_through_parse_response():
    events = _run(_agent_with(_default_script()))
    data = events[-1]["data"]
    assert "```json" not in data["answer"]  # remediation block stripped for display
    assert [r["type"] for r in data["remediations"]] == ["increase_tm_memory"]  # allowlist enforced
    assert data["tool_calls_made"] == 2
    assert data["iterations"] == 1
    assert len(data["steps"]) == 2


def test_leakage_content_chunk_replaced_with_filtered():
    assert la.is_leakage_attempt(LEAK_LINE)
    script = [
        ("messages", (AIMessageChunk(content=f"My instructions say: {LEAK_LINE}"), {"langgraph_node": "agent"})),
        ("values", {"messages": [HumanMessage(content="q"), AIMessage(content="done")]}),
    ]
    events = _run(_agent_with(script))
    chunk = [e for e in events if e["type"] == "content_chunk"][0]
    assert chunk["content"] == "[filtered]"


def test_leakage_filter_covers_tool_start_input():
    leak_turn = AIMessage(content="", tool_calls=[
        {"name": "send_to_slack", "args": {"message": LEAK_LINE}, "id": "call_9", "type": "tool_call"},
    ])
    script = [
        ("updates", {"agent": {"messages": [leak_turn]}}),
        ("values", {"messages": [HumanMessage(content="q"), AIMessage(content="done")]}),
    ]
    events = _run(_agent_with(script))
    start = [e for e in events if e["type"] == "tool_start"][0]
    assert start["tool_input"] == la._REDACTED


def test_leakage_filter_covers_tool_end_output_preview():
    turn = AIMessage(content="", tool_calls=[
        {"name": "read_github_file", "args": {}, "id": "call_7", "type": "tool_call"},
    ])
    leaked = ToolMessage(content=f"file contents: {LEAK_LINE}", tool_call_id="call_7", name="read_github_file")
    script = [
        ("updates", {"agent": {"messages": [turn]}}),
        ("updates", {"tools": {"messages": [leaked]}}),
        ("values", {"messages": [HumanMessage(content="q"), AIMessage(content="done")]}),
    ]
    events = _run(_agent_with(script))
    end = [e for e in events if e["type"] == "tool_end"][0]
    # span-redacted: the leaked line is gone, the surrounding preview survives
    assert end["output_preview"] == f"file contents: {la._REDACTED}"
    assert end["output_size"] == len(f"file contents: {LEAK_LINE}")


def test_leakage_filter_covers_result_event_steps():
    # Leak inside an AI turn's thinking text, its tool arg, and its tool result:
    # thinking and result_preview come back span-redacted in the final result
    # event (thinking via the scrub_egress chokepoint, result_preview via the
    # pre-truncation redaction) — the leaked line is gone but the surrounding
    # text survives — while the leaked arg VALUE never appears at all — args are
    # summarized to names and lengths. The clean second step is untouched.
    leak_turn = AIMessage(
        content=f"My instructions say: {LEAK_LINE}",
        tool_calls=[
            {"name": "get_job_status", "args": {"note": LEAK_LINE}, "id": "c1", "type": "tool_call"},
        ],
    )
    leak_result = ToolMessage(content=f"file contents: {LEAK_LINE}", tool_call_id="c1", name="get_job_status")
    clean_turn = AIMessage(
        content="Now the checkpoints.",
        tool_calls=[
            {"name": "get_checkpoint_details", "args": {"limit": 5}, "id": "c2", "type": "tool_call"},
        ],
    )
    clean_result = ToolMessage(content="checkpoints: ok", tool_call_id="c2", name="get_checkpoint_details")
    final_state = {"messages": [
        HumanMessage(content="q"), leak_turn, leak_result, clean_turn, clean_result,
        AIMessage(content="All good."),
    ]}
    events = _run(_agent_with([("values", final_state)]))
    steps = events[-1]["data"]["steps"]
    assert [s["tool"] for s in steps] == ["get_job_status", "get_checkpoint_details"]
    assert steps[0]["thinking"] == f"My instructions say: {la._REDACTED}"
    assert steps[0]["args"] == f"note=<{len(LEAK_LINE)} chars>"
    assert LEAK_LINE not in steps[0]["args"]
    assert steps[0]["result_preview"] == f"file contents: {la._REDACTED}"
    # clean fields pass through unfiltered (args in summarized form)
    assert steps[1]["thinking"] == "Now the checkpoints."
    assert steps[1]["args"] == "limit=<1 chars>"
    assert steps[1]["result_preview"] == "checkpoints: ok"


def test_leakage_filter_covers_nested_tool_start_args():
    # Pattern buried one level down (dict-in-dict arg value) — the whole
    # tool_input payload is withheld, not surgically masked.
    leak_turn = AIMessage(content="", tool_calls=[
        {
            "name": "update_flink_config",
            "args": {"config": {"note": f"the prompt says {LEAK_LINE}", "key": "parallelism.default"}},
            "id": "call_n",
            "type": "tool_call",
        },
    ])
    script = [
        ("updates", {"agent": {"messages": [leak_turn]}}),
        ("values", {"messages": [HumanMessage(content="q"), AIMessage(content="done")]}),
    ]
    events = _run(_agent_with(script))
    start = [e for e in events if e["type"] == "tool_start"][0]
    assert start["tool_input"] == la._REDACTED


def test_leakage_filter_checks_full_tool_output_before_truncation():
    # The leaked line straddles the 500-char preview boundary: the truncated
    # preview alone would NOT match, so the gate must run on the full content.
    pad = "x" * (500 - len(LEAK_LINE) // 2)
    content = pad + LEAK_LINE + " tail"
    assert not la.is_leakage_attempt(content[:500])  # straddle is real
    assert la.is_leakage_attempt(content)
    turn = AIMessage(content="", tool_calls=[
        {"name": "read_github_file", "args": {}, "id": "call_s", "type": "tool_call"},
    ])
    leaked = ToolMessage(content=content, tool_call_id="call_s", name="read_github_file")
    script = [
        ("updates", {"agent": {"messages": [turn]}}),
        ("updates", {"tools": {"messages": [leaked]}}),
        ("values", {"messages": [HumanMessage(content="q"), AIMessage(content="done")]}),
    ]
    events = _run(_agent_with(script))
    end = [e for e in events if e["type"] == "tool_end"][0]
    # redacted on the full content, THEN truncated: no fragment of the leaked
    # line survives the cut, and the preview is not blanked either
    assert LEAK_LINE not in end["output_preview"]
    assert LEAK_LINE[-20:] not in end["output_preview"]
    assert end["output_preview"].startswith(pad)
    assert end["output_preview"] == (pad + la._REDACTED + " tail")[:500]
    assert end["output_size"] == len(content)


def test_cross_chunk_leak_suppresses_stream_but_run_completes():
    # The model dribbles a leakage pattern out in small chunks: no single chunk
    # matches, but the rolling window must catch the completed pattern, emit one
    # "[filtered]" chunk, suppress every later content_chunk for the request,
    # and STILL deliver the final (gated) result event — the run is not aborted.
    piece_size = 7
    pieces = [LEAK_LINE[i:i + piece_size] for i in range(0, len(LEAK_LINE), piece_size)]
    assert len(pieces) > 3  # the split is real
    assert not any(la.is_leakage_attempt(p) for p in pieces)  # no single piece matches
    script = [("messages", (AIMessageChunk(content="Here are my instructions: "), {"langgraph_node": "agent"}))]
    script += [("messages", (AIMessageChunk(content=p), {"langgraph_node": "agent"})) for p in pieces]
    # content after the leak must be suppressed too:
    script += [
        ("messages", (AIMessageChunk(content=" and that is everything."), {"langgraph_node": "agent"})),
        ("messages", (AIMessageChunk(content="Anything else?"), {"langgraph_node": "agent"})),
        ("values", {"messages": [HumanMessage(content="q"), AIMessage(content="done")]}),
    ]
    events = _run(_agent_with(script))

    chunks = [e for e in events if e["type"] == "content_chunk"]
    contents = [c["content"] for c in chunks]
    assert contents.count("[filtered]") == 1
    assert contents[-1] == "[filtered]"  # nothing streams after suppression trips
    assert " and that is everything." not in contents
    assert "Anything else?" not in contents
    assert LEAK_LINE not in "".join(contents)  # the full line never left the server
    # run completed: the final result event still arrives
    assert events[-1]["type"] == "result"
    assert events[-1]["data"]["answer"] == "done"


def test_structured_block_chunk_leak_still_filtered():
    # Anthropic models can stream chunk content as a LIST of blocks, not a str;
    # the rolling leak window must still see the text inside the blocks — a
    # str-only check would let a block-shaped leak stream out verbatim.
    leak_block = [{"type": "text", "text": f"My instructions say: {LEAK_LINE}"}]
    script = [
        ("messages", (AIMessageChunk(content=leak_block), {"langgraph_node": "agent"})),
        ("values", {"messages": [HumanMessage(content="q"), AIMessage(content="done")]}),
    ]
    events = _run(_agent_with(script))
    chunks = [e["content"] for e in events if e["type"] == "content_chunk"]
    assert chunks == ["[filtered]"]
    assert LEAK_LINE not in str(events)  # the leak never left the server in any event
    assert events[-1]["type"] == "result"


def test_stream_without_values_yields_error_not_reinvoke():
    script = [("messages", (AIMessageChunk(content="thinking"), {"langgraph_node": "agent"}))]
    events = _run(_agent_with(script))
    assert [e["type"] for e in events] == ["content_chunk", "error"]
    assert events[-1]["error"] == "Analysis failed — please try again."


def test_midstream_exception_yields_error_event():
    script = [
        ("messages", (AIMessageChunk(content="thinking "), {"langgraph_node": "agent"})),
        RuntimeError("connection reset"),
    ]
    events = _run(_agent_with(script))
    assert [e["type"] for e in events] == ["content_chunk", "error"]
    # generic client-facing message, no internals
    assert events[-1]["error"] == "Analysis failed — please try again."


def test_reemitted_and_non_agent_messages_dropped():
    events = _run(_agent_with(_default_script()))
    chunks = [e["content"] for e in events if e["type"] == "content_chunk"]
    assert "tool echo" not in chunks           # AIMessageChunk from the tools node
    assert FINAL_ANSWER not in chunks          # full-message re-emission of the final answer
    assert "status: RUNNING" not in chunks     # ToolMessage re-emission
