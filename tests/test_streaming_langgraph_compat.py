# Copyright Yahoo, Licensed under the terms of the Apache 2.0 license. See LICENSE for terms.

"""Real-langgraph shape tripwire for the multi-mode astream contract.

analyze_stream consumes astream(stream_mode=["updates", "messages", "values"]) from
the installed langgraph. The exact payload shapes of "updates" and "values" are not
part of any typed API surface, so this module runs a real create_react_agent with a
scripted tool-calling fake model and asserts every shape the streaming core relies
on — a future langgraph bump that changes any of them fails here, not in production.

Self-contained (no conftest); requires the real langgraph/langchain-core install.
"""
import asyncio
import json

import pytest

pytest.importorskip("langgraph")

from langchain_core.language_models.chat_models import BaseChatModel  # noqa: E402
from langchain_core.messages import (  # noqa: E402
    AIMessage,
    AIMessageChunk,
    BaseMessage,
    HumanMessage,
    ToolMessage,
)
from langchain_core.outputs import ChatGeneration, ChatGenerationChunk, ChatResult  # noqa: E402
from langchain_core.tools import tool  # noqa: E402
from langgraph.prebuilt import create_react_agent  # noqa: E402

from app.langgraph_agent import LangGraphAgent  # noqa: E402

FINAL_ANSWER = "The echo tool returned successfully. All good."


@tool
def echo_tool(text: str) -> str:
    """Echo the input text back."""
    return f"echo: {text}"


class ScriptedToolCallModel(BaseChatModel):
    """First turn emits a tool call; the turn after a ToolMessage emits the final answer."""

    @property
    def _llm_type(self) -> str:
        return "scripted-tool-call"

    def bind_tools(self, tools, **kwargs):
        return self

    def _turn_message(self, messages) -> AIMessage:
        if any(isinstance(m, ToolMessage) for m in messages):
            return AIMessage(content=FINAL_ANSWER)
        return AIMessage(
            content="Checking with the echo tool.",
            tool_calls=[
                {"name": "echo_tool", "args": {"text": "hi"}, "id": "call_compat_1", "type": "tool_call"}
            ],
        )

    def _generate(self, messages, stop=None, run_manager=None, **kwargs) -> ChatResult:
        return ChatResult(generations=[ChatGeneration(message=self._turn_message(messages))])

    def _stream(self, messages, stop=None, run_manager=None, **kwargs):
        message = self._turn_message(messages)
        mid = len(message.content) // 2
        for part in (message.content[:mid], message.content[mid:]):
            chunk = ChatGenerationChunk(message=AIMessageChunk(content=part))
            if run_manager:
                run_manager.on_llm_new_token(part, chunk=chunk)
            yield chunk
        if message.tool_calls:
            chunk = ChatGenerationChunk(
                message=AIMessageChunk(
                    content="",
                    tool_call_chunks=[
                        {
                            "name": tc["name"],
                            "args": json.dumps(tc["args"]),
                            "id": tc["id"],
                            "index": 0,
                            "type": "tool_call_chunk",
                        }
                        for tc in message.tool_calls
                    ],
                )
            )
            if run_manager:
                run_manager.on_llm_new_token("", chunk=chunk)
            yield chunk


@pytest.fixture(scope="module")
def stream_items():
    agent = create_react_agent(ScriptedToolCallModel(), [echo_tool])

    async def run():
        items = []
        async for item in agent.astream(
            {"messages": [HumanMessage(content="please echo")]},
            stream_mode=["updates", "messages", "values"],
        ):
            items.append(item)
        return items

    return asyncio.run(run())


def test_astream_yields_mode_payload_two_tuples(stream_items):
    assert stream_items
    for item in stream_items:
        assert isinstance(item, tuple) and len(item) == 2
        assert item[0] in {"updates", "messages", "values"}


def test_messages_payload_is_message_and_metadata_with_langgraph_node(stream_items):
    msg_items = [p for m, p in stream_items if m == "messages"]
    assert msg_items
    for payload in msg_items:
        assert isinstance(payload, tuple) and len(payload) == 2
        message, metadata = payload
        assert isinstance(message, BaseMessage)
        assert isinstance(metadata, dict)
        assert "langgraph_node" in metadata
    # live tokens: at least one AIMessageChunk attributed to the agent node
    assert any(
        isinstance(m, AIMessageChunk) and meta.get("langgraph_node") == "agent"
        for m, meta in msg_items
    )


def test_updates_keys_are_agent_and_tools_with_message_lists(stream_items):
    updates = [p for m, p in stream_items if m == "updates"]
    assert updates
    keys = set()
    for payload in updates:
        assert isinstance(payload, dict)
        keys.update(payload.keys())
    assert keys == {"agent", "tools"}

    agent_updates = [p["agent"] for p in updates if "agent" in p]
    tool_call_msgs = [
        msg for u in agent_updates for msg in u["messages"] if getattr(msg, "tool_calls", None)
    ]
    assert tool_call_msgs
    tc = tool_call_msgs[0].tool_calls[0]
    assert tc["name"] == "echo_tool"
    assert tc["args"] == {"text": "hi"}
    assert tc["id"]

    tools_updates = [p["tools"] for p in updates if "tools" in p]
    tool_msgs = [msg for u in tools_updates for msg in u["messages"]]
    assert tool_msgs
    assert all(isinstance(m, ToolMessage) for m in tool_msgs)
    assert tool_msgs[0].tool_call_id == tc["id"]


def test_final_values_is_full_state_ending_with_final_aimessage(stream_items):
    values = [p for m, p in stream_items if m == "values"]
    assert values
    final = values[-1]
    assert isinstance(final, dict) and "messages" in final
    last = final["messages"][-1]
    assert isinstance(last, AIMessage) and not isinstance(last, AIMessageChunk)
    assert last.content == FINAL_ANSWER
    assert any(isinstance(m, ToolMessage) for m in final["messages"])


def test_analyze_stream_end_to_end_over_real_langgraph():
    agent = object.__new__(LangGraphAgent)
    agent.agent = create_react_agent(ScriptedToolCallModel(), [echo_tool])

    async def collect():
        return [e async for e in agent.analyze_stream("please echo")]

    events = asyncio.run(collect())
    types = [e["type"] for e in events]
    assert types.count("result") == 1 and types[-1] == "result"
    assert "error" not in types

    starts = [e for e in events if e["type"] == "tool_start"]
    ends = [e for e in events if e["type"] == "tool_end"]
    assert [s["tool_name"] for s in starts] == ["echo_tool"]
    assert [(e["tool_name"], e["tool_number"]) for e in ends] == [("echo_tool", 1)]
    assert ends[0]["output_preview"] == "echo: hi"

    data = events[-1]["data"]
    assert data["answer"] == FINAL_ANSWER
    assert data["tool_calls_made"] == 1

    chunks = [e for e in events if e["type"] == "content_chunk"]
    assert chunks
    # the final answer streamed live in the post-tool segment, exactly once
    assert "".join(c["content"] for c in chunks if c["segment"] == 1) == FINAL_ANSWER
