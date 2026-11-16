# Copyright Yahoo, Licensed under the terms of the Apache 2.0 license. See LICENSE for terms.

"""Source-level coverage invariants for the egress chokepoint, plus static
guards on the UI's escapeHtml helper.

The failure mode the egress chokepoint closes is a channel added later WITHOUT
the check (exactly how steps[].args / steps[].thinking became uncovered once).
These tests inspect the source so any new yield site or return path that
bypasses scrub_egress fails CI, not code review.

Imports app.langgraph_agent (pulls langchain); skips cleanly in a bare shell and
runs in CI (the built image does not contain tests/) — same pattern as the other agent-level tests.
"""
import inspect
import re
from pathlib import Path

import pytest

pytest.importorskip("langgraph")

from app.langgraph_agent import LangGraphAgent  # noqa: E402


# ── scrub_egress coverage invariants ─────────────────────────────────────────

def test_every_yield_in_analyze_stream_is_wrapped_in_scrub_egress():
    src = inspect.getsource(LangGraphAgent.analyze_stream)
    bare_yields = re.findall(r"yield\s+\{", src)
    assert not bare_yields, f"unscrubbed yield site(s) in analyze_stream: {len(bare_yields)}"
    assert "yield scrub_egress(" in src


def test_parse_response_single_return_is_wrapped_in_scrub_egress():
    src = inspect.getsource(LangGraphAgent._parse_response)
    # ^\s*return matches only return STATEMENTS (comments mentioning "return
    # value" have a leading #, so they don't match).
    returns = re.findall(r"^\s*return\b.*", src, re.M)
    assert len(returns) == 1, f"_parse_response must have exactly one return, found: {returns}"
    assert returns[0].strip().startswith("return scrub_egress("), \
        "_parse_response must return via scrub_egress only"


def test_parse_response_never_joins_raw_argument_values():
    src = inspect.getsource(LangGraphAgent._parse_response)
    assert "summarize_tool_args(" in src
    assert 'f"{k}={v}"' not in src, "steps[].args must not carry verbatim argument values"


# ── UI escaper static guard ──────────────────────────────────────────────────
# escapeHtml output feeds HTML-attribute contexts, so it must escape quotes.
# The textContent/innerHTML DOM round-trip escapes & < > but NOT quotes
# (quote-out -> inline event-handler injection) and must not come back.

UI_INDEX = Path(__file__).resolve().parent.parent / "app" / "ui" / "index.html"


def _escape_html_source():
    src = UI_INDEX.read_text(encoding="utf-8")
    m = re.search(r"function escapeHtml\([\s\S]*?\n\}", src)
    assert m, "escapeHtml() not found in app/ui/index.html"
    return m.group(0)


def test_escapehtml_escapes_both_quote_kinds():
    body = _escape_html_source()
    assert "&quot;" in body, "escapeHtml must escape double quotes (attribute context)"
    assert "&#39;" in body, "escapeHtml must escape single quotes (attribute context)"
    for entity in ("&amp;", "&lt;", "&gt;"):
        assert entity in body


def test_escapehtml_is_not_the_quote_blind_dom_idiom():
    body = _escape_html_source()
    assert "textContent" not in body
    assert "innerHTML" not in body
    assert "createElement" not in body
