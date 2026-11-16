"""Egress-governance tests: Slack destination pinning (sink-side
allowlist) and mrkdwn output escaping in both formatters.

No network: the allowlist refusal happens before any HTTP call, and the
positive-path test stubs the aiohttp session with a sentinel to prove the
send got PAST the allowlist."""

import asyncio
import inspect
import json
from unittest.mock import patch

from app.grafana_poller import _build_slack_blocks, _escape_mrkdwn, _to_slack_mrkdwn
from app.slack_client import SlackClient, _allowed_channels, escape_mrkdwn, trusted_link_markup


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


_SLACK_ENV = ("SLACK_ALLOWED_CHANNELS", "SLACK_DEFAULT_CHANNEL", "GRAFANA_ALERT_SLACK_CHANNEL")


def _clear_slack_env(monkeypatch):
    for var in _SLACK_ENV:
        monkeypatch.delenv(var, raising=False)


class _CapturingSession:
    """Stands in for aiohttp.ClientSession: records the chat.postMessage payload
    and answers ok=True, so a test can assert on what would have been sent."""
    sent = []

    def __init__(self, *a, **kw):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    def post(self, url, json=None, headers=None, **kwargs):
        # The Slack client posts with allow_redirects=False so the
        # bot token cannot follow a redirect off slack.com; accept and pin it.
        assert kwargs.get("allow_redirects") is False, kwargs
        _CapturingSession.sent.append(json)
        session = self

        class _Resp:
            status = 200

            async def json(self_inner):
                return {"ok": True, "ts": "1.2"}

            async def __aenter__(self_inner):
                return self_inner

            async def __aexit__(self_inner, *exc):
                return False
        return _Resp()


def _capture_send(client, **kwargs):
    _CapturingSession.sent = []
    with patch("app.slack_client.aiohttp.ClientSession", _CapturingSession):
        result = _run(client.send_message(**kwargs))
    assert result["success"] is True, result
    return _CapturingSession.sent[-1]


# ── Slack destination allowlist (sink-side) ─────────────────────────────────────

def test_allowed_channels_parses_strips_and_dedups(monkeypatch):
    _clear_slack_env(monkeypatch)
    monkeypatch.setenv("SLACK_ALLOWED_CHANNELS", " #example-alerts, ops-flink ,, #ops-flink ")
    assert _allowed_channels() == frozenset({"example-alerts", "ops-flink"})


def test_allowed_channels_empty_when_nothing_configured(monkeypatch):
    _clear_slack_env(monkeypatch)
    assert _allowed_channels() == frozenset()


def test_allowed_channels_include_operator_pinned_destinations(monkeypatch):
    """Review: the allowlist never included SLACK_DEFAULT_CHANNEL /
    GRAFANA_ALERT_SLACK_CHANNEL, and most deployments set no
    SLACK_ALLOWED_CHANNELS — so it was an empty set in every deployment. The
    operator-pinned destinations are permitted by construction."""
    _clear_slack_env(monkeypatch)
    monkeypatch.setenv("SLACK_DEFAULT_CHANNEL", "#Example-Alerts")
    monkeypatch.setenv("GRAFANA_ALERT_SLACK_CHANNEL", "C0123ABCD")
    assert _allowed_channels() == frozenset({"example-alerts", "c0123abcd"})


def test_send_refused_for_unlisted_channel(monkeypatch):
    _clear_slack_env(monkeypatch)
    monkeypatch.setenv("SLACK_ALLOWED_CHANNELS", "example-alerts")
    client = SlackClient(bot_token="xoxb-test")
    result = _run(client.send_message(text="hi", channel="#random"))
    assert result["success"] is False
    assert "not permitted" in result["error"]


def test_pinned_default_channel_is_permitted_without_allowlist(monkeypatch):
    """SLACK_DEFAULT_CHANNEL alone (the common deployment shape) must work: the
    operator chose that destination, so it needs no second variable."""
    _clear_slack_env(monkeypatch)
    monkeypatch.setenv("SLACK_DEFAULT_CHANNEL", "example-alerts")
    client = SlackClient(bot_token="xoxb-test")
    with patch("app.slack_client.aiohttp.ClientSession",
               side_effect=RuntimeError("net-sentinel")):
        result = _run(client.send_message(text="hi"))
    assert "net-sentinel" in result["error"]


def test_explicit_channel_outside_pinned_set_is_refused(monkeypatch):
    _clear_slack_env(monkeypatch)
    monkeypatch.setenv("SLACK_DEFAULT_CHANNEL", "example-alerts")
    client = SlackClient(bot_token="xoxb-test")
    result = _run(client.send_message(text="hi", channel="random"))
    assert result["success"] is False
    assert "not permitted" in result["error"]


def test_allowlist_comparison_is_normalized(monkeypatch):
    """'#Example-Alerts ' and 'example-alerts' are the same destination —
    the comparison was exact-string before."""
    _clear_slack_env(monkeypatch)
    monkeypatch.setenv("SLACK_ALLOWED_CHANNELS", "Example-Alerts")
    client = SlackClient(bot_token="xoxb-test")
    with patch("app.slack_client.aiohttp.ClientSession",
               side_effect=RuntimeError("net-sentinel")):
        result = _run(client.send_message(text="hi", channel="#example-alerts "))
    assert "net-sentinel" in result["error"]


def test_send_allowed_channel_passes_allowlist(monkeypatch):
    """An allowlisted channel ('#' normalized) must get past the allowlist to
    the network layer — proven by the sentinel the stubbed session raises."""
    _clear_slack_env(monkeypatch)
    monkeypatch.setenv("SLACK_ALLOWED_CHANNELS", "example-alerts")
    client = SlackClient(bot_token="xoxb-test")
    with patch("app.slack_client.aiohttp.ClientSession",
               side_effect=RuntimeError("net-sentinel")):
        result = _run(client.send_message(text="hi", channel="#example-alerts"))
    assert result["success"] is False
    assert "net-sentinel" in result["error"]


def test_nothing_configured_fails_closed(monkeypatch):
    """With no operator-configured destination at all, every explicit channel
    is refused before any network call (previously: no restriction)."""
    _clear_slack_env(monkeypatch)
    client = SlackClient(bot_token="xoxb-test")
    with patch("app.slack_client.aiohttp.ClientSession",
               side_effect=RuntimeError("net-sentinel")):
        result = _run(client.send_message(text="hi", channel="anything"))
    assert result["success"] is False
    assert "not permitted" in result["error"]


# ── trusted links survive the escaping (review: every link was disabled) ───────

def test_trusted_link_markup_renders_live_link_with_escaped_label():
    out = trusted_link_markup([("https://github.com/o/r/pull/42", "PR #42 <!channel>")])
    assert out.startswith("<https://github.com/o/r/pull/42|PR #42 ")
    assert "<!channel>" not in out          # label is escaped, URL is not


def test_trusted_link_markup_drops_unsafe_urls():
    bad = [
        ("http://github.com/o/r/pull/1", "PR #1"),            # not https
        ("https://github.com/o/r/pull/1|x", "PR #1"),         # '|' would split the anchor
        ("https://evil.example/x>", "PR #1"),                       # '>' closes the markup
        ("javascript:alert(1)", "PR #1"),
        (None, "PR #1"),
    ]
    assert trusted_link_markup(bad) == ""


def test_send_message_appends_trusted_link_after_escaping(monkeypatch):
    """The reproduced regression: escape_mrkdwn + verbatim + parse=none leave
    NO link alive, so the PR URL the model emits arrives unclickable. The
    trusted link built from the tool result must survive in the payload —
    unescaped, in both the fallback text and a trailing block."""
    _clear_slack_env(monkeypatch)
    monkeypatch.setenv("SLACK_DEFAULT_CHANNEL", "example-alerts")
    client = SlackClient(bot_token="xoxb-test")
    pr_url = "https://github.com/example-org/flink-job/pull/42"
    payload = _capture_send(
        client,
        text=f"Drafted PR: {pr_url} <https://evil.example|Runbook>",
        blocks=client.format_analysis_as_blocks("## Action\ndone"),
        trusted_links=[(pr_url, "PR #42")],
    )
    live = f"<{pr_url}|PR #42>"
    assert live in payload["text"]
    assert "<https://evil.example|Runbook>" not in payload["text"]   # model markup stays inert
    dumped = json.dumps(payload["blocks"])
    assert live in dumped
    assert payload["blocks"][-1]["text"]["verbatim"] is True
    assert payload["parse"] == "none"


def test_send_message_without_trusted_links_adds_nothing(monkeypatch):
    _clear_slack_env(monkeypatch)
    monkeypatch.setenv("SLACK_DEFAULT_CHANNEL", "example-alerts")
    client = SlackClient(bot_token="xoxb-test")
    payload = _capture_send(client, text="plain", blocks=None)
    assert payload["text"] == "plain"
    assert "blocks" not in payload


# ── mrkdwn escaping (CWE-116) ───────────────────────────────────────────────────

HOSTILE = "<!channel> see <https://evil.example|Runbook: click to acknowledge> & more"


def test_escape_mrkdwn_neutralizes_broadcast_and_anchor():
    for helper in (escape_mrkdwn, _escape_mrkdwn):
        out = helper(HOSTILE)
        assert "<!channel>" not in out
        assert "<https://evil.example" not in out
        assert "&lt;" in out and "&amp;" in out


def test_poller_mrkdwn_escapes_first_then_rewrites():
    out = _to_slack_mrkdwn("**bold** text\n- item\n" + HOSTILE)
    # rewrites still work (escape-first ordering must not mangle them)
    assert "*bold*" in out
    assert "• item" in out
    # hostile markup is inert
    assert "<!channel>" not in out
    assert "<https://evil.example" not in out


def test_poller_blocks_carry_no_raw_markup():
    blocks = _build_slack_blocks(f"## Action\n{HOSTILE}", title="t")
    dumped = json.dumps(blocks)
    assert "<!channel>" not in dumped
    assert "<https://evil.example" not in dumped


def test_format_analysis_as_blocks_carries_no_raw_markup():
    client = SlackClient(bot_token="xoxb-test")
    analysis = f"## Status\n**Status:** RUNNING\n{HOSTILE}\n- bullet"
    dumped = json.dumps(client.format_analysis_as_blocks(analysis))
    assert "<!channel>" not in dumped
    assert "<https://evil.example" not in dumped


def test_send_message_escapes_fallback_text_source_invariant():
    src = inspect.getsource(SlackClient.send_message)
    assert "escape_mrkdwn(" in src, \
        "send_message must escape the model-derived top-level text"


# ── Slack: bare @channel/@here can only be neutralized server-side ────────────

def _mrkdwn_objects(node):
    if isinstance(node, dict):
        if node.get("type") == "mrkdwn":
            yield node
        for v in node.values():
            yield from _mrkdwn_objects(v)
    elif isinstance(node, list):
        for v in node:
            yield from _mrkdwn_objects(v)


def test_every_mrkdwn_object_is_verbatim_in_both_builders():
    from app.grafana_poller import _build_slack_blocks
    from app.slack_client import SlackClient
    text = "## Status\n@channel **Status:** RUNNING\n- item @here"
    objs = list(_mrkdwn_objects(_build_slack_blocks(text, title="t")))
    objs += list(_mrkdwn_objects(SlackClient().format_analysis_as_blocks(text)))
    assert objs, "expected mrkdwn objects"
    assert all(o.get("verbatim") is True for o in objs)


def test_send_message_sets_parse_none_source_invariant():
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "app" / "slack_client.py").read_text(encoding="utf-8")
    assert '"parse": "none",' in src
