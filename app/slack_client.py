# Copyright Yahoo, Licensed under the terms of the Apache 2.0 license. See LICENSE for terms.

import asyncio
import json
import logging
import os
import re
from typing import Dict, Optional

import aiohttp

from app import secret_provider

logger = logging.getLogger(__name__)

# Slack API error codes that mean the presented token is bad (rotated/revoked),
# not that the request was malformed — these trigger a cache invalidation.
_SLACK_AUTH_ERRORS = ("invalid_auth", "token_revoked", "account_inactive")


# ── Egress governance (sink-side controls) ─────────────────────────────────────
# Every Slack send in this service ultimately passes through send_message, so the
# destination allowlist and markup escaping live HERE: any caller — the agent's
# send_to_slack tool, the Grafana poller, or future code — inherits them.

def _normalize_channel(channel: str) -> str:
    """Canonical form for allowlist comparison: surrounding whitespace and a
    leading '#' dropped, case folded (channel names are lowercase in Slack, and
    IDs compare case-insensitively without harm). Name-vs-ID equivalence is not
    resolvable without an API call, so pin the same form in every variable."""
    return channel.strip().lstrip("#").casefold()


# Operator-pinned destination variables. Every value set here is implicitly a
# permitted destination: an operator who pins SLACK_DEFAULT_CHANNEL or
# GRAFANA_ALERT_SLACK_CHANNEL has chosen it, and most deployments set no
# SLACK_ALLOWED_CHANNELS at all — without this the allowlist would be an
# empty set in every real deployment.
_OPERATOR_DESTINATION_VARS = ("SLACK_DEFAULT_CHANNEL", "GRAFANA_ALERT_SLACK_CHANNEL")


def _allowed_channels() -> frozenset:
    """Sink-side destination allowlist: SLACK_ALLOWED_CHANNELS (comma-separated
    names or IDs, '#' optional) UNION the operator-pinned destination variables.
    Read at call time so tests and env-driven deploys don't need a module
    reload. When the result is empty nothing is configured, and send_message
    refuses every destination (fail closed)."""
    listed = (
        c for c in os.getenv("SLACK_ALLOWED_CHANNELS", "").split(",") if c.strip()
    )
    pinned = (os.getenv(var, "") for var in _OPERATOR_DESTINATION_VARS)
    return frozenset(
        _normalize_channel(c) for c in (*listed, *pinned) if c and c.strip()
    )


_BROADCAST_RE = re.compile(r"<!(channel|here|everyone)>", re.I)

# Shape of a link URL this module will emit as live markup. Only code-derived
# URLs (the pr_url a GitHub API response returned) ever reach this — never
# model text — but the shape is still pinned: https only, no whitespace and
# none of the characters that terminate or split Slack's <url|label> syntax.
_TRUSTED_LINK_URL_RE = re.compile(r"^https://[A-Za-z0-9.\-]+(?::\d{1,5})?/[^\s<>|]*$")


def trusted_link_markup(links) -> str:
    """Render code-derived (url, label) pairs as live Slack links.

    escape_mrkdwn + verbatim + parse=none leave NO link alive in model-derived
    text — that is the point — so anything the operator must be able to click
    (the PR the agent just opened) is appended here from the tool result, after
    escaping, as a separate trusted line. Labels are escaped: only the URL is
    trusted, and it is shape-checked. Pairs that fail the check are dropped."""
    lines = []
    for url, label in links or ():
        if not isinstance(url, str) or not _TRUSTED_LINK_URL_RE.match(url):
            logger.warning("trusted link dropped: URL failed shape check")
            continue
        lines.append(f"<{url}|{escape_mrkdwn(str(label))}>")
    return "\n".join(lines)


def escape_mrkdwn(text: str) -> str:
    """Neutralize Slack mrkdwn control sequences in model-derived text (CWE-116).

    Slack treats <...> as markup: <!channel> notifies the whole channel and
    <url|label> renders a link with arbitrary anchor text — both are injection
    primitives when the text comes from model output. Escaping must happen
    BEFORE any markup rewriting; the broadcast-token strip afterwards is
    defense in depth for anything that survives escaping."""
    text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return _BROADCAST_RE.sub("", text)


class SlackClient:
    def __init__(self, bot_token: Optional[str] = None):
        self.bot_token = bot_token or os.getenv("SLACK_BOT_TOKEN", "")
        self.default_channel = os.getenv("SLACK_DEFAULT_CHANNEL", "")
        self.enabled = bool(self.bot_token)
        self.api_base = "https://slack.com/api"

        if self.enabled:
            logger.info("Slack integration enabled with bot token (default channel: %s)",
                       self.default_channel or "none")
        else:
            logger.warning("Slack integration disabled - SLACK_BOT_TOKEN not set")

    async def _current_token(self) -> str:
        """Resolve the bot token per call: prefer the secret provider's cached
        token (TTL-refreshed, so a rotation in a live secret backend propagates without a
        restart; SECRET_PROVIDER=env values change only on a pod restart),
        falling back to the constructor/env token for local-dev construction.
        The getter may re-fetch from the secret backend (possibly blocking) — to_thread keeps
        it off the event loop. Returns "" when an invalidated token's re-fetch
        failed (fail closed: never re-present a known-bad credential)."""
        try:
            token = await asyncio.to_thread(secret_provider.get_slack_token)
        except Exception as e:
            logger.warning("Slack bot token refresh failed — failing closed for this send: %s", e)
            return ""
        return token or self.bot_token

    async def send_message(
        self,
        text: str,
        channel: Optional[str] = None,
        blocks: Optional[list] = None,
        truncate: bool = True,
        thread_ts: Optional[str] = None,
        trusted_links: Optional[list] = None,
    ) -> Dict:
        """Send a message to Slack via Web API (chat.postMessage).

        Args:
            text: Message text (also used as fallback for blocks)
            channel: Channel name (#alerts) or ID (C1234567). Uses SLACK_DEFAULT_CHANNEL if not specified.
            blocks: Slack Block Kit blocks for rich formatting
            truncate: If True, truncate text/blocks to fit Slack limits
            thread_ts: If set, post as a reply in that thread (use the `ts` from a prior send_message response)
            trusted_links: Code-derived (url, label) pairs — e.g. the PR a tool
                result returned — appended AFTER escaping as live links, since
                nothing in the model-derived text can be a link any more.

        Returns:
            Dict with success status, message, channel info, and ts (thread root for follow-up replies)
        """
        if not self.enabled:
            logger.error("send_message called but Slack is not enabled")
            return {
                "success": False,
                "error": "Slack not configured - set SLACK_BOT_TOKEN environment variable",
            }

        target_channel = channel or self.default_channel
        if not target_channel:
            return {
                "success": False,
                "error": "No channel specified and SLACK_DEFAULT_CHANNEL not set",
            }

        # Strip # prefix if present (API accepts both)
        if target_channel.startswith("#"):
            target_channel = target_channel[1:]

        # Destination allowlist (sink-side, so every caller inherits it): the
        # permitted set is SLACK_ALLOWED_CHANNELS plus the operator-pinned
        # destination variables, compared in normalized form. Anything outside
        # it — and everything, when nothing is configured — is refused BEFORE
        # any network call (fail closed). The refusal surfaces as success=False,
        # which callers record in their slack_send audit event.
        allowed = _allowed_channels()
        if _normalize_channel(target_channel) not in allowed:
            logger.warning(
                "slack send refused: channel %r is not an operator-configured destination"
                " (SLACK_ALLOWED_CHANNELS / SLACK_DEFAULT_CHANNEL / GRAFANA_ALERT_SLACK_CHANNEL)",
                target_channel,
            )
            return {
                "success": False,
                "error": "destination channel is not permitted by this deployment",
            }

        # The top-level text is model-derived on every current call path (message
        # body without blocks; notification/preview fallback with blocks) — escape
        # it so it cannot carry broadcast tokens or spoofed anchors. Block payloads
        # are escaped by their builders (format_analysis_as_blocks / the poller's
        # _to_slack_mrkdwn) before their markup rewrites, so there is no
        # double-escaping: call sites pass raw text here.
        text = escape_mrkdwn(text)

        # Slack has message limits: 3000 chars for text, 50 blocks max
        if truncate and len(text) > 2900:
            text = text[:2900] + "\n\n_[Message truncated due to length]_"

        if truncate and blocks and len(blocks) > 45:
            blocks = blocks[:45]
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "verbatim": True, "text": "_[Additional blocks truncated]_"}
            })

        # Trusted links go in AFTER escaping, as their own line / block, so the
        # operator gets a clickable PR link while nothing the model wrote can
        # become one. (verbatim / parse=none disable AUTO-linking only; explicit
        # <url|label> markup still renders.)
        link_markup = trusted_link_markup(trusted_links)
        if link_markup:
            text = f"{text}\n{link_markup}"
            if blocks is not None:
                blocks = list(blocks) + [{
                    "type": "section",
                    "text": {"type": "mrkdwn", "verbatim": True, "text": link_markup[:2900]},
                }]

        # parse=none + verbatim on every mrkdwn object: Slack's server-side
        # parsing otherwise still linkifies bare @channel / @here / @everyone
        # into broadcasts even after <...> escaping (the escaping neutralizes
        # <!channel>; it cannot neutralize bare mentions — only verbatim can).
        payload = {
            "channel": target_channel,
            "text": text,
            "parse": "none",
        }
        if blocks:
            payload["blocks"] = blocks
        if thread_ts:
            payload["thread_ts"] = thread_ts

        token = await self._current_token()
        if not token:
            return {
                "success": False,
                "error": "Slack bot token unavailable — re-fetch from secret provider failed",
            }

        try:
            timeout = aiohttp.ClientTimeout(total=10)
            headers = {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            }

            async with aiohttp.ClientSession(timeout=timeout) as session:
                # allow_redirects=False (consistent with every other
                # credential-bearing client): the bot token must never follow
                # a redirect to a host other than the fixed Slack API base.
                async with session.post(
                    f"{self.api_base}/chat.postMessage",
                    json=payload,
                    headers=headers,
                    allow_redirects=False,
                ) as resp:
                    response_data = await resp.json()

                    if resp.status == 200 and response_data.get("ok"):
                        logger.info(
                            "Slack message sent successfully to %s (%d chars)",
                            target_channel, len(text)
                        )
                        return {
                            "success": True,
                            "message": f"Message sent to Slack channel: {target_channel}",
                            "channel": target_channel,
                            "ts": response_data.get("ts"),
                        }
                    else:
                        error_msg = response_data.get("error", "unknown error")
                        if error_msg in _SLACK_AUTH_ERRORS:
                            # The token was rotated or revoked — invalidate so the
                            # next send re-fetches a fresh one from the secret backend.
                            secret_provider.invalidate_slack_token()
                        logger.error(
                            "Slack API failed: %s (HTTP %d)", error_msg, resp.status
                        )
                        return {
                            "success": False,
                            "error": f"Slack API error: {error_msg}",
                        }
        except aiohttp.ClientError as e:
            logger.error("Slack API request failed: %s", e)
            return {"success": False, "error": f"Network error: {str(e)}"}
        except Exception as e:
            logger.error("Slack send_message failed: %s", e, exc_info=True)
            return {"success": False, "error": str(e)}

    def format_analysis_as_blocks(self, analysis: str, title: str = "Flink AI Analysis") -> list:
        """Convert AI analysis text to Slack Block Kit format with rich formatting.

        Returns a list of Slack blocks with nice formatting, emojis, and structure.
        """
        import re
        from datetime import datetime

        # Escape model-derived text ONCE at entry — before any markup rewriting —
        # so every mrkdwn field built below (section bodies, section headers, the
        # extracted metric fields) is inert. The title feeds plain_text blocks
        # only, which Slack does not parse as mrkdwn.
        analysis = escape_mrkdwn(analysis)

        blocks = [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": f"⚡ {title}", "emoji": True},
            },
            {"type": "divider"},
        ]

        # Extract key metrics if present (look for patterns like "Status: RUNNING", "Uptime: 2d")
        metrics = self._extract_metrics(analysis)
        if metrics:
            blocks.append({
                "type": "section",
                "fields": metrics[:10],  # Max 10 fields in a section
            })
            blocks.append({"type": "divider"})

        # Split into sections by markdown headers
        lines = analysis.split("\n")
        current_section = []
        section_emoji = {
            "status": "📊",
            "summary": "📋",
            "issue": "⚠️",
            "error": "❌",
            "warning": "⚠️",
            "checkpoint": "✅",
            "performance": "🚀",
            "metric": "📈",
            "recommendation": "💡",
            "fix": "🔧",
            "remediation": "🛠️",
        }

        for line in lines:
            # Handle headers
            if line.startswith("# ") or line.startswith("## ") or line.startswith("### "):
                # Flush current section
                if current_section:
                    text = self._format_section_content("\n".join(current_section).strip())
                    if text:
                        blocks.append({
                            "type": "section",
                            "text": {"type": "mrkdwn", "verbatim": True, "text": text[:2900]},
                        })
                    current_section = []

                # Add header with emoji
                header_text = line.lstrip("#").strip().lower()
                emoji = "📌"
                for keyword, e in section_emoji.items():
                    if keyword in header_text:
                        emoji = e
                        break

                blocks.append({
                    "type": "section",
                    "text": {"type": "mrkdwn", "verbatim": True, "text": f"{emoji} *{line.lstrip('#').strip()}*"},
                })
            else:
                current_section.append(line)

        # Flush remaining section
        if current_section:
            text = self._format_section_content("\n".join(current_section).strip())
            if text:
                blocks.append({
                    "type": "section",
                    "text": {"type": "mrkdwn", "verbatim": True, "text": text[:2900]},
                })

        # Add footer with timestamp
        blocks.append({"type": "divider"})
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
        blocks.append({
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "verbatim": True,
                    "text": f"🤖 *Flink AI Debugger* | {timestamp}",
                }
            ],
        })

        return blocks

    def _extract_metrics(self, text: str) -> list:
        """Extract key-value metrics from text for structured display."""
        import re

        # Patterns like "Status: RUNNING", "Uptime: 2d 5h", "Throughput: 25k/s"
        pattern = r'\*\*([^:]+):\*\*\s+([^\n]+)'
        matches = re.findall(pattern, text)

        fields = []
        status_emojis = {
            "running": "🟢",
            "healthy": "✅",
            "failed": "🔴",
            "warning": "🟡",
            "error": "❌",
            "ok": "✅",
            "high": "🔴",
            "medium": "🟡",
            "low": "🟢",
        }

        for key, value in matches[:10]:  # Limit to 10 metrics
            # Add emoji based on value
            emoji = ""
            value_lower = value.lower()
            for keyword, e in status_emojis.items():
                if keyword in value_lower:
                    emoji = e + " "
                    break

            fields.append({
                "type": "mrkdwn",
                "verbatim": True,
                "text": f"*{key.strip()}*\n{emoji}{value.strip()}",
            })

        return fields

    def _format_section_content(self, text: str) -> str:
        """Format section content with better bullet points and code blocks."""
        if not text:
            return ""

        lines = text.split("\n")
        formatted_lines = []

        for line in lines:
            # Convert markdown bold to Slack bold
            line = line.replace("**", "*")

            # Enhance bullet points
            if line.strip().startswith("- "):
                line = line.replace("- ", "• ", 1)
            elif line.strip().startswith("* "):
                line = line.replace("* ", "• ", 1)

            # Add emojis to common patterns
            if "✓" in line or "success" in line.lower():
                if not any(e in line for e in ["✅", "🟢", "✓"]):
                    line = "✅ " + line.lstrip("• ").lstrip()
            elif "✗" in line or "fail" in line.lower():
                if not any(e in line for e in ["❌", "🔴", "✗"]):
                    line = "❌ " + line.lstrip("• ").lstrip()
            elif "warning" in line.lower() or "⚠" in line:
                if not any(e in line for e in ["⚠️", "🟡"]):
                    line = "⚠️ " + line.lstrip("• ").lstrip()

            formatted_lines.append(line)

        return "\n".join(formatted_lines)
