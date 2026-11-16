"""Dead-code regression tests: removed dead surface must stay removed.

Two artifacts were deleted deliberately and must not quietly return:

  * app/slack_client_webhook.py -- an UNREFERENCED duplicate class also named
    SlackClient that read SLACK_BOT_TOKEN / SLACK_WEBHOOK_URL / SLACK_WEBHOOKS
    directly from the environment (bypassing the secret provider every live
    credential goes through) and POSTed to an arbitrary env-controlled webhook
    URL. Nothing ever imported it; a one-line import swap would have moved the
    Slack credential off the secret provider without an obviously security-relevant diff.

  * MetricsCollector.collect_context() -- 77 dead lines with no caller anywhere,
    advertised as a live capability by docs. Re-activating it would exercise an
    unbounded time_range_hours fan-out against the shared operator database.

Pure-stdlib text/structure assertions: no third-party deps, no docker, no network.
"""

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
APP_DIR = REPO_ROOT / "app"


def _app_sources():
    return {p: p.read_text() for p in APP_DIR.rglob("*.py")}


# ---------------------------------------------------------------------------
# The env-sourced webhook Slack client stays gone
# ---------------------------------------------------------------------------

def test_slack_webhook_module_gone():
    assert not (APP_DIR / "slack_client_webhook.py").exists(), (
        "app/slack_client_webhook.py is back -- the env-sourced duplicate "
        "SlackClient (secret-provider bypass + arbitrary webhook URL) was deleted deliberately"
    )


def test_nothing_references_the_webhook_module():
    for path, source in _app_sources().items():
        assert "slack_client_webhook" not in source, (
            f"{path} references the deleted webhook module"
        )


def test_no_env_sourced_webhook_credential_inputs():
    """SLACK_WEBHOOK_URL / SLACK_WEBHOOKS existed ONLY in the deleted module.
    They are env-controlled arbitrary POST destinations; nothing live may read
    them."""
    for path, source in _app_sources().items():
        for var in ("SLACK_WEBHOOK_URL", "SLACK_WEBHOOKS"):
            assert var not in source, f"{path} reads {var} from the environment"


# ---------------------------------------------------------------------------
# The dead context-aggregation path stays gone
# ---------------------------------------------------------------------------

def test_collect_context_stays_deleted():
    for path, source in _app_sources().items():
        assert "collect_context" not in source, (
            f"{path} reintroduces collect_context -- it had no caller and its "
            "unbounded time_range_hours fan-out was never exercised or tested"
        )


def test_docs_do_not_advertise_context_aggregation():
    """Covers the prose ("context aggregation") and the architecture-diagram
    component box ("Context Aggregator") alike."""
    for rel in ("ARCHITECTURE.md", "README.md"):
        content = (REPO_ROOT / rel).read_text().lower()
        assert "context aggregat" not in content, (
            f"{rel} advertises the deleted context-aggregation capability"
        )
