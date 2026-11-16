# Copyright Yahoo, Licensed under the terms of the Apache 2.0 license. See LICENSE for terms.

import asyncio
import json
import logging
from contextlib import asynccontextmanager
import os
import re
import time
import unicodedata
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import HTMLResponse, Response, JSONResponse, StreamingResponse
from pydantic import BaseModel, Field, PrivateAttr, field_validator, model_validator

from app.flink_client import FlinkClient
from app.kubernetes_client import KubernetesClient, k8s_call
from app.postgres_client import PostgresStateReader, postgres_enabled as _postgres_enabled
from app.metrics_collector import MetricsCollector
from app.langgraph_agent import LangGraphAgent, execute_approved_pr
from app.auto_remediator import AutoRemediator, RemediationType, RemediationAction
from app.slack_client import SlackClient
from app.github_client import GitHubClient
from app.egress_governance import redact_for_client
from app.egress_policy import EgressPolicyError, validated_anthropic_base_url
from app import secret_provider
from app import write_proposals
from app.audit import audit, audit_remediation, client_ip, get_correlation_id, new_correlation_id, redact_credentials
from app.rate_limiter import SlidingWindowRateLimiter
from app.write_authz import agent_halted, kill_switch_state, write_tools_enabled
from app import telemetry

# Plain log lines carry UTC timestamps and the flow's correlation id (the same
# id the audit records carry), so the two streams can be joined.
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)sZ [%(levelname)s] %(name)s [cid=%(correlation_id)s]: %(message)s",
)
for _h in logging.getLogger().handlers:
    if _h.formatter is not None:
        _h.formatter.converter = time.gmtime

# Bound on a single plaintext log line: large enough for legitimate diagnostic
# lines, small enough that an unbounded remote body (e.g. a Grafana API error
# response) cannot flood the stream.
_MAX_LOG_MSG = 8192

# C0 control characters + DEL, other than \r / \n (escaped explicitly below)
# and \t (harmless, kept for readability): escaped to \xNN so terminal-control
# sequences (e.g. ESC) can't mangle the log stream either.
_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


_TRACEBACK_FORMATTER = logging.Formatter()


class _FlattenFilter(logging.Filter):
    """Collapse control characters and bound length in the plaintext log stream (CWE-117).

    Remote- and model-controlled content (Grafana API bodies and alert names,
    user question text, Kubernetes object fields) is interpolated verbatim into
    the plaintext lines produced by the root formatter above; embedded CR/LF
    would otherwise forge whole log entries. Escaping at the handler fixes the
    class in one place instead of at each interpolation site.

    The structured JSON audit channel does NOT pass through here — app/audit.py
    sets propagate=False on "app.audit" and owns its handler — so audit records
    keep their byte-for-byte shape. Tracebacks keep their line breaks, but
    get the same credential mask: an exception message can quote a job
    parameter or a URL with credentials in it.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        if not hasattr(record, "correlation_id"):
            record.correlation_id = get_correlation_id() or "-"
        # Audit records own their channel and shape (see the docstring); a
        # handler shared with that logger must leave them untouched.
        if record.name == "app.audit" or record.name.startswith("app.audit."):
            return True
        # The formatter reuses exc_text when set, so the masked traceback is what gets written.
        if record.exc_info and not record.exc_text:
            record.exc_text = _TRACEBACK_FORMATTER.formatException(record.exc_info)
        if record.exc_text:
            record.exc_text = redact_credentials(record.exc_text)
        if record.stack_info:
            record.stack_info = redact_credentials(record.stack_info)
        try:
            msg = record.getMessage()
        except Exception:
            # Never drop a record over a %-format mismatch. Not a forgery path:
            # the handler's own format() will hit the same error and route the
            # record to logging's internal error handler, not the log stream.
            return True
        # Mask credential-shaped text (bearer tokens, password=..., URL
        # userinfo, vendor keys) with the same helper the model-bound and audit
        # paths use: job and remote content interpolated into a plain log line
        # must not reach the log sink in clear (CWE-532). Runs before the
        # newline escaping so real line breaks still bound each match, and on
        # a bounded prefix so an oversize message cannot make it slow.
        original_len = len(msg)
        msg = redact_credentials(msg[: 2 * _MAX_LOG_MSG])
        flat = msg.replace("\r", "\\r").replace("\n", "\\n")
        flat = _CTRL_RE.sub(lambda m: f"\\x{ord(m.group()):02x}", flat)
        if len(flat) > _MAX_LOG_MSG or original_len > 2 * _MAX_LOG_MSG:
            flat = flat[:_MAX_LOG_MSG] + f"…[truncated {max(original_len - _MAX_LOG_MSG, 0)} chars]"
        record.msg = flat
        record.args = ()                    # already interpolated by getMessage()
        return True


# Attach to the root HANDLER, not a logger: a logger-attached filter only sees
# records emitted through that logger, whereas the handler sees every record
# propagating to the root (grafana_poller, kubernetes_client, webhook loggers, ...).
# Idempotent so importlib.reload (tests) doesn't stack duplicate filters. Note:
# a handler added to the root logger later at runtime must attach this filter too.
for _h in logging.getLogger().handlers:
    if not any(isinstance(_f, _FlattenFilter) for _f in _h.filters):
        _h.addFilter(_FlattenFilter())

logger = logging.getLogger(__name__)

ROOT_PATH = os.getenv("ROOT_PATH", "")


def postgres_enabled() -> bool:
    """PostgreSQL autoscaler integration is OPT-IN (default off). Single
    definition lives in app.postgres_client (PostgresStateReader gates its own
    construction-time validation on it); re-exported here for the startup
    hook."""
    return _postgres_enabled()


class StripPrefixMiddleware:
    """Strips ROOT_PATH prefix from incoming request paths before routing."""
    def __init__(self, app, prefix: str):
        self.app = app
        self.prefix = prefix.rstrip("/")

    async def __call__(self, scope, receive, send):
        if scope["type"] in ("http", "websocket") and self.prefix:
            path = scope.get("path", "")
            if path == self.prefix:
                scope["path"] = "/"
            elif path.startswith(self.prefix + "/"):
                scope["path"] = path[len(self.prefix):]
        await self.app(scope, receive, send)


# Auto-generated docs are disabled: the front-door SSO proxy authenticates but does
# not authorize, so /docs, /redoc, and /openapi.json would expose the full API
# inventory to every SSO-authenticated user.
_app = FastAPI(
    title="Flink AI Debugger",
    version="1.0.0",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

# Explicit CORS policy. The UI is same-origin, so cross-origin requests are denied by
# default; configuring the middleware explicitly keeps the policy from being silently
# widened by a future reverse proxy. Set CORS_ALLOWED_ORIGINS (comma-separated) to
# permit specific trusted origins.
# Methods/headers are the minimal set the API actually serves: every route is GET or
# POST, and the only non-safelisted request header clients send is Content-Type.
# Widening this list is a deliberate, reviewed change — do not restore wildcards.
_cors_origins = [o.strip() for o in os.getenv("CORS_ALLOWED_ORIGINS", "").split(",") if o.strip()]
# Fail-closed wildcard guard: Starlette treats a "*" entry in allow_origins as
# allow-all-origins, which would silently undo the deny-all default above. Entries
# merely containing "*" (e.g. "https://*.example.com") are compared literally by
# Starlette and never match — an inert misconfiguration. Both are dropped with a
# warning so a wildcard can never widen the policy.
_wildcard_origins = [o for o in _cors_origins if "*" in o]
if _wildcard_origins:
    logger.warning(
        "CORS_ALLOWED_ORIGINS contains wildcard origin(s) %s — ignoring them. "
        "A '*' entry would allow all origins; set explicit origins or leave "
        "unset for deny-all.",
        _wildcard_origins,
    )
    _cors_origins = [o for o in _cors_origins if "*" not in o]
_app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)


class _CrossSitePostGuard:
    """Refuse cross-site and non-JSON POSTs before routing (CWE-352).

    The API authenticates nobody itself, so a browser that can reach it (through
    the authenticating front-door proxy, or over a port-forward) must not be
    usable by another site's page. Every POST route takes JSON or no body, and
    the UI sends Content-Type: application/json on each POST, so:

    * Sec-Fetch-Site ``cross-site`` / ``same-site`` is refused (403). Browsers
      set this header themselves; the UI is same-origin.
    * Without Sec-Fetch-Site (older browsers, non-browser clients), an Origin
      header that matches neither the request's Host / X-Forwarded-Host nor an
      operator-trusted CORS origin is refused (403).
    * A POST whose Content-Type is not application/json is refused (415): an
      HTML form or a body-less fetch cannot set it without a CORS preflight,
      which the deny-all CORS policy above refuses.

    An origin listed in CORS_ALLOWED_ORIGINS is the operator's explicit trust
    and is let through. Pure ASGI (not BaseHTTPMiddleware) so the SSE stream on
    /api/query/stream is untouched.
    """

    def __init__(self, app, trusted_origins):
        self.app = app
        self.trusted_origins = frozenset(o.rstrip("/").lower() for o in trusted_origins)

    @staticmethod
    def _origin_host(origin: str) -> str:
        rest = origin.split("://", 1)[-1]
        return rest.split("/", 1)[0].lower()

    def _refusal(self, headers: dict):
        origin = headers.get("origin", "")
        trusted = bool(origin) and origin.rstrip("/").lower() in self.trusted_origins
        site = headers.get("sec-fetch-site", "").strip().lower()
        if not trusted:
            if site in ("cross-site", "same-site"):
                return 403, "Cross-site request refused"
            if not site and origin:
                hosts = {headers.get("host", "").lower()}
                hosts.update(
                    h.strip().lower()
                    for h in headers.get("x-forwarded-host", "").split(",") if h.strip()
                )
                if origin.lower() == "null" or self._origin_host(origin) not in hosts:
                    return 403, "Cross-site request refused"
        ctype = headers.get("content-type", "").split(";", 1)[0].strip().lower()
        if ctype != "application/json":
            return 415, "Content-Type must be application/json"
        return None

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http" and scope.get("method") == "POST":
            headers = {
                k.decode("latin-1").lower(): v.decode("latin-1")
                for k, v in scope.get("headers") or []
            }
            refusal = self._refusal(headers)
            if refusal is not None:
                status, detail = refusal
                audit("request_refused", Request(scope), path=scope.get("path"),
                      status=status, reason=detail)
                response = JSONResponse({"detail": detail}, status_code=status)
                await response(scope, receive, send)
                return
        await self.app(scope, receive, send)


_app.add_middleware(_CrossSitePostGuard, trusted_origins=_cors_origins)


# Inbound Host allowlist (DNS-rebinding defence, CWE-350/CWE-346). Added LAST so
# it is the outermost middleware and runs before anything else. A page whose
# domain re-resolves to 127.0.0.1 during a port-forward becomes same-origin with
# this API, so CORS alone cannot stop it; checking Host can. Loopback is always
# allowed: the pod-local reverse proxy reaches the app at 127.0.0.1:8765 without
# rewriting Host, and the container probes call http://127.0.0.1:8765/api/health.
# INBOUND_ALLOWED_HOSTS (comma-separated) adds names, e.g. when a proxy forwards
# the public host name unchanged. It is separate from EGRESS_ALLOWED_HOSTS, which
# lists OUTBOUND destinations. A bare "*" is dropped, as for CORS.
_INBOUND_DEFAULT_HOSTS = ["127.0.0.1", "localhost"]
_inbound_extra = [
    h.strip().lower() for h in os.getenv("INBOUND_ALLOWED_HOSTS", "").split(",") if h.strip()
]
if "*" in _inbound_extra:
    logger.warning("INBOUND_ALLOWED_HOSTS contains '*' — ignoring it; list host names explicitly.")
    _inbound_extra = [h for h in _inbound_extra if h != "*"]
_inbound_hosts = _INBOUND_DEFAULT_HOSTS + [h for h in _inbound_extra if h not in _INBOUND_DEFAULT_HOSTS]
_app.add_middleware(TrustedHostMiddleware, allowed_hosts=_inbound_hosts)

app = StripPrefixMiddleware(_app, ROOT_PATH) if ROOT_PATH else _app

# ── Initialize clients ───────────────────────────────────────────────

flink_client = FlinkClient()
k8s_client = KubernetesClient()
postgres_reader = PostgresStateReader()
auto_remediator = AutoRemediator(flink_client, k8s_client)
metrics_collector = MetricsCollector(flink_client)
# SlackClient, GitHubClient, and LangGraphAgent are initialized in startup_event after secrets are loaded.
slack_client: Optional[SlackClient] = None
github_client: Optional[GitHubClient] = None
langgraph_agent: Optional[LangGraphAgent] = None
# Module-scope on purpose: shutdown_event() must be able to reach the poller to
# stop it. A startup-local reference made GrafanaAlertPoller.stop() dead code —
# the autonomous loop could not be stopped short of killing the pod.
grafana_poller: Optional["GrafanaAlertPoller"] = None

UI_DIR = Path(__file__).parent / "ui"

# ── Rate limiting (CWE-770) ────────────────────────────────────────────────────
# In-process sliding-window limiter: the sidecar is a single-process,
# single-replica deployment, so process-local state is authoritative. Keyed by
# the right-indexed X-Forwarded-For client IP (app.audit.client_ip) — behind the
# edge proxy → SSO gateway → pod-local reverse proxy chain the socket peer is always the proxy's
# loopback address, so a peer-address key would collapse every caller into one bucket.
# Limits are env-overridable per deployment.
#
# Parsing is guarded and clamped, matching app.audit._trusted_proxy_hops: these
# run at import time and SlidingWindowRateLimiter raises on limit < 1, so a bare
# int() would turn RATE_LIMIT_QUERY_PER_MINUTE=0 (the natural way an operator
# expresses "disable") or any typo into CrashLoopBackOff.
_MAX_RATE_LIMIT = 1000


def _rate_limit_env(name: str, default: int, maximum: int = _MAX_RATE_LIMIT) -> int:
    """Positive per-minute limit from the environment; never raises.

    Clamped at BOTH ends: an unbounded override defeats the ceiling it
    configures, so the upper clamp is part of the control.
    """
    try:
        return min(max(1, int(os.getenv(name, "").strip() or default)), maximum)
    except (TypeError, ValueError):
        logger.warning(
            "%s is not a valid integer — falling back to the default of %d", name, default
        )
        return default


_query_rate_limiter = SlidingWindowRateLimiter(
    limit=_rate_limit_env("RATE_LIMIT_QUERY_PER_MINUTE", 10), window_seconds=60.0
)
# Tighter bound for endpoints that impose load on the monitored Flink job itself
# (thread dumps, skewness scans, full diagnostics).
_heavy_rate_limiter = SlidingWindowRateLimiter(
    limit=_rate_limit_env("RATE_LIMIT_HEAVY_PER_MINUTE", 2), window_seconds=60.0
)
_logs_rate_limiter = SlidingWindowRateLimiter(
    limit=_rate_limit_env("RATE_LIMIT_LOGS_PER_MINUTE", 10), window_seconds=60.0
)
# Remaining read routes that reach Flink REST or PostgreSQL (job status,
# autoscaler events/errors/status). Its own budget so the UI's 15 s status
# poll never competes with log reads.
_read_rate_limiter = SlidingWindowRateLimiter(
    limit=_rate_limit_env("RATE_LIMIT_READ_PER_MINUTE", 10), window_seconds=60.0
)


# Concurrency cap on the agent path (CWE-400). A per-IP RATE limit does not
# bound CONCURRENCY: 10 requests from one IP can all be in flight at once, and N
# source IPs give N x 10/min. Each in-flight chain holds an LLM connection plus
# its tool fan-out in a 1 GiB / 500m pod, so the ticket's actual ask — "how many
# agent chains run concurrently" — needs this separate bound. Load is SHED with
# 429 rather than queued: queueing would hold connections open behind a limit
# that already signals saturation.
MAX_CONCURRENT_AGENT_QUERIES = _rate_limit_env("MAX_CONCURRENT_AGENT_QUERIES", 3, maximum=50)
_agent_semaphores: "dict[object, asyncio.Semaphore]" = {}


def _agent_semaphore() -> asyncio.Semaphore:
    """One semaphore per running loop (a fresh loop per pytest test)."""
    loop = asyncio.get_running_loop()
    sem = _agent_semaphores.get(loop)
    if sem is None:
        sem = asyncio.Semaphore(MAX_CONCURRENT_AGENT_QUERIES)
        _agent_semaphores[loop] = sem
    return sem


@asynccontextmanager
async def _agent_slot(endpoint: str):
    """Hold one agent-concurrency slot, or reject with 429 if the pod is saturated."""
    sem = _agent_semaphore()
    if sem.locked():
        logger.warning("Agent concurrency limit reached — rejecting %s", endpoint)
        raise HTTPException(
            status_code=429,
            detail="Too many concurrent analyses in progress. Please retry shortly.",
            headers={"Retry-After": "30"},
        )
    async with sem:
        yield


def _enforce_rate_limit(
    limiter: SlidingWindowRateLimiter, endpoint: str, http_request: Request
) -> None:
    """Reject with 429 before any work (agent chain, K8s/Flink fan-out) happens."""
    allowed, retry_after = limiter.check(client_ip(http_request))
    if not allowed:
        audit("rate_limited", http_request, endpoint=endpoint)
        raise HTTPException(
            status_code=429,
            detail="Rate limit exceeded — try again later.",
            headers={"Retry-After": str(max(1, int(retry_after + 0.999)))},
        )


# ── Lifecycle ────────────────────────────────────────────────────────

@_app.on_event("startup")
async def startup_event():
    global slack_client, github_client, langgraph_agent, grafana_poller

    # Enable OpenTelemetry (app metrics + agent tracing → in-pod otel-collector) before
    # serving requests. Best-effort: never blocks startup if the collector is unavailable.
    telemetry.setup_telemetry(_app)

    # Load secrets into process memory via the secret provider — never written to disk.
    # Run in a thread so a provider that blocks does not stall the async event loop.

    # Slack token is optional — missing config disables Slack but does not block startup.
    try:
        slack_token = await asyncio.to_thread(secret_provider.fetch_slack_token)
        slack_client = SlackClient(bot_token=slack_token)
    except Exception as e:
        logger.warning("Slack token fetch failed — Slack integration disabled: %s", e)
        slack_client = SlackClient()

    # Grafana SA token is optional — missing config disables alert poller.
    try:
        await asyncio.to_thread(secret_provider.fetch_grafana_sa_token)
    except Exception as e:
        logger.warning("Grafana SA token fetch failed — alert poller disabled: %s", e)

    # GitHub token is optional — missing config disables create_github_pr but does not block startup.
    try:
        github_token = await asyncio.to_thread(secret_provider.fetch_github_token)
        github_client = GitHubClient(token=github_token)
    except Exception as e:
        logger.warning("GitHub token fetch failed — create_github_pr disabled: %s", e)
        github_client = GitHubClient()

    # Egress policy for the Anthropic endpoint is enforced OUTSIDE the
    # degrade-gracefully block below: a destination that violates the policy
    # must fail startup like every other client (fail closed), not be logged
    # as "key fetch failed" while the pod reports Ready.
    anthropic_base_url = validated_anthropic_base_url()
    logger.info("Anthropic endpoint %s passed egress policy", anthropic_base_url)

    # Anthropic API key is required for the agent — failure disables chat only.
    logger.info("Fetching Anthropic API key from secret provider...")
    try:
        await asyncio.to_thread(secret_provider.fetch_key)
        logger.info("Anthropic API key fetch complete — no secret written to disk or k8s")
        logger.info("Initializing LangGraph agent...")
        langgraph_agent = LangGraphAgent(
            flink_client, k8s_client, postgres_reader, auto_remediator, slack_client,
            github_client=github_client,
        )
        logger.info("LangGraph agent ready")
    except EgressPolicyError:
        # Belt and braces: never downgrade a policy violation to a warning.
        raise
    except Exception as e:
        logger.error("Anthropic API key fetch failed — chat will be unavailable, all other features unaffected: %s", e)

    if postgres_enabled():
        try:
            await asyncio.to_thread(secret_provider.fetch_postgres_password)
            await postgres_reader.connect()
            logger.info("PostgreSQL connected (TLS enabled, password from secret provider)")
        except Exception as e:
            logger.warning("PostgreSQL connection failed (will retry): %s", e)
    else:
        logger.info("PostgreSQL disabled (set POSTGRES_ENABLED=true to enable)")

    # Fail-loud RBAC self-check: when write tools are enabled, verify the pod's own
    # identity actually has the cluster-mutate permissions the remediation path needs
    # (the name-scoped patch Role of the pod's own ServiceAccount, k8s/rbac.yaml; never flink-ai-debugger-role). This
    # surfaces a missing grant at startup instead of as a confusing 403 mid-remediation.
    # Best-effort and wrapped — it must never block startup.
    if write_tools_enabled():
        try:
            # Synchronous K8s API call (urllib3) — keep it off the event loop,
            # same idiom as the secret-provider fetches above.
            perms = await k8s_call(k8s_client.check_write_permissions)
            denied = [k for k, v in perms.items() if v is False]
            unknown = [k for k, v in perms.items() if v is None]
            if denied:
                logger.warning("Write tools enabled but Kubernetes RBAC denies required permission(s): %s — remediations will fail at runtime — grant RBAC or set ENABLE_WRITE_TOOLS=false", ", ".join(denied))
            if unknown:
                logger.warning("Write tools enabled but could not verify Kubernetes RBAC for: %s — SelfSubjectAccessReview returned no decision; remediations may fail at runtime", ", ".join(unknown))
            if perms and not denied and not unknown:
                logger.info("Write tools enabled — required cluster-mutate permissions present (granted to the pod's ServiceAccount): %s", ", ".join(perms.keys()))
        except Exception as e:
            logger.warning("RBAC write-permission self-check could not run: %s", e)

    # Kill-switch arming check (containment observability): the control fails
    # open by design, so a pod where it is inoperable must say so at startup —
    # not be discovered mid-incident. Three-valued on purpose: a present-but-
    # unreadable file must NOT be reported as 'released'. See
    # docs/AI_INCIDENT_RESPONSE.md.
    _ks_state = kill_switch_state()
    if _ks_state in ("engaged", "released"):
        logger.info("Runtime kill switch armed (file mounted; currently %s)", _ks_state)
    else:
        logger.warning(
            "Runtime kill switch NOT operable (state=%s) — the selective "
            "containment control cannot be engaged for this pod. Apply the "
            "namespace-wide flink-ai-debugger-kill-switch ConfigMap and mount it "
            "per the volume contract in docs/AI_INCIDENT_RESPONSE.md (or a "
            "per-deployment <deployment>-kill-switch ConfigMap); until then containment "
            "falls back to scale-to-zero/pod deletion.", _ks_state,
        )

    await metrics_collector.start_background_collection()

    # Start Grafana alert poller if SA token is configured
    if secret_provider.get_grafana_sa_token() and langgraph_agent:
        from app.grafana_poller import GrafanaAlertPoller
        alert_model = os.getenv("GRAFANA_ALERT_MODEL", "claude-opus-4-20250514")
        # alert_flow=True: alert-triggered agents never register the
        # cluster-mutating tools — the alert question's HARD CONSTRAINT is
        # enforced at tool registration, not only as prose.
        alert_agent = LangGraphAgent(flink_client, k8s_client, postgres_reader, auto_remediator, slack_client, model_override=alert_model, github_client=github_client, alert_flow=True)
        logger.info("Grafana alert poller using model: %s", alert_model)
        # Assigned to the MODULE global (declared above) — not a startup-local —
        # so shutdown_event() can reach it and actually stop the loop.
        grafana_poller = GrafanaAlertPoller(alert_agent, slack_client)
        await grafana_poller.start()

    logger.info("Flink AI Debugger started")


@_app.on_event("shutdown")
async def shutdown_event():
    # Stop the autonomous loop first: a SIGTERM must halt the poller (and any
    # in-flight alert analysis) before the process's other teardown, so the
    # "Grafana alert poller stopped" line lands in the termination logs.
    if grafana_poller is not None:
        await grafana_poller.stop()
    await metrics_collector.stop_background_collection()
    await postgres_reader.close()
    logger.info("Flink AI Debugger stopped")


# ── UI ───────────────────────────────────────────────────────────────

@_app.get("", response_class=HTMLResponse)
@_app.get("/", response_class=HTMLResponse)
@_app.get("/chat", response_class=HTMLResponse)
async def serve_ui():
    index_file = UI_DIR / "index.html"
    if not index_file.exists():
        raise HTTPException(status_code=404, detail="UI not found")
    content = index_file.read_text()
    # Anti-framing (clickjacking): frame-ancestors is ignored in a <meta> CSP,
    # so it is sent as a header, with X-Frame-Options for older browsers.
    return HTMLResponse(content=content, headers={
        "X-Frame-Options": "DENY",
        "Content-Security-Policy": "frame-ancestors 'none'",
    })


@_app.get("/favicon.png")
async def serve_favicon():
    favicon_file = UI_DIR / "favicon.png"
    if not favicon_file.exists():
        raise HTTPException(status_code=404, detail="Favicon not found")
    return Response(content=favicon_file.read_bytes(), media_type="image/png")


# ── Health & Status ──────────────────────────────────────────────────

@_app.get("/api/health")
async def health_check():
    """Process-liveness ONLY — no external dependencies (CWE-1088).

    Both container probes previously hit an endpoint that awaited Flink REST
    (aiohttp total=30s) and Postgres, so a slow dependency alone could blow the
    probe's 5s budget and restart the sidecar — destroying the in-memory
    remediation history and metrics deque. Liveness now proves the event loop
    is serving; dependency state lives on /api/ready.
    """
    return {
        "status": "healthy",
        "metrics_history_size": len(metrics_collector.metrics_history),
    }


@_app.get("/api/ready")
async def readiness_check():
    """Dependency status for the readiness probe and dashboards.

    Each check is bounded (2s) so this endpoint always answers within the
    probe's 5s budget even when a dependency blackholes connections. It always
    returns 200 with per-dependency status in the body: failing sidecar
    readiness on a dependency outage would remove the whole JobManager pod from
    Service endpoints (taking the Flink UI down with it). A stalled event loop
    still fails the probe via curl --max-time.
    """
    async def _bounded(coro, fallback):
        try:
            return await asyncio.wait_for(coro, timeout=2.0)
        except Exception:
            return fallback

    # Concurrently, not sequentially: run in series the two 2s-bounded checks
    # cost up to 4s, which overruns the probe budget on any dependency slowness.
    # Gathered, the endpoint's worst case is ~2s.
    job_id, pg_status = await asyncio.gather(
        _bounded(flink_client.get_running_job_id(), None),
        _bounded(
            postgres_reader.verify_tables_exist(),
            {"connected": False, "error": "unreachable or timed out"},
        ),
    )
    return {
        "status": "ready",
        "flink_connected": job_id is not None,
        "running_job_id": job_id,
        "postgres": pg_status,
        "metrics_history_size": len(metrics_collector.metrics_history),
    }


@_app.get("/api/job/status")
async def job_status(http_request: Request):
    _enforce_rate_limit(_read_rate_limiter, "job_status", http_request)
    job_id = await flink_client.get_running_job_id()
    audit("data_access", http_request, route="job_status")
    if not job_id:
        return {"status": "NO_JOB", "message": "No running Flink job found"}
    details = await flink_client.get_job_details(job_id)
    checkpoints = await flink_client.analyze_checkpoint_health(job_id)
    # Job and vertex names can carry job parameters; mask as for logs.
    return await asyncio.to_thread(redact_for_client, {
        "job_id": job_id,
        "status": details.get("state", "UNKNOWN"),
        "name": details.get("name", "N/A"),
        "start_time": details.get("start-time"),
        "vertices": [
            {
                "name": v.get("name"),
                "parallelism": v.get("parallelism"),
                "status": v.get("status"),
            }
            for v in details.get("vertices", [])
        ],
        "checkpoints": checkpoints,
    })


# ── AI Analysis ──────────────────────────────────────────────────────

# Single explicit budget for the total client-supplied model context: question
# plus every history message content, measured after normalization. The
# per-field caps below are inner bounds; without this total, 20 history entries
# of 20 000 chars would dwarf the question cap 80×.
#
# Over budget, the OLDEST history entries are dropped until the rest fits —
# the per-message caps (question 5000, content 20000) are still hard rejects,
# and since the question alone is always ≤ 5000 the trim always converges.
# Rejecting instead (the first cut of this control) 422'd the shipped UI: ten
# ordinary ~3 200-char answers exceed 30 000 and every later question failed
# until Clear. Mirrored by the
# UI's own pre-send trim (TOTAL_CONTEXT_BUDGET_CHARS in app/ui/index.html) —
# keep the three in sync (tests/test_untrusted_input_hygiene.py locks them).
TOTAL_CONTEXT_BUDGET_CHARS = 30000

# Zero-width, bidi-control, Unicode tag (U+E0000–E007F, the ASCII-smuggling
# range) and other invisible characters: stripped from all client-supplied
# model input — they render invisibly (or reorder rendering) while remaining
# fully model-visible, so they can smuggle instruction text past a human review.
_INVISIBLE_MODEL_INPUT_RE = re.compile(
    "[\u180e\u200b\u200c\u200d\u200e\u200f\u2060\u2061\u2062\u2063\u2064"
    "\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069"
    "\u3164\ufeff\uffa0\u00ad\U000e0000-\U000e007f]"
)


def _normalize_model_input(text: str) -> str:
    """NFKC-normalize and strip bidi/zero-width characters from client text
    before it reaches the model (CWE-20)."""
    text = unicodedata.normalize("NFKC", text)
    return _INVISIBLE_MODEL_INPUT_RE.sub("", text)


class HistoryMessage(BaseModel):
    role: str = Field(..., description="Must be 'user' or 'assistant'")
    content: str = Field(..., max_length=20000)

    @field_validator("role")
    @classmethod
    def role_must_be_valid(cls, v: str) -> str:
        if v not in ("user", "assistant"):
            raise ValueError("role must be 'user' or 'assistant'")
        return v

    @field_validator("content")
    @classmethod
    def normalize_content(cls, v: str) -> str:
        v = _normalize_model_input(v)
        # NFKC can EXPAND some sequences (ligatures, enclosed digits) past the
        # pre-validation max_length; re-enforce the cap on the normalized value.
        if len(v) > 20000:
            raise ValueError("content exceeds 20000 characters after normalization")
        return v


class QueryRequest(BaseModel):
    question: str = Field(..., max_length=5000)
    history: list[HistoryMessage] = Field(default=[], max_length=20)
    time_range_hours: int = 5

    @field_validator("question")
    @classmethod
    def normalize_question(cls, v: str) -> str:
        v = _normalize_model_input(v)
        # NFKC can EXPAND some sequences (ligatures, enclosed digits) past the
        # pre-validation max_length; re-enforce the cap on the normalized value.
        if len(v) > 5000:
            raise ValueError("question exceeds 5000 characters after normalization")
        return v

    # How many history entries the budget trim dropped (0 when none). Surfaced
    # in the ai_query audit event so a trimmed conversation is visible without
    # the client having to report it.
    _history_trimmed: int = PrivateAttr(default=0)

    @property
    def history_trimmed(self) -> int:
        return self._history_trimmed

    @model_validator(mode="after")
    def enforce_total_context_budget(self):
        """Drop the OLDEST history entries until question + history fits.

        Whole entries are dropped, never cut mid-message, so no turn changes
        meaning — the conversation just forgets its oldest exchanges, which is
        what a bounded chat window does anyway. A single over-cap field is
        still rejected by the per-field validators above; this only bounds the
        sum. The question is never trimmed, and its 5000 cap is below the
        budget, so the loop always terminates with a non-negative remainder.
        """
        total = len(self.question) + sum(len(m.content) for m in self.history)
        dropped = 0
        while total > TOTAL_CONTEXT_BUDGET_CHARS and self.history:
            total -= len(self.history[0].content)
            del self.history[0]
            dropped += 1
        if total > TOTAL_CONTEXT_BUDGET_CHARS:
            # Unreachable while the question cap is below the budget; kept so a
            # future cap change cannot silently reopen the total.
            raise ValueError(
                "question alone exceeds the "
                f"{TOTAL_CONTEXT_BUDGET_CHARS}-character context budget"
            )
        self._history_trimmed = dropped
        return self


@_app.post("/api/query")
async def ai_query(request: QueryRequest, http_request: Request):
    _enforce_rate_limit(_query_rate_limiter, "ai_query", http_request)
    new_correlation_id()  # bind before the entry audit event so it shares the chain id
    audit("ai_query", http_request, question=request.question,
          history_len=len(request.history), history_trimmed=request.history_trimmed,
          time_range_hours=request.time_range_hours)
    if langgraph_agent is None:
        raise HTTPException(status_code=503, detail="Agent not yet initialized — startup in progress")
    started = time.monotonic()
    try:
        history = [{"role": m.role, "content": m.content} for m in request.history]
        async with _agent_slot("ai_query"):
            result = await langgraph_agent.analyze(
                question=request.question,
                history=history,
            )
        tools_invoked = [s.get("tool") for s in (result.get("steps") or []) if s.get("type") == "tool_call"]
        # analyze() never raises — failures come back as a dict flagged
        # error=True — so derive the audited/telemetry status instead of
        # hardcoding "ok" (a swallowed outage must not be recorded as success).
        status = "error" if result.get("error") else "ok"
        # Prompt-leakage tripwire outcome (count-only), same fields the poller
        # records, so an interactive run whose answer was redacted or withheld
        # is visible in the audit trail without the answer text.
        leakage = result.get("leakage") or {}
        audit("ai_query_result", http_request, status=status,
              tools_invoked=tools_invoked, tool_calls_made=result.get("tool_calls_made"),
              leakage_redacted_spans=int(leakage.get("redacted_spans") or 0),
              leakage_withheld=bool(leakage.get("withheld")))
        telemetry.record_query(status, "sync", time.monotonic() - started)
        return result
    except HTTPException:
        # The 429 from _agent_slot is a deliberate load-shed signal — it must not
        # be relabelled as a 500 by the generic handler below.
        raise
    except Exception as e:
        logger.error("AI query failed: %s", e, exc_info=True)
        audit("ai_query_result", http_request, status="error")
        telemetry.record_query("error", "sync", time.monotonic() - started)
        raise HTTPException(status_code=500, detail="Internal analysis error")


@_app.post("/api/query/stream")
async def ai_query_stream(request: QueryRequest, http_request: Request):
    """Streaming version that sends Server-Sent Events for tool calls and partial results."""
    _enforce_rate_limit(_query_rate_limiter, "ai_query_stream", http_request)
    new_correlation_id()  # bind before the entry audit event so it shares the chain id
    audit("ai_query_stream", http_request, question=request.question,
          history_len=len(request.history), history_trimmed=request.history_trimmed,
          time_range_hours=request.time_range_hours)
    if langgraph_agent is None:
        async def _not_ready():
            yield f"data: {json.dumps({'type': 'error', 'error': 'Agent not yet initialized — startup in progress'})}\n\n"
        return StreamingResponse(_not_ready(), media_type="text/event-stream")

    # Same concurrency bound as /api/query. Acquired HERE, not inside the
    # generator, so saturation can still be signalled as a real 429 status —
    # once StreamingResponse is returned the status line is already committed.
    # Released in the generator's finally, which also runs on client disconnect.
    _slot = _agent_semaphore()
    if _slot.locked():
        logger.warning("Agent concurrency limit reached — rejecting ai_query_stream")
        raise HTTPException(
            status_code=429,
            detail="Too many concurrent analyses in progress. Please retry shortly.",
            headers={"Retry-After": "30"},
        )
    await _slot.acquire()

    async def event_generator():
        queue: asyncio.Queue = asyncio.Queue()

        async def _produce():
            tools_invoked = []
            saw_error = False
            leakage = {}
            started = time.monotonic()
            try:
                history = [{"role": m.role, "content": m.content} for m in request.history]
                await queue.put({'type': 'start', 'question': request.question})
                async for event in langgraph_agent.analyze_stream(
                    question=request.question,
                    history=history,
                ):
                    if event.get("type") == "tool_start":
                        tools_invoked.append(event.get("tool_name"))
                    if event.get("type") == "error":
                        # analyze_stream swallows agent failures and yields an
                        # error event, so this loop completes normally — track it
                        # or the failure is audited as ok.
                        saw_error = True
                    if event.get("type") == "result":
                        # Tripwire outcome rides on the final result event.
                        leakage = (event.get("data") or {}).get("leakage") or {}
                    await queue.put(event)
                status = "error" if saw_error else "ok"
                audit("ai_query_result", http_request, status=status, tools_invoked=tools_invoked,
                      leakage_redacted_spans=int(leakage.get("redacted_spans") or 0),
                      leakage_withheld=bool(leakage.get("withheld")))
                telemetry.record_query(status, "stream", time.monotonic() - started)
                await queue.put({'type': 'done'})
            except Exception as e:
                logger.error("AI streaming query failed: %s", e, exc_info=True)
                audit("ai_query_result", http_request, status="error", tools_invoked=tools_invoked)
                telemetry.record_query("error", "stream", time.monotonic() - started)
                await queue.put({'type': 'error', 'error': 'Internal analysis error'})
            finally:
                await queue.put(None)  # sentinel

        async def _heartbeat():
            # SSE comment every 20s keeps proxy idle timers (NGINX, Envoy, ...)
            # from closing the connection during long tool chains. Comment lines
            # are discarded by EventSource on the browser side.
            try:
                while True:
                    await asyncio.sleep(20)
                    await queue.put({'type': '__keepalive'})
            except asyncio.CancelledError:
                pass

        producer = asyncio.create_task(_produce())
        heartbeat_task = asyncio.create_task(_heartbeat())
        try:
            while True:
                event = await queue.get()
                if event is None:
                    break
                if event.get('type') == '__keepalive':
                    yield ": keepalive\n\n"
                else:
                    yield f"data: {json.dumps(event)}\n\n"
        finally:
            heartbeat_task.cancel()
            if not producer.done():
                producer.cancel()
            for t in (heartbeat_task, producer):
                try:
                    await t
                except (asyncio.CancelledError, Exception):
                    pass
            _slot.release()

    # X-Accel-Buffering: no tells NGINX (and any compatible proxy) not to buffer
    # this response. Without it, tool_start/tool_end events queue inside NGINX's
    # internal buffer and only flush on upstream close, so the user sees only
    # "Analyzing..." for the entire duration with no live tool progress. Also
    # required for the SSE heartbeat to actually keep idle timers alive.
    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "X-Accel-Buffering": "no",
            "Cache-Control": "no-cache",
        },
    )


# ── Diagnostics ──────────────────────────────────────────────────────

@_app.get("/api/diagnostics/full")
async def full_diagnostics(http_request: Request):
    _enforce_rate_limit(_heavy_rate_limiter, "full_diagnostics", http_request)
    job_id = await flink_client.get_running_job_id()
    if not job_id:
        return {"error": "No running Flink job found"}

    flink_diag = await flink_client.get_full_diagnostics(job_id)
    # Synchronous K8s API fan-out (urllib3) — keep it off the event loop.
    k8s_diag = await k8s_call(k8s_client.get_full_diagnostics)
    autoscaler_info = await postgres_reader.get_comprehensive_autoscaler_info(job_id)

    audit("data_access", http_request, route="full_diagnostics")
    # Job logs and job parameters can carry credentials; mask them the same way
    # the model-bound path does before they leave the pod (CWE-200/CWE-532).
    return await asyncio.to_thread(redact_for_client, {
        "job_id": job_id,
        "flink": flink_diag,
        "kubernetes": k8s_diag,
        "autoscaler": autoscaler_info,
    })


@_app.post("/api/diagnostics/thread-dump")
async def thread_dump(http_request: Request):
    # Tighter limit: thread dumps impose load on the monitored Flink job itself.
    _enforce_rate_limit(_heavy_rate_limiter, "thread_dump", http_request)
    result = await flink_client.analyze_thread_dumps()
    audit("data_access", http_request, route="thread_dump")
    # Thread names and stack frames can carry job parameters; mask as for logs.
    return await asyncio.to_thread(redact_for_client, result)


@_app.post("/api/diagnostics/skewness")
async def skewness_analysis(http_request: Request):
    # Tighter limit: skewness scans impose load on the monitored Flink job itself.
    _enforce_rate_limit(_heavy_rate_limiter, "skewness_analysis", http_request)
    job_id = await flink_client.get_running_job_id()
    if not job_id:
        raise HTTPException(status_code=404, detail="No running Flink job found")
    result = await flink_client.analyze_skewness(job_id)
    audit("data_access", http_request, route="skewness_analysis")
    return await asyncio.to_thread(redact_for_client, result)


@_app.get("/api/logs/{log_type}")
async def get_logs(log_type: str, http_request: Request):
    _enforce_rate_limit(_logs_rate_limiter, "get_logs", http_request)
    # KubernetesClient is synchronous (urllib3): each branch performs one or
    # more blocking pod-log reads (up to 5 sequential TaskManager reads), so run
    # them on a worker thread — a stalled event loop here previously blocked
    # /api/health and let the kubelet restart the sidecar (CWE-1088/CWE-400).
    if log_type == "operator":
        result = await k8s_call(k8s_client.get_operator_logs)
    elif log_type == "jobmanager":
        result = await k8s_call(k8s_client.get_flink_jobmanager_logs)
    elif log_type == "taskmanager":
        result = await k8s_call(k8s_client.get_flink_taskmanager_logs)
    else:
        # Static client message — do not reflect the caller-supplied value (CWE-209).
        # The rejected value is recorded server-side only, for probing visibility.
        audit("logs_type_rejected", http_request, requested_type=log_type)
        raise HTTPException(status_code=400, detail="Invalid log type")
    audit("data_access", http_request, route="get_logs", log_type=log_type)
    # Pod logs can carry credentials printed by the job; mask them before they
    # leave the pod, as the model-bound path already does (CWE-532). Off the
    # event loop: the pass over a large log takes a few hundred ms.
    return await asyncio.to_thread(redact_for_client, result)


# ── Autoscaler ───────────────────────────────────────────────────────

@_app.get("/api/autoscaler/events")
async def autoscaler_events(
    http_request: Request,
    hours: int = Query(default=24, ge=1, le=168),
):
    _enforce_rate_limit(_read_rate_limiter, "autoscaler_events", http_request)
    audit("data_access", http_request, route="autoscaler_events", hours=hours)
    job_id = await flink_client.get_running_job_id()
    if not job_id:
        return {"events": [], "message": "No running job"}
    events = await postgres_reader.get_autoscaler_events(job_id, hours=hours)
    return await asyncio.to_thread(redact_for_client, {"events": events, "count": len(events)})


@_app.get("/api/autoscaler/errors")
async def autoscaler_errors(
    http_request: Request,
    hours: int = Query(default=24, ge=1, le=168),
):
    _enforce_rate_limit(_read_rate_limiter, "autoscaler_errors", http_request)
    audit("data_access", http_request, route="autoscaler_errors", hours=hours)
    job_id = await flink_client.get_running_job_id()
    if not job_id:
        return {"errors": [], "message": "No running job"}
    errors = await postgres_reader.get_autoscaler_errors(job_id, hours=hours)
    return await asyncio.to_thread(redact_for_client, {"errors": errors, "count": len(errors)})


@_app.get("/api/autoscaler/status")
async def autoscaler_status(http_request: Request):
    _enforce_rate_limit(_read_rate_limiter, "autoscaler_status", http_request)
    audit("data_access", http_request, route="autoscaler_status")
    tables = await postgres_reader.verify_tables_exist()
    stats = await postgres_reader.get_table_statistics()
    return await asyncio.to_thread(redact_for_client, {"tables": tables, "statistics": stats})


# ── Auto-Remediation ────────────────────────────────────────────────

# `applied_by` is deliberately NOT a request field: it records the trigger path
# (chat / REST / alert / system), never the human user — see app/audit.py's module
# docstring on identity. Per-user attribution is not available in-pod (the SSO proxy
# forwards no identity header downstream), so a caller-supplied value could only ever
# fabricate a human-looking name inside an otherwise-anonymous audit record; the
# trustworthy attribution remains the audit event's right-indexed source_ip. The route
# below sets the constant "rest", matching the other trigger paths ("ai_agent_chat",
# "system"); an `applied_by` key in the request body is ignored (pydantic drops
# unknown fields) so it can never influence the audit trail or remediation history.
class RemediationRequest(BaseModel):
    type: str
    # Omission previews, same as the agent tool: a body without dry_run must not
    # fire a savepoint + CR patch. Callers that mean it send "dry_run": false.
    # (Every in-repo caller already passes the flag explicitly; the earlier
    # "keep False for existing clients" rationale had no such client.)
    dry_run: bool = True


_HALTED_DETAIL = "Operator kill switch is engaged — write operations are halted"


def _deny_if_halted(http_request: Request, **fields) -> None:
    """Runtime kill switch check for the REST write routes.

    Evaluated per request, here at the route, rather than inside
    write_tools_enabled(): that gate is also consulted at agent construction,
    where a halt would be baked into the compiled graph and outlive the
    operator's release. The denial is audited under its own event name so a
    responder can tell containment (agent_halted) from an authorization denial
    (remediation_denied / write_tools_disabled) in the audit stream.
    """
    if agent_halted():
        audit("agent_halted", http_request, **fields)
        raise HTTPException(status_code=403, detail=_HALTED_DETAIL)


@_app.post("/api/remediation/apply")
async def apply_remediation(request: RemediationRequest, http_request: Request):
    # A live apply takes a savepoint and patches the job: bound it like the other
    # routes that load the monitored job (CWE-770).
    _enforce_rate_limit(_heavy_rate_limiter, "remediation_apply", http_request)
    new_correlation_id()  # bind before the first audit event so denial, rejection and result share the chain id
    # Operator kill switch first: containment wins over everything else,
    # including a deployment that has write tools legitimately enabled.
    _deny_if_halted(http_request, route="apply", requested_type=request.type)
    # Same gate as the agent's write tools: this REST path reaches the same
    # cluster-mutating remediation, so it must honor the write-authz check too.
    if not write_tools_enabled():
        # The write-authz decision is the most security-relevant one this service
        # makes; record the denial the same way the adjacent rejections are
        # recorded — an unaudited authorization decision is invisible to an
        # incident responder (probing of this endpoint left no trace).
        audit("remediation_denied", http_request, reason="write_tools_disabled",
              requested_type=request.type)
        raise HTTPException(status_code=403, detail="Write operations are disabled")
    try:
        rtype = RemediationType(request.type)
    except ValueError:
        # Static client message — do not reflect the caller-supplied value or enumerate
        # the valid types (CWE-209). The rejected value is recorded server-side only.
        audit("remediation_type_rejected", http_request, requested_type=request.type)
        raise HTTPException(status_code=400, detail="Invalid remediation type")

    action = auto_remediator.create_action(rtype)
    result = await auto_remediator.apply_remediation(
        action, applied_by="rest", dry_run=request.dry_run
    )
    audit_remediation(result, http_request)
    return result.to_dict()


@_app.get("/api/remediation/history")
async def remediation_history(http_request: Request):
    audit("data_access", http_request, route="remediation_history")
    return {"history": auto_remediator.get_history()}


_ROLLBACK_INDEX_REMOVED = (
    "'index' is no longer accepted: POST the stable 'id' of the entry from "
    "GET /api/remediation/history (history[].id). Positions in that list shift "
    "once the bounded history starts evicting, so an index could target the "
    "wrong remediation."
)


class RollbackRequest(BaseModel):
    # The value is the stable ``id`` that GET /api/remediation/history returns
    # for each entry, NOT a position in that list: history is a bounded deque
    #, so a position changes meaning once eviction starts while
    # the id does not. The pre-bound positional ``index`` key is REJECTED, not
    # aliased: aliasing it to ``id`` made an old-contract ``{"index": 60}``
    # after eviction roll back id 60 (a different entry) with success: true.
    id: int

    @model_validator(mode="before")
    @classmethod
    def _reject_positional_index(cls, data):
        # Fires whether ``index`` arrives alone or beside ``id`` — an ambiguous
        # body must not be resolved silently either way.
        if isinstance(data, dict) and "index" in data:
            raise ValueError(_ROLLBACK_INDEX_REMOVED)
        return data


@_app.post("/api/remediation/rollback")
async def rollback_remediation(request: RollbackRequest, http_request: Request):
    _enforce_rate_limit(_heavy_rate_limiter, "remediation_rollback", http_request)
    new_correlation_id()  # bind before the audit event so it shares the chain id
    _deny_if_halted(http_request, route="rollback", id=request.id)
    # Same gate as /api/remediation/apply. auto_remediator.rollback() is a pure
    # history lookup today, but the route's name promises a mutation and the
    # authorization decision belongs here at the route — it must not depend on
    # the implementation staying a lookup. Denials are audited like the sibling
    # route's: an unaudited authorization decision is invisible to an incident
    # responder.
    if not write_tools_enabled():
        audit("remediation_denied", http_request, reason="write_tools_disabled",
              requested_action="rollback", id=request.id)
        raise HTTPException(status_code=403, detail="Write operations are disabled")
    result = await auto_remediator.rollback(request.id)
    success = result.get("success") if isinstance(result, dict) else None
    audit("rollback_lookup", http_request, id=request.id, success=success)
    return result


# ── Human approval of agent-proposed writes ─────────────────────────────────
# The agent's cluster-mutating tools only PROPOSE (app/write_proposals.py).
# These routes are the human step: the model has no tool for them and never
# sees a proposal id. Same gates as /api/remediation/apply: rate limit, kill
# switch, write gate; the cross-site POST guard keeps another site's page out.


class ProposalDecision(BaseModel):
    proposal_id: str = Field(..., min_length=1, max_length=128)


def _proposal_gates(http_request: Request, route: str) -> None:
    _enforce_rate_limit(_heavy_rate_limiter, f"remediation_{route}", http_request)
    new_correlation_id()
    _deny_if_halted(http_request, route=route)
    if not write_tools_enabled():
        audit("remediation_denied", http_request, reason="write_tools_disabled",
              requested_action=route)
        raise HTTPException(status_code=403, detail="Write operations are disabled")


@_app.post("/api/remediation/approve")
async def approve_proposal(request: ProposalDecision, http_request: Request):
    _proposal_gates(http_request, "approve")
    ref = write_proposals.proposal_ref(request.proposal_id)
    proposal = write_proposals.take(request.proposal_id)
    if proposal is None:
        audit("write_approve_rejected", http_request, proposal_ref=ref, reason="unknown_or_expired")
        raise HTTPException(status_code=404, detail="Unknown or expired proposal")
    action, args = proposal["action"], proposal["args"]
    if action == "update_flink_config":
        result = await k8s_call(k8s_client.patch_flink_config, args)
        ok = bool(isinstance(result, dict) and result.get("success"))
        # patch_flink_config reports failure as {"error": ...}: audit the real result.
        audit("config_update", http_request, config_key=",".join(sorted(args)), success=ok,
              error=None if ok else (result or {}).get("error"), applied_by="approved_chat")
    elif action == "restart_flink_job":
        result = await k8s_call(k8s_client.restart_flink_job)
        ok = bool(isinstance(result, dict) and result.get("success"))
        audit("job_restart", http_request, success=ok,
              error=None if ok else (result or {}).get("error"), applied_by="approved_chat")
    elif action == "apply_remediation":
        remediation = auto_remediator.create_action(RemediationType(args["type"]))
        outcome = await auto_remediator.apply_remediation(
            remediation, applied_by="approved_chat", dry_run=False)
        audit_remediation(outcome, http_request)
        result = outcome.to_dict()
        ok = bool(outcome.success)
    elif action == "create_github_pr":
        # Path rules, pinned repo and the daily cap are re-checked at execution.
        result = await execute_approved_pr(github_client, args)
        ok = bool(isinstance(result, dict) and result.get("success"))
    else:
        audit("write_approve_rejected", http_request, proposal_ref=ref, reason="unsupported_action")
        raise HTTPException(status_code=400, detail="Unsupported proposal")
    audit("write_approved", http_request, action=action, proposal_ref=ref, success=ok)
    return result


@_app.get("/api/remediation/pending")
async def pending_proposals(http_request: Request):
    """Proposals awaiting a decision, for runs with no chat to show them in
    (alert-triggered analyses). Same gates as approve / reject."""
    _proposal_gates(http_request, "pending")
    audit("data_access", http_request, route="remediation_pending")
    return {"pending": write_proposals.pending()}


@_app.post("/api/remediation/reject")
async def reject_proposal(request: ProposalDecision, http_request: Request):
    _proposal_gates(http_request, "reject")
    ref = write_proposals.proposal_ref(request.proposal_id)
    proposal = write_proposals.take(request.proposal_id)
    if proposal is None:
        audit("write_reject_unknown", http_request, proposal_ref=ref)
        raise HTTPException(status_code=404, detail="Unknown or expired proposal")
    audit("write_rejected", http_request, action=proposal["action"], proposal_ref=ref)
    return {"success": True, "rejected": True, "action": proposal["action"]}


# ── Grafana Alert Polling ───────────────────────────────────────────────
# The AI debugger polls Grafana's alerting API for firing alerts
# matching this Flink deployment (by job or flink_deployment label).
# See app/grafana_poller.py for the polling implementation.
# The poller starts automatically when GRAFANA_URL and GRAFANA_SA_TOKEN are set.


# ── Metrics ──────────────────────────────────────────────────────────

@_app.get("/api/metrics/timeseries")
async def metrics_timeseries(http_request: Request, hours: int = Query(default=1, ge=1, le=6)):
    audit("data_access", http_request, route="metrics_timeseries", hours=hours)
    return await asyncio.to_thread(
        redact_for_client, {"data": metrics_collector.get_time_series(hours=hours)})



# ── Main ─────────────────────────────────────────────────────────────

def resolve_bind_host() -> str:
    """Resolve the uvicorn bind address.

    Bind loopback unconditionally so :8765 is not on the pod's routable interface and
    is unreachable cross-pod (the loopback bind stands in place of a NetworkPolicy,
    and the API behind it performs no authorization of its own). Loopback is NOT a
    boundary between containers in the same pod: flink-main-container shares the pod
    network namespace and can reach this port. Your authenticating reverse proxy (not
    part of the example manifest) should also call over 127.0.0.1.

    HOST is honored only when ALLOW_NON_LOOPBACK_BIND=true is ALSO set, so undoing the
    loopback control requires a second, explicitly named variable and emits a loud
    warning — a deliberate, visible act instead of a silent one-variable regression.
    Debug use only; never set it in a deployed manifest.

    A non-loopback HOST WITHOUT the opt-in is ignored, and that is logged as a WARNING
    too: an operator who set HOST and sees the pod bind 127.0.0.1 should find the reason
    in the startup log instead of debugging a silent no-op. The warning names the variable, never any other setting.
    """
    if os.getenv("ALLOW_NON_LOOPBACK_BIND", "").strip().lower() == "true":
        host = os.getenv("HOST", "127.0.0.1")
        logger.warning(
            "ALLOW_NON_LOOPBACK_BIND=true: binding %s. The debugger API performs no "
            "authorization of its own and no NetworkPolicy is deployed. Debug only.",
            host,
        )
        return host
    requested = os.getenv("HOST", "").strip()
    if requested and requested not in _LOOPBACK_HOSTS:
        logger.warning(
            "HOST=%s had no effect: binding 127.0.0.1. HOST is honored only together with "
            "ALLOW_NON_LOOPBACK_BIND=true, because the loopback bind is the cross-pod "
            "reachability control for an API that performs no authorization of its own. "
            "Set ALLOW_NON_LOOPBACK_BIND=true as well (debug only) if a non-loopback bind "
            "is really intended.",
            requested,
        )
    return "127.0.0.1"


# HOST values that are already loopback and therefore not a request the opt-in would change.
_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1", "[::1]"})


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", "8765"))
    host = resolve_bind_host()
    uvicorn.run(app, host=host, port=port, log_level="info")
