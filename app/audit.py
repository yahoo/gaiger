# Copyright Yahoo, Licensed under the terms of the Apache 2.0 license. See LICENSE for terms.

"""Structured audit logging for the AI debugger.

Emits one JSON object per line on a dedicated ``app.audit`` logger so the cluster
log pipeline captures a durable, queryable audit trail of every AI query, tool
call, and remediation. No PostgreSQL: the debugger is read-only to it and it is
optional in the sidecar, so stdout -> your log backend is the durable store. Any
cluster log collector (e.g. an OTel Collector or Fluent Bit DaemonSet) that ships
container stdout to your log backend is sufficient; no per-pod log sidecar is
required. See docs/MONITORING.md ("Audit trail") for the event catalogue, query
and retention guidance.

Identity: the authenticating reverse proxy in front of this pod typically
authenticates the user but forwards no identity header downstream (only
X-Forwarded-* headers and, optionally, an mTLS service cert). So per-user
attribution is not available to the sidecar; we record the source IP and the
auth path the service actually OBSERVED (see ``_observed_auth`` -- never an
asserted literal). Capturing the human identity would require the proxy to
forward an identity header and is out of scope here.

Source IP: every proxy in your ingress / authenticating reverse-proxy chain
(edge load balancer -> SSO gateway -> per-pod reverse proxy) *appends* to
X-Forwarded-For and none strips client-supplied entries, so the leftmost XFF
entry is attacker-spoofable. The trustworthy client IP is the one the trusted
edge recorded, at a fixed offset from the right of the chain
(AUDIT_TRUSTED_PROXY_HOPS, default 0: the header is ignored until the
operator sets the hop count); reading right-indexed defeats spoofing
because an attacker can only prepend on the left. When the chain is shorter
than the trusted depth (dev / port-forward, never the production chain) there
is no edge-recorded entry to trust, so source_ip is recorded as "untrusted"
rather than a caller-chosen value. The chain is retained in each record
(``forwarded_for``) for forensic verification -- sanitized like any untrusted
field (truncated and masked), never verbatim-unbounded.
"""
import itertools
import json
import logging
import os
import re
import sys
import uuid
from contextvars import ContextVar
from datetime import datetime, timezone
from typing import Any, Optional

# Dedicated audit channel: JSON-only lines on stdout, kept separate from the
# app's prefixed logging.basicConfig format so each line is independently
# parseable by the log pipeline.
_audit_logger = logging.getLogger("app.audit")

# Monotonic per-process audit sequence number: without it, "no audit events in
# this window" is indistinguishable from "the pipeline dropped them". itertools
# .count is implemented in C, so next() on it is a single bytecode and is safe
# across the event loop's tasks without a lock. Restarts reset it to 1 —
# intended: (pod start time, seq) is what makes a gap detectable; a seq
# discontinuity within one process lifetime means dropped audit records.
_seq = itertools.count(1)

# Per-process instance id: makes seq gap detection self-contained. seq resets to
# 1 on each process start, and multiple replicas (or a future standalone
# Deployment) would otherwise interleave seq=1,2,3... into one log index,
# producing false gaps or masking real ones. Partition by (instance, seq) — no
# reliance on the OTel collector injecting pod identity into the envelope.
_instance = uuid.uuid4().hex[:12]

# Correlation ID: links the ai_query event to the tool-call / remediation events
# it spawns. The agent's tools run as closures with no request object, so the
# source IP is only captured on the originating query event; without a shared id
# the tool events can only be tied back by timestamp inference. We bind one id
# into the async context (ContextVar) at the start of each flow — the API boundary
# for HTTP queries, the alert handler for the Grafana poller — so the flow's entry
# event shares the id; create_task copies the context, so the agent's downstream
# tool calls inherit it. The agent entry points (analyze / analyze_stream) call
# ensure_correlation_id() as a backstop, so a caller that forgets to bind still
# gets a correlated tool-call chain.
_correlation_id: ContextVar[Optional[str]] = ContextVar("audit_correlation_id", default=None)


def new_correlation_id() -> str:
    """Generate a correlation id, bind it to the current async context, and return it.

    Call once at the start of each flow — request handler or alert handler — BEFORE
    its first audit event, so the entry event and every event emitted afterwards
    (including agent tool calls) share the same id.
    """
    cid = uuid.uuid4().hex
    _correlation_id.set(cid)
    return cid


def ensure_correlation_id() -> str:
    """Correlation id bound to this async context, binding a new one if absent.

    Called by the agent entry points so every tool-call chain is correlated even
    when the caller didn't bind an id first.
    """
    return get_correlation_id() or new_correlation_id()


def get_correlation_id() -> Optional[str]:
    """Correlation id bound to the current async context, or None if unset."""
    return _correlation_id.get()


# Marker on the stdout handler this module owns, so "already configured" is
# decided by the presence of OUR handler — not by the logger having any handler
# at all. A foreign handler attached first (a test capture handler, a future
# in-process log shipper) must never suppress configuration.
_OWN_HANDLER_MARK = "_flink_ai_debugger_audit_stdout"


def _configure() -> logging.Logger:
    # Level and propagate are idempotent — set them unconditionally. Gating them
    # behind "no handlers yet" left the logger at NOTSET (inheriting the root
    # WARNING threshold, so every INFO audit record was dropped) whenever
    # anything else touched the "app.audit" logger before this import ran.
    _audit_logger.setLevel(logging.INFO)
    _audit_logger.propagate = False  # avoid double-emit via the root formatter
    if not any(getattr(h, _OWN_HANDLER_MARK, False) for h in _audit_logger.handlers):
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(logging.Formatter("%(message)s"))
        setattr(handler, _OWN_HANDLER_MARK, True)
        _audit_logger.addHandler(handler)
    return _audit_logger


_configure()


def _trusted_proxy_hops() -> int:
    """The number of proxies in front of this pod that append to X-Forwarded-For.

    Default 0: X-Forwarded-For is IGNORED and the socket peer is recorded, so a
    caller cannot choose its own audit source_ip or rate-limit key. Set it to the
    real depth of your proxy chain (e.g. 1 for one pod-local reverse proxy, 3 for
    edge LB -> SSO gateway -> pod-local proxy); the client IP is then read that
    many entries from the right. Invalid values fall back to 0."""
    try:
        return min(max(0, int(os.getenv("AUDIT_TRUSTED_PROXY_HOPS", "0"))), _MAX_TRUSTED_HOPS)
    except ValueError:
        return 0


def client_ip(request: Optional[Any]) -> str:
    """Trustworthy source IP from X-Forwarded-For, which is off by default.

    With AUDIT_TRUSTED_PROXY_HOPS unset or 0 the header is ignored and the
    immediate peer is recorded.

    The front-door proxy chain (edge LB -> SSO gateway -> in-pod proxy) appends to XFF and
    never strips client-supplied entries, so the leftmost entry is spoofable. The
    real client IP is the one the trusted edge recorded, at a fixed offset from the
    right (``_trusted_proxy_hops()``); reading right-indexed defeats spoofing
    because an attacker can only prepend entries on the left. When the chain is
    shorter than the trusted depth (dev / port-forward) there is no trustworthy
    entry, so this fails closed to "untrusted" (CWE-290). With no XFF header at
    all it falls back to the immediate peer, then "unknown"."""
    if request is None:
        return "unknown"
    try:
        hops = _trusted_proxy_hops()
        xff = request.headers.get("x-forwarded-for") if hops > 0 else None
        if xff:
            parts = [p.strip() for p in xff.split(",") if p.strip()]
            if parts:
                if len(parts) >= hops:
                    return parts[-hops]
                # Shorter than the trusted depth (only reached off the production
                # chain — dev / kubectl port-forward): there is NO edge-recorded
                # entry to trust, and the leftmost entry is fully caller-supplied.
                # source_ip is the only attribution this record carries (actor is
                # always "anonymous"), so fail closed and record that we do not
                # know it rather than a value the caller chose (CWE-290).
                return "untrusted"
        client = getattr(request, "client", None)
        return client.host if client else "unknown"
    except Exception:  # never let header parsing break a request
        return "unknown"


def _observed_auth(request: Optional[Any]) -> str:
    """The auth path this service actually OBSERVED for the caller.

    - ``"none"``    — no HTTP request exists (Grafana poller / internal caller).
    - ``"unknown"`` — an HTTP request arrived, but nothing in it lets the sidecar
      verify it came through the authenticating front door.

    Deliberately NOT derived from X-Forwarded-For in any form: no proxy in the
    chain strips client-supplied entries (see module docstring), so both the
    header's presence and its hop count are forgeable by exactly the caller this
    field exists to distinguish. The only trustworthy signal would be a header
    the pod-local reverse proxy injects and the client cannot supply; when that marker
    exists, this helper is where it gets observed and reported. Until then the
    field never asserts "sso-gated": that was true only for gateway traffic yet
    was stamped on every record, including loopback and port-forward callers.
    """
    return "none" if request is None else "unknown"


def _raw_forwarded_for(request: Optional[Any]) -> Optional[str]:
    """Raw X-Forwarded-For header, kept for forensic chain reconstruction."""
    if request is None:
        return None
    try:
        return request.headers.get("x-forwarded-for")
    except Exception:
        return None


# ── Redaction (CWE-532): keep sensitive data out of the durable audit sink ──
# The audit line is the permanent record (stdout -> log collector -> log backend), so anything
# written verbatim is a lasting exposure. Redaction lives HERE, at the single emit
# choke point, so no individual call site can reintroduce a leak by passing a new
# free-text field. Policy is a FAIL-SAFE ALLOWLIST: known-structured fields pass
# through untouched (preserving forensic byte-stability and the log-backend correlation
# join); every other field — including any future one — is treated as untrusted and
# sanitized. Secrets and structured PII (which have recognisable shapes) are masked;
# unstructured prose PII (names, free-text context) cannot be pattern-matched and is
# a deliberately accepted residual risk (truncation only).

_MAX_TRUSTED_HOPS = 10          # ceiling on AUDIT_TRUSTED_PROXY_HOPS
_MAX_FIELD_CHARS = 2048         # truncate free-text before masking (bounds regex cost)
_MAX_REDACT_DEPTH = 6           # recursion guard for nested dict / list values

# Fields whose VALUES are infra-set or structured and safe to record verbatim —
# exempt from BOTH truncation and masking so forensic values stay byte-stable
# (source_ip, correlation_id, savepoint_id, numeric counters) and log-backend
# joins/filters keep working. forwarded_for is deliberately NOT allowlisted: the
# raw X-Forwarded-For header is caller-controlled, so it goes through
# _safe_sanitize like any untrusted field (truncated at _MAX_FIELD_CHARS and
# masked) -- still available for forensic chain reconstruction, but it can no
# longer be unbounded or carry an injected payload into the JSON channel.
# Anything NOT listed is sanitized;
# that default is what makes the over-logging class non-reintroducible. Model- or
# user-controlled fields are deliberately ABSENT so they are always sanitized —
# question, config_value, config_key, tools_invoked, channel, title, error — as is
# changes_made (so its nested values are walked). Sanitizing a legitimate structured
# value (a Flink key, a tool name, a channel) leaves it unchanged, so the only effect
# is to mask one that unexpectedly carries a secret/PII (e.g. an arg-inverted key).
_ALLOWLIST_FIELDS = frozenset({
    "event", "ts", "seq", "instance", "classification", "source_ip", "auth",
    "actor", "correlation_id",
    "status", "success", "dry_run", "history_len", "time_range_hours",
    "tool_calls_made", "message_len",
    "remediation_type", "applied_by", "savepoint_id", "id",
    # answer_sha256 is computed in-code (hex digest of the agent completion) and
    # must stay byte-stable for log-backend joins — a digest with a long digit tail
    # would otherwise be mangled by the CC digit-run mask.
    "answer_sha256",
})

# Ordered: value-bearing key=value secrets first, then shaped tokens, then PII.
# The first _SECRET_ONLY_COUNT entries are credential-shaped (key=value secrets,
# URL userinfo, bearer/JWT/vendor tokens); the remainder are structured PII
# (email, SSN, card-number digit runs). The audit sink applies all of them. The
# model-bound egress path applies only the credential-shaped ones: tool results
# are Flink/K8s payloads where the PII shapes match operational data (RPC
# addresses like flink@jobmanager.ns.svc, epoch-millis timestamps, state sizes)
# and would corrupt what the model reasons over without protecting anything.
_SECRET_KEYWORD = r"(?:password|passwd|secret|token|api[_-]?key|apikey|authorization|jaas)"
# Key segments that REFERENCE a credential rather than carry one (mirrors
# _KEY_REFERENCE_TAILS below): `token_count=12`, `password_file=/run/x` and
# `secret_name=creds` are not secrets and must not be masked.
_SECRET_KEY_TAIL = r"(?:name|ref|file|path|id|enabled|count|type)"
# key=value / key: value where the KEY is a segmented identifier containing a
# credential keyword. The original `\b(keyword)\b` boundary never matched
# underscore-joined names — `DB_PASSWORD=...`, `AWS_SECRET_ACCESS_KEY=...`,
# `GITHUB_TOKEN=...`, `client_secret=...` all passed through unchanged, because
# `_` is a word character and so there is no `\b` between it and the keyword.
# The key is now: [prefix segments][keyword][suffix segments], each segment
# joined by `_ . -`, anchored on a non-alphanumeric character at both ends.
# The keyword itself must end a segment, so `passwordless_login=` (keyword
# followed by more letters) is not a key, and no suffix segment may be a
# reference tail, so `token_count=` is not one either.
#
# Two round-3 review corrections:
# - The VALUE may be an HTTP auth scheme plus its credential (`Authorization:
#   Bearer <token>`, `Authorization: Basic <b64>`). The value previously stopped
#   at whitespace, so only the scheme word was masked and the token itself
#   survived (`Authorization: <REDACTED:secret> opaque0123...`). The scheme form
#   is tried first so the whole `Bearer <token>` is consumed as one value.
# - The prefix / suffix segment repeats are BOUNDED (`{0,8}`). Unbounded and
#   lazy, the prefix made the pattern quadratic on separator-dense text with no
#   keyword (`"ab_" * 3000` cost ~550 ms, 36 KB ~9 s per leaf) because every
#   segment boundary restarted a scan that could extend to the end of the text.
#   Eight segments cover every real key shape (`AWS_SECRET_ACCESS_KEY`,
#   `spring.datasource.hikari.password`) while bounding each start position to
#   a constant amount of work. The model path also caps leaf length before the
#   regex runs (egress_governance._redact_leaves).
#
# Round-4 review corrections:
# - Quotes: the key's closing quote and the value's opening quote accepted only
#   `"`, while the value class already excluded `'`, so a single-quoted value
#   could never match at all — `PlainLoginModule required username='alice'
#   password='hunter2';` (the Kafka JAAS string), `export DB_PASSWORD='hunter2'`
#   and `'password': 'x'` (Python repr) passed unchanged. Both quote slots are
#   now a `["']` class. A matching-quote backreference was considered and
#   rejected: the value class excludes both quote characters, so the value
#   already stops at whichever quote closes it, and a plain class keeps the
#   pattern backtracking-free (the timing test below guards this).
# - `-D` JVM system properties: `-Dpassword=hunter2` never matched, quoted or
#   not, because `D` is alphanumeric and defeats the key's leading boundary.
#   The boundary now also accepts a `-D` prefix (lookbehind, so `-D` itself is
#   not part of the key and is preserved in the output).
# - The auth-scheme separator is `[ \t]+`, not `\s+`: `Authorization: Bearer`
#   at the end of a line must not consume the first token of the next line
#   as its credential.
_SECRET_KV_SEGMENT_LIMIT = 8
_SECRET_KV_RE = re.compile(
    r"(?i)(?:(?<![A-Za-z0-9])|(?<=-D))"          # key boundary, or a JVM -D property prefix
    r"((?:[A-Za-z0-9]+[_.\-]){0," + str(_SECRET_KV_SEGMENT_LIMIT) + r"}?"   # DB_  aws.secret.  client_
    + _SECRET_KEYWORD +
    r"(?:[_.\-](?!" + _SECRET_KEY_TAIL + r"(?![A-Za-z0-9]))[A-Za-z0-9]+)"    # _ACCESS_KEY, not _count
    r"{0," + str(_SECRET_KV_SEGMENT_LIMIT) + r"})"
    r"(?![A-Za-z0-9])"
    r"([\"']?\s*[=:]\s*)([\"']?)"                 # optional quotes: `"password": "x"`, `'password': 'x'`, `password='x'`
    r"((?:bearer|basic)[ \t]+[^\s,\"';]{1,512}"   # scheme + credential consumed as ONE value (same line only)
    r"|[^\s,\"';]{1,256})"
)

_SECRET_PATTERNS = [
    (_SECRET_KV_RE, r"\1\2\3<REDACTED:secret>"),
    # user:password@host embedded in a URL — mask the whole userinfo (before email,
    # so the password isn't only caught coincidentally as part of an email match)
    (re.compile(r"(?i)(https?://)[^:@\s/]{1,256}:[^@\s/]{1,256}@"), r"\1<REDACTED:url-auth>@"),
    (re.compile(r"(?i)\bbearer[ \t]+[A-Za-z0-9._\-]{8,512}"), "Bearer <REDACTED:token>"),
    # HTTP Basic credential without its header name (a pasted header value, a
    # curl -H fragment): base64 of `user:password`, so `+ / =` are in-alphabet.
    # The token must carry a digit or a base64 symbol so that prose such as
    # "Basic Authentication failed" in a log line is not rewritten. Scheme and
    # credential must sit on ONE line ([ \t]+, not \s+), as for the key=value rule.
    (re.compile(r"(?i)\bbasic[ \t]+(?=[A-Za-z0-9+/]*[0-9+/=])[A-Za-z0-9+/]{8,512}={0,2}(?![A-Za-z0-9+/=])"),
     "Basic <REDACTED:token>"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "<REDACTED:aws_key>"),
    (re.compile(r"\b(?:sk-[A-Za-z0-9\-]{10,256}|ghp_[A-Za-z0-9]{20,256}|xox[baprs]-[A-Za-z0-9\-]{8,256})\b"),
     "<REDACTED:token>"),
    # bare JWT (no "bearer" prefix): three base64url segments; "eyJ" = base64url('{"')
    (re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{8,}"), "<REDACTED:jwt>"),
    # ---- structured PII below this line (audit sink only) ----
    (re.compile(r"[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,255}\.[A-Za-z]{2,24}"), "<REDACTED:email>"),
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "<REDACTED:ssn>"),
    (re.compile(r"\b(?:\d[ \-]?){13,19}\b"), "<REDACTED:cc>"),
]


_SECRET_ONLY_COUNT = next(
    i for i, (_, repl) in enumerate(_SECRET_PATTERNS) if repl == "<REDACTED:email>"
)


def redact_secrets(text: str) -> str:
    """Apply the secret / structured-PII masking patterns WITHOUT the audit-field
    truncation. Used by the audit sink (via _scrub_text)."""
    for pattern, repl in _SECRET_PATTERNS:
        text = pattern.sub(repl, text)
    return text


# Every credential pattern above requires one of these substrings, so a string
# without any of them cannot match and the six passes can be skipped. Cheap
# prefilter for the model-bound path, which walks thousands of small leaves.
_CREDENTIAL_TRIGGER_RE = re.compile(
    r"(?i)password|passwd|secret|token|api[_-]?key|apikey|authorization|jaas"
    r"|://|bearer|basic|AKIA|sk-|ghp_|xox[baprs]-|eyJ"
)


def redact_credentials(text: str) -> str:
    """Credential-shaped patterns only (no email / SSN / card-number masking).
    Used by the model-bound egress path (app.egress_governance.truncate_for_model):
    tool results must stay faithful operational data for the model, so only
    material that is a secret in ANY context is masked there."""
    if not _CREDENTIAL_TRIGGER_RE.search(text):
        return text
    for pattern, repl in _SECRET_PATTERNS[:_SECRET_ONLY_COUNT]:
        text = pattern.sub(repl, text)
    return text


# Key names whose VALUE is a credential regardless of the value's shape:
# `kafka.sasl.password: hunter2`, `s3.secret-key: ...`, `accessToken: ...`. The
# text patterns are blind to these (nothing in "hunter2" looks like a secret),
# so both redaction walkers consult the key and mask the WHOLE value under it —
# a string, a number, a list (`password: ["hunter2"]`) or a nested dict
# (`credentials: {db: hunter2}`); a credential does not stop being one because
# it is wrapped in a container. Matching is on normalized segments (split on
# . _ - / and camelCase), never substrings, so `secretName` / `secretKeyRef` /
# `tokenizer` are NOT masked — they name a secret rather than carry one.
_SENSITIVE_KEY_SEGMENTS = frozenset({
    "password", "passwords", "passwd", "pwd", "secret", "secrets", "token", "tokens",
    "apikey", "apikeys", "auth", "credential", "credentials", "authorization",
    "passphrase",
    # Kafka `sasl.jaas.config` carries the SASL username AND password inline
    # (`... PlainLoginModule required username='u' password='p';`); the whole
    # value is credential material, whatever its shape.
    "jaas",
})
_SENSITIVE_KEY_PAIRS = frozenset({
    ("api", "key"), ("api", "keys"), ("access", "key"), ("secret", "key"),
    ("private", "key"), ("auth", "token"), ("access", "token"), ("refresh", "token"),
})
_KEY_REFERENCE_TAILS = frozenset({"name", "ref", "file", "path", "id", "enabled", "count", "type"})
_CAMEL_RE = re.compile(r"([a-z0-9])([A-Z])")
_KEY_SPLIT_RE = re.compile(r"[._\-/ :]+")


def is_sensitive_key(key) -> bool:
    """True when a dict key names a credential VALUE (see above)."""
    if not isinstance(key, str) or not key:
        return False
    segments = [s for s in _KEY_SPLIT_RE.split(_CAMEL_RE.sub(r"\1_\2", key).lower()) if s]
    if not segments:
        return False
    if segments[-1] in _KEY_REFERENCE_TAILS:
        return False  # secretName / tokenFile / passwordEnabled reference, don't carry, a secret
    if any(seg in _SENSITIVE_KEY_SEGMENTS for seg in segments):
        return True
    return any((a, b) in _SENSITIVE_KEY_PAIRS for a, b in zip(segments, segments[1:]))


def mask_whole_value(key, value) -> bool:
    """True when the entire value under ``key`` must be replaced by the secret
    placeholder rather than walked: the key names a credential and the value
    carries something (None and the empty string have nothing to leak and are
    kept so the record still shows the field was unset)."""
    if value is None or value == "":
        return False
    return is_sensitive_key(key)


def _scrub_text(text: str) -> str:
    """Truncate (bounding regex cost) then mask secret / structured-PII patterns."""
    if len(text) > _MAX_FIELD_CHARS:
        text = text[:_MAX_FIELD_CHARS] + "...[truncated]"
    return redact_secrets(text)


def has_secret_shape(text: str) -> bool:
    """True when any _SECRET_PATTERNS entry matches — the single credential /
    structured-PII shape definition, shared by the audit scrubber and by
    read-side value backstops (flink_client cluster-config filter) so the two
    cannot drift apart. Bounded like _scrub_text so regex cost stays capped."""
    if len(text) > _MAX_FIELD_CHARS:
        text = text[:_MAX_FIELD_CHARS]
    return any(pattern.search(text) for pattern, _ in _SECRET_PATTERNS)


def _sanitize_value(value: Any, depth: int = 0) -> Any:
    """Recursively sanitize an untrusted value: strings are scrubbed, dict/list are
    walked to their leaves, and numbers/bools/None pass through unchanged so log-backend
    numeric/boolean filters keep working."""
    if depth > _MAX_REDACT_DEPTH:
        return "<redaction-depth-exceeded>"
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return _scrub_text(value)
    if isinstance(value, dict):
        # keys are field-name metadata kept for log structure; only values are
        # scrubbed — but the whole value under a credential-named key is masked
        # (is_sensitive_key), whatever its type: `password: ["hunter2"]` and
        # `credentials: {db: hunter2}` carry the secret one container down, and
        # the value's shape alone gives nothing to match.
        return {
            k: ("<REDACTED:secret>" if mask_whole_value(k, v)
                else _safe_sanitize(v, depth + 1))
            for k, v in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [_safe_sanitize(v, depth + 1) for v in value]
    return _scrub_text(str(value))  # unknown type -> stringify then scrub


def _safe_sanitize(value: Any, depth: int = 0) -> Any:
    """_sanitize_value wrapped so one bad field can never drop the whole audit line."""
    try:
        return _sanitize_value(value, depth)
    except Exception:  # noqa: BLE001 — a redaction failure must not lose the record
        return "<redaction-error>"


def _sanitize_record(record: dict) -> dict:
    """Allowlisted fields pass through untouched; every other field is sanitized."""
    return {
        key: (value if key in _ALLOWLIST_FIELDS else _safe_sanitize(value))
        for key, value in record.items()
    }


def audit(event: str, request: Optional[Any] = None, **fields: Any) -> None:
    """Emit one structured audit event as a single JSON line.

    Always includes: event, ts (ISO-8601 UTC), seq (monotonic per-process — gap
    indicator), instance (per-process id partitioning the seq streams),
    classification, source_ip, auth (observed: none/unknown — see
    ``_observed_auth``), actor (anonymous — see module docstring), and the raw
    forwarded_for chain when present, plus any caller-supplied fields (question,
    tools_invoked, remediation_type, applied_by, ...).

    Never raises: auditing must not break the request path.
    """
    try:
        record = {
            "event": event,
            "ts": datetime.now(timezone.utc).isoformat(),
            "seq": next(_seq),                  # gap indicator: loss vs. silence
            "instance": _instance,              # partitions seq streams per process
            "classification": "confidential",   # sink classification (SCM.C.03)
            "source_ip": client_ip(request),
            "auth": _observed_auth(request),    # observed, never asserted
            # actor stays "anonymous": an authenticating proxy in front of this pod
            # typically forwards no identity header downstream (see module docstring) — do not fake a value or trust a caller-supplied one here.
            "actor": "anonymous",
        }
        cid = _correlation_id.get()
        if cid:
            record["correlation_id"] = cid  # ties this event to its originating ai_query
        raw_xff = _raw_forwarded_for(request)
        if raw_xff:
            # Forensic chain — NOT allowlisted, so _sanitize_record truncates and
            # masks it like any other caller-controlled value (CWE-117/CWE-532).
            record["forwarded_for"] = raw_xff
        record.update(fields)
        record = _sanitize_record(record)  # redact at the single choke point (CWE-532)
        _audit_logger.info(json.dumps(record, default=str, separators=(",", ":")))
    except Exception:  # noqa: BLE001 — auditing must never break the caller
        logging.getLogger(__name__).exception("audit emit failed for event=%s", event)


def audit_remediation(result: Any, request: Optional[Any] = None) -> None:
    """Audit a remediation application from a RemediationResult-shaped object.

    Duck-typed (no import of RemediationResult) to keep this module dependency-free.
    ``applied_by`` is the trigger path (chat / REST / alert / system), not the human
    user — see the module docstring on identity.
    """
    audit(
        "remediation",
        request,
        # Stable RemediationResult.id: the same value a later rollback_lookup
        # event records, so the two can be joined in the log backend even after the
        # in-memory history has evicted the entry.
        id=getattr(result, "id", None),
        remediation_type=getattr(result, "remediation_type", None),
        applied_by=getattr(result, "applied_by", None),
        success=getattr(result, "success", None),
        dry_run=getattr(result, "dry_run", None),
        savepoint_id=getattr(result, "backup_created", None),
        changes_made=getattr(result, "changes_made", None),
    )
