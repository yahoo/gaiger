"""Egress-governance primitives for the LangGraph agent's outbound channels.

Kept free of langchain/langgraph imports so the security-critical logic is unit
testable in a bare environment (the agent module pulls the full LLM stack).
Used by app/langgraph_agent.py:

- truncate_for_model: the single outbound-to-model chokepoint — secret
  redaction (CWE-200) + size bound for every dynamic tool result.
- github_tools_enabled: single predicate under which the GitHub read tools AND
  create_github_pr register together (read-then-write is one capability).
- passthrough_for_edit: unredacted, untruncated return for the file-read tool
  whose output is written back verbatim; refuses oversize files instead.
- pr_branch_allowed / pr_path_allowed: validation of create_github_pr's
  100% model-controlled branch/path arguments, evaluated BEFORE any GitHub
  call so the writable envelope is set by code/configuration, not model output.
"""

import asyncio
import json
import os
import re
from typing import Optional

from app.audit import mask_whole_value, redact_credentials


# Recursion guard for the leaf walker. Generous compared to the audit path's
# depth 6 because tool results are nested Flink/K8s REST payloads, not flat
# audit records.
_MAX_REDACT_DEPTH = 25

# Structure deeper than the guard is replaced by this placeholder, never
# stringified: str(dict) flattens the keys into the text, and the key-based
# masking (kafka.sasl.password -> whole value) does not apply to text, so the
# old `redact_credentials(str(value))` fallback could leak a credential that
# only its key identified (review, round 3).
_DEPTH_EXCEEDED = "<redaction-depth-exceeded>"

# Marker appended to a string leaf cut at the leaf cap (see _redact_leaves).
_LEAF_CUT_MARKER = "...[truncated]"


def _redact_leaves(value, depth: int = 0, leaf_cap: Optional[int] = None):
    r"""Walk a decoded structure and apply redact_credentials to STRING LEAVES ONLY.

    Numbers, booleans and None pass through untouched — deliberately, and for
    the same reason audit._sanitize_value does it: the masking patterns are
    text-shaped and several of them (notably the credit-card rule
    ``\b(?:\d[ \-]?){13,19}\b``) match bare digit runs. Applying them to a
    SERIALIZED json blob rewrites every 13-19 digit number in the payload —
    every Flink epoch-millis timestamp (checkpoint trigger/ack, watermarks) —
    into ``<REDACTED:cc>``, which both destroys the model's ability to compute
    checkpoint duration or recency AND emits a document that no longer parses
    as JSON. Redacting per leaf and serializing afterwards keeps the output
    parseable and keeps numeric fields intact.

    ``leaf_cap`` bounds the length of a string leaf BEFORE the regex passes run
    (review, round 3: the key=value pattern was quadratic on separator-dense
    text, and this path had no length cap, so one 36 KB log leaf cost ~9 s).
    truncate_for_model passes its own output limit: every serialized character
    of a leaf lands at or after the leaf's own offset in the document, so no
    character beyond ``limit`` of a single leaf can survive the final byte cut
    anyway — the cap changes cost, not what the model receives.
    """
    if depth > _MAX_REDACT_DEPTH:
        return _DEPTH_EXCEEDED
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        if leaf_cap is not None and len(value) > leaf_cap:
            value = value[:leaf_cap] + _LEAF_CUT_MARKER
        return redact_credentials(value)
    if isinstance(value, dict):
        # Keys are field-name metadata and are never rewritten (Flink/K8s
        # payloads are keyed by numeric ids and epoch timestamps). They ARE
        # consulted: the whole value under a credential-named key
        # (kafka.sasl.password, s3.secret-key, accessToken, credentials, ...)
        # is masked, whatever its type — a string, a list of strings, a nested
        # dict — because such values have no recognisable shape of their own
        # and the text patterns are blind to them.
        return {
            k: ("<REDACTED:secret>" if mask_whole_value(k, v)
                else _redact_leaves(v, depth + 1, leaf_cap))
            for k, v in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [_redact_leaves(v, depth + 1, leaf_cap) for v in value]
    # unknown type -> stringify, then treat as a string leaf (cap + scrub)
    return _redact_leaves(str(value), depth, leaf_cap)


def redact_for_client(result):
    """Credential masking for REST read responses (pod logs, diagnostics).

    Same leaf walker as the model-bound path, without the size cut: string
    leaves get the credential patterns, and the whole value under a
    credential-named key (kafka.sasl.password, ...) is masked. Numbers stay
    numbers, so the response keeps its shape."""
    return _redact_leaves(result)


def truncate_for_model(result, limit: int = 30000) -> str:
    """Outbound-to-model chokepoint. EVERY dynamic tool result passes through
    here before entering model context (and thence the Anthropic API), so the
    credential-shaped masking applied on the audit path (CWE-532) is applied on
    this egress path too (CWE-200), then the size bound. Structured-PII shapes
    (email / SSN / card digit runs) are deliberately NOT applied here: they match
    operational data (RPC addresses, epoch timestamps) and would corrupt what the
    model reasons over. Enforced by a
    source-level invariant test: tool bodies may json.dumps only literal
    constant dicts — anything dynamic must return via this function.

    Redaction runs per string leaf BEFORE serialization (see _redact_leaves),
    never over the serialized blob.

    ensure_ascii=False is load-bearing for the fence that wraps this output
    (langgraph_agent._as_untrusted): the default ASCII escaping
    would turn a zero-width space into the six literal characters ``\\u200b``
    and a fullwidth '＜' into ``\\uff1c``, so the invisible-character strip, the
    NFKC fold and the fence-tag neutralizer would never fire on tool payloads.
    The output is prose for the model, never re-parsed as JSON; json.dumps
    still escapes control characters regardless of this flag, and slicing is
    by code point so the cut never splits a character."""
    try:
        s = json.dumps(_redact_leaves(result, leaf_cap=limit), default=str, ensure_ascii=False)
    except Exception:  # noqa: BLE001 — never let redaction lose a tool result
        # Fail safe, not open: fall back to masking the serialized form. Output
        # fidelity degrades (numbers may be masked) but nothing leaks. The blob
        # is cut to the limit BEFORE the regex passes for the same cost bound
        # as the per-leaf cap; the marker below then records the cut.
        raw = json.dumps(result, default=str, ensure_ascii=False)
        if len(raw) > limit:
            return redact_credentials(raw[:limit]) + "\n... [truncated]"
        return redact_credentials(raw)
    if len(s) > limit:
        s = s[:limit] + "\n... [truncated]"
    return s


async def truncate_for_model_offloaded(result, limit: int = 30000) -> str:
    """truncate_for_model run off the event loop.

    The per-leaf regex pass over a large tool result (pod logs, thread dumps)
    was measured at 178-881 ms; on the loop that stalls every other in-flight
    request and the poller. The leaves are individually small, so the GIL is
    released between them and the loop keeps serving while the worker thread
    scrubs. This is the awaitable the agent aliases as ``_truncate``."""
    return await asyncio.to_thread(truncate_for_model, result, limit)


def fit_listing_for_model(result, limit: int = 30000, key: str = "files") -> dict:
    """Shrink a file listing so that its serialized form fits the model-bound
    size bound WITHOUT cutting the JSON mid-document.

    truncate_for_model's byte cut is right for free text but wrong for a
    listing: 500 Java paths serialize to ~35k chars, so the 30k cut left ~420
    parseable entries while the prefix still claimed ``count: 500, truncated:
    false``. Here trailing entries are dropped until the whole envelope fits,
    and ``count`` / ``truncated`` are recomputed to describe what the model
    actually receives. Returns a new dict; the input is not mutated."""
    if not isinstance(result, dict) or not isinstance(result.get(key), list):
        return result
    files = list(result[key])
    envelope = dict(result)
    envelope[key] = []
    envelope["count"] = 0
    envelope["truncated"] = True
    # Leave room for the truncation marker truncate_for_model would append,
    # so the fitted listing is never byte-cut afterwards.
    budget = limit - len(json.dumps(envelope, default=str)) - 32
    kept = []
    used = 0
    for path in files:
        cost = len(json.dumps(path, default=str)) + 2  # ", " separator
        if used + cost > budget:
            break
        kept.append(path)
        used += cost
    envelope[key] = kept
    envelope["count"] = len(kept)
    envelope["truncated"] = bool(result.get("truncated")) or len(kept) < len(files)
    return envelope


# Size ceiling (in CHARACTERS OF FILE CONTENT) for a file the model may read
# for editing. Above this the tool REFUSES rather than truncates:
# create_github_pr replaces whole files, so a truncated read would be written
# back as the file's entire new content.
MAX_EDITABLE_FILE_CHARS = 200_000


def content_too_large_for_edit(result, limit: int = MAX_EDITABLE_FILE_CHARS) -> bool:
    """True when a SUCCESSFUL read carries more content than the edit path
    accepts. passthrough_for_edit refuses on this; the read tool consults it
    first so the refusal is audited as a rejection rather than as a
    successful egress (the content never reaches the model)."""
    if not isinstance(result, dict) or not result.get("success"):
        return False
    content = result.get("content")
    return isinstance(content, str) and len(content) > limit


def passthrough_for_edit(result, limit: int = MAX_EDITABLE_FILE_CHARS) -> str:
    """Return path for read_github_file — the ONE tool whose output is meant to
    be edited and written back verbatim by create_github_pr.

    Deliberately NOT truncate_for_model for the file CONTENT: redaction
    placeholders or a size cut would silently land in the repository as the
    file's new content. The content is passed through unchanged, and an
    oversize file is refused with an explicit error so the model cannot proceed
    on a partial view.

    Two review corrections:
    - the size is measured on ``content`` in characters, not on the
      ``json.dumps`` of the whole envelope (which with ensure_ascii inflated a
      120k-char non-ASCII file to ~480k and refused it), and the serialized form
      keeps non-ASCII as-is for the same reason;
    - only a successful read is passed through. Error envelopes (a GitHub
      error message can echo a token) go through the redacting chokepoint like
      every other tool result.

    The read/write tool pair is registered under one predicate
    (github_tools_enabled), so this path exists only where create_github_pr
    does; the audit event on the read tool records the egress."""
    if not isinstance(result, dict) or not result.get("success"):
        return truncate_for_model(result)
    content = result.get("content")
    if not isinstance(content, str):
        return truncate_for_model(result)
    if content_too_large_for_edit(result, limit):
        return json.dumps({
            "success": False,
            "error": (
                f"file too large to read for editing ({len(content)} chars > {limit}); "
                "narrow the change to a smaller file or ask the operator to apply it"
            ),
        })
    return json.dumps(result, default=str, ensure_ascii=False)


# High-confidence credential material that has no legitimate place in a source
# file the model reads for editing: PEM private-key blocks and the vendor token
# shapes the audit path masks. The read path cannot redact (the content is
# written back verbatim), so it REFUSES instead. Deliberately excludes the
# key=value pattern: `password = config.get("password")` is ordinary source.
_HARD_CREDENTIAL_RE = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----"     # PEM / OpenSSH / PGP private key
    r"|PuTTY-User-Key-File-\d"                               # .ppk body
    r"|\bAKIA[0-9A-Z]{16}\b"
    r"|\b(?:sk-[A-Za-z0-9\-]{10,256}|ghp_[A-Za-z0-9]{20,256}|xox[baprs]-[A-Za-z0-9\-]{8,256})\b"
    r"|\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{8,}"
)


def contains_hard_credential(text: str) -> bool:
    """True when a file's content carries credential material that must not
    enter model context even via the unredacted edit path."""
    return bool(text) and _HARD_CREDENTIAL_RE.search(text) is not None


def github_tools_enabled(write_enabled: bool, github_configured: bool) -> bool:
    """Single predicate for the GitHub tool set — list_github_files,
    read_github_file AND create_github_pr register together or not at all.

    The prompts require read-then-write for code fixes, so a deployment with the
    write tool but no read tools would push the model into editing blind, and a
    deployment with read tools but no write tool ships repository source into
    model context (an egress channel) with nothing to do with it. Both halves
    therefore sit under the write gate (ENABLE_WRITE_TOOLS + non-production) plus
    a configured client and TARGET_REPO."""
    return bool(write_enabled and github_configured)


_PR_BRANCH_RE = re.compile(r"^ai-debugger/[a-z0-9][a-z0-9._-]{0,39}$")

# Protected repo surfaces the agent must never write (and, for symmetry, never
# read into model context): CI / build / deploy configuration and key/secret
# material, matched as path SEGMENTS at ANY depth (catches nested deploy/,
# helm/, docker/Dockerfile, ci/Jenkinsfile, apps/x/k8s/…). Checks are
# case-insensitive. A denylist rather than a src/** allowlist because
# TARGET_REPO layouts are team-specific (pom.xml, build.gradle, root configs
# are legitimate fix targets); the residual risk is accepted
# and backstopped by human PR review.
#
# Round-3 review: the segment rules over-matched ordinary source and dropped
# it from list_github_files as well — `src/main/java/.../deploy/Job.java`
# (a Java package called deploy), `.../charts/Renderer.java`,
# `DockerfileParser.java`, `i18n/messages.key`. The rules are now split by how
# unambiguous the segment is:
# - dot-prefixed CI / IaC directories are refused at any depth whatever the
#   leaf (nothing but pipeline configuration lives under `.github/`);
# - GENERIC infra directory names (deploy, charts, helm, k8s, terraform) are
#   refused unless the leaf is a compiled-language source file, which is what
#   a same-named code package contains and what a deployment directory does
#   not (manifests, values, scripts, templates);
# - Dockerfile is matched as the file name shape (`Dockerfile`,
#   `Dockerfile.dev`, `app.dockerfile`), not as a prefix of any name;
# - `.key` is refused when it sits under a key-material directory or, on the
#   read path, when its CONTENT is a key block (contains_hard_credential);
#   the other suffixes are unambiguous key/store formats and stay as they are.
_DENY_DIR_SEGMENTS = frozenset({
    ".github", ".circleci", ".ci", ".buildkite", ".teamcity", ".argo",
    ".terraform", ".ssh",
})
_DENY_INFRA_DIR_SEGMENTS = frozenset({
    "k8s", "helm", "charts", "deploy",
    # infrastructure-as-code
    "terraform",
})
# Leaves that make a generic infra-named directory read as a code package.
# Deliberately compiled/typed languages only: `deploy/release.py`,
# `deploy/run.sh`, `charts/index.js` are as likely to be deployment tooling as
# source, and stay refused.
_SOURCE_FILE_SUFFIXES = (
    ".java", ".scala", ".kt", ".go", ".rs", ".c", ".cc", ".cpp", ".h", ".hpp", ".cs",
)
# Directories under which a `.key` file is key material by placement.
_KEY_MATERIAL_DIR_SEGMENTS = frozenset({
    "certs", "cert", "certificates", "keys", "ssl", "tls", "pki", "secrets", "secret",
})
_DENY_FILE_SEGMENTS = frozenset({
    # Screwdriver (screwdriver-cd/screwdriver) is an open-source CI/CD system;
    # its pipeline file is a CI surface like any other listed here.
    "screwdriver.yaml", "screwdriver.yml",
    "jenkinsfile", "makefile",
    ".gitlab-ci.yml", "cloudbuild.yaml", ".travis.yml", ".drone.yml",
    "azure-pipelines.yml", "bitbucket-pipelines.yml", "appveyor.yml",
    "id_rsa", "id_ed25519", "id_ecdsa", "id_dsa",
    # credential stores that tooling reads by fixed name
    ".netrc", "_netrc", ".npmrc", ".pypirc", ".git-credentials", ".pgpass",
    ".htpasswd", ".boto", ".s3cfg", ".dockercfg",
})
# Key/secret material by extension — primarily protects the READ (egress) path.
_DENY_FILE_SUFFIXES = (
    ".pem", ".p12", ".pfx", ".jks", ".keystore",
    ".p8", ".gpg", ".pgp", ".asc", ".ppk", ".kdbx",
    ".tf", ".tfvars", ".tfstate",
)


def _is_dockerfile_name(seg: str) -> bool:
    """`Dockerfile`, `Dockerfile.<variant>`, `<name>.dockerfile` — the shapes
    Docker tooling reads — and NOT any name that merely begins with the word
    (`DockerfileParser.java` is source). ``seg`` is already lower-cased."""
    return seg == "dockerfile" or seg.startswith("dockerfile.") or seg.endswith(".dockerfile")

# git ref / base branch names the tools will pass to the GitHub API: simple
# conservative shape, no traversal-ish '..' (also a git-ref invalid sequence).
_GIT_REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,99}$")


def git_ref_allowed(ref: str) -> bool:
    """Conservative shape check for model-supplied git refs (base_branch, ref):
    alphanumeric start, limited charset, bounded length, no '..'."""
    return bool(_GIT_REF_RE.match(ref)) and ".." not in ref


def pr_branch_allowed(branch_name: str, base_branch: str) -> bool:
    """Branch must sit in the agent's own namespace and can never equal the
    base branch — combined with github_client's refusal to reuse an existing
    branch, this closes the commit-lands-on-main primitive. The base branch
    itself must also be a sane git ref."""
    return (
        bool(_PR_BRANCH_RE.match(branch_name))
        and branch_name != base_branch
        and git_ref_allowed(base_branch)
    )


def repo_path_allowed(file_path: str) -> bool:
    """Require an already-canonical relative path and refuse CI/build/deploy
    surfaces and key material at ANY depth. Canonical means: no backslashes,
    not absolute, and no empty / '.' / '..' segments — so traversal and alias
    shapes ('./.github/…', 'a//b', 'a/../x') are REJECTED rather than
    normalized.

    Applied to BOTH create_github_pr (write envelope) and read_github_file
    (egress envelope): an injected instruction must not be able to pull CI /
    deploy configuration or key material into model context either."""
    if not file_path or "\\" in file_path or file_path.startswith("/"):
        return False
    # Reject whitespace and non-printable characters (CWE-117, log forging).
    # These paths are model-controlled and are written to the same stdout stream
    # that carries the single-JSON-line audit events, so an embedded newline
    # lets a path inject a whole forged audit-shaped line. Rejecting the
    # character class outright is cheaper and more durable than escaping at each
    # log call site, and legitimate source paths never contain whitespace.
    if any(ch.isspace() or not ch.isprintable() for ch in file_path):
        return False
    segments = file_path.split("/")
    if any(seg in ("", ".", "..") for seg in segments):
        return False
    lowered = [s.lower() for s in segments]
    leaf = lowered[-1]
    is_source_leaf = leaf.endswith(_SOURCE_FILE_SUFFIXES)
    for seg in lowered:
        if seg in _DENY_DIR_SEGMENTS or seg in _DENY_FILE_SEGMENTS:
            return False
        if seg in _DENY_INFRA_DIR_SEGMENTS and not is_source_leaf:
            return False
        if _is_dockerfile_name(seg) or seg == ".env" or seg.startswith(".env."):
            return False
        if seg.endswith(_DENY_FILE_SUFFIXES):
            return False
    if leaf.endswith(".key") and any(seg in _KEY_MATERIAL_DIR_SEGMENTS for seg in lowered[:-1]):
        return False
    return True


# Backwards-compatible name used by the PR tool; same policy for both surfaces.
pr_path_allowed = repo_path_allowed


def repo_path_filter_allowed(path_filter) -> bool:
    """Validate list_github_files' model-supplied `path_filter` — a directory
    PREFIX, not a full path. Empty / None means "no filter" and is allowed.

    Otherwise it must satisfy the same envelope as a file path (so a filter
    cannot name a protected surface, embed traversal, or carry the control
    characters that make log forging possible), tolerating one trailing slash
    since a prefix is naturally written 'src/main/java/'."""
    if path_filter is None or path_filter == "":
        return True
    if not isinstance(path_filter, str):
        return False
    candidate = path_filter[:-1] if path_filter.endswith("/") else path_filter
    return repo_path_allowed(candidate)


# ── PR creation limits ─────────────────────────────────────────────────────────
#
# create_github_pr pushes a branch to TARGET_REPO BEFORE any review, so the
# target repo's CI may run model-written code. These bound when and where the
# agent may do that.


def alert_flow_prs_enabled() -> bool:
    """ENABLE_ALERT_FLOW_PRS (default false): whether the UNATTENDED alert flow
    may register the GitHub tool set. Chat (operator-driven) runs are unaffected."""
    return os.getenv("ENABLE_ALERT_FLOW_PRS", "false").strip().lower() == "true"


def pr_allowed_prefixes() -> tuple:
    """GITHUB_PR_ALLOWED_PREFIXES: optional comma-separated path prefixes a PR
    edit must start with (e.g. "src/main/"). Empty = no extra restriction."""
    return tuple(p.strip() for p in os.getenv("GITHUB_PR_ALLOWED_PREFIXES", "").split(",") if p.strip())


def pr_prefix_allowed(file_path: str) -> bool:
    prefixes = pr_allowed_prefixes()
    return not prefixes or file_path.startswith(prefixes)


def pr_max_per_day() -> int:
    """GITHUB_PR_MAX_PER_DAY (default 5, clamped 0..100): PRs the agent may open
    in any rolling 24 hours. 0 refuses every PR."""
    try:
        return min(max(0, int(os.getenv("GITHUB_PR_MAX_PER_DAY", "5"))), 100)
    except ValueError:
        return 5
