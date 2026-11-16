# Copyright Yahoo, Licensed under the terms of the Apache 2.0 license. See LICENSE for terms.

"""Centralized authorization for the AI debugger's cluster-mutating ("write") tools.

Single source of truth used by BOTH the LangGraph agent (tool registration) and the
FastAPI REST remediation endpoint, so neither path can mutate the cluster unless the
deployment has explicitly opted in AND the environment is positively identified as
non-production.

Gating rule (one-way production hard-stop, fail closed):

    write tools enabled  ==  ENABLE_WRITE_TOOLS truthy  AND  environment == nonprod

The per-deployment ENABLE_WRITE_TOOLS flag remains the only switch that *enables* write
tools. Environment detection only ever *disables* them -- it can never turn them on -- so
a flag accidentally left true in a production manifest cannot expose the mutating surface.

The environment is inferred from DEPLOY_ENV, which must be injected by the deployment
manifest / CD pipeline for the target environment (e.g. ``prod``, ``prod-us-east-1``,
``nonprod``, ``staging``). It sits in the same env list as ENABLE_WRITE_TOOLS and is
therefore spoofable by anyone who can edit that manifest. This check is defence in depth
against operator error (e.g. a manifest copied to production with the flag left true),
NOT a control against an attacker who can edit the manifest: such an attacker would set
ENABLE_WRITE_TOOLS directly. An unrecognised or blank DEPLOY_ENV is treated as
production (fail closed). Local development without a DEPLOY_ENV must set the explicit,
logged ALLOW_WRITE_TOOLS_WITHOUT_ENV=true escape hatch, which must never appear in a
deployment manifest.
"""
import logging
import os
import re
from pathlib import Path

logger = logging.getLogger(__name__)

_NONPROD_SEGMENTS = frozenset({"nonprod", "dev", "test", "staging"})
_PROD_SEGMENTS = frozenset({"prod", "prd", "production"})

# Runtime kill switch (operator containment control). Backed by a ConfigMap
# volume mount: the kubelet updates a plain (non-subPath) ConfigMap mount in
# place, so the flag is mutable in a RUNNING container — unlike an environment
# variable, which is fixed for the container's lifetime. Values that engage the
# switch mirror the runbook wording.
_DEFAULT_KILL_SWITCH_FILE = "/etc/flink-ai-debugger/kill-switch"
_HALT_VALUES = frozenset({"1", "true", "halt"})


def _kill_switch_file() -> Path:
    # Resolved per call (not at import): tests and deployments point it via
    # AGENT_KILL_SWITCH_FILE, and a per-call getenv is negligible next to the
    # file read itself.
    return Path(os.getenv("AGENT_KILL_SWITCH_FILE", _DEFAULT_KILL_SWITCH_FILE))


# Once-per-FAILURE-EPISODE latch for unexpected kill-switch read errors: the
# control fails open by design, but it must never fail SILENTLY — an operator
# relying on it needs the failure in the logs. The latch is set on the first
# unexpected error and RESET by the next successful read, so a file that
# breaks, is repaired, and breaks again warns again (a once-per-process latch
# would log the second episode nowhere). ENOENT is excluded from both sides
# of the latch: an absent file is the normal "not mounted / released-by-
# deletion" state, not an error, and it is also not a recovery.
_halt_read_error_warned = False


def kill_switch_armed() -> bool:
    """True when the kill-switch file is present (the ConfigMap is mounted).

    Used by the startup arming check so a pod whose kill switch is inoperable
    (ConfigMap not applied / volume not rendered) says so loudly at startup
    instead of failing open silently during an incident.
    """
    try:
        return _kill_switch_file().is_file()
    except OSError:
        return False


# The flag is at most a few bytes; anything larger is not a kill-switch value
# (a ConfigMap key can carry up to ~1 MiB, and a mis-targeted mount could hand
# us an arbitrary file). Bounding the read keeps the per-call cost constant.
_MAX_KILL_FILE_BYTES = 64


def _read_kill_switch() -> bool:
    """Decode the kill file and return whether it engages the switch.

    Raises FileNotFoundError when the file is absent and lets every other
    failure propagate to the caller, which decides how to report it. Reads
    BYTES: a ConfigMap `binaryData` key, a stray BOM, or a truncated multibyte
    sequence must not turn into a UnicodeDecodeError that escapes as an
    unhandled exception from what callers treat as a boolean probe.
    """
    with _kill_switch_file().open("rb") as fh:
        raw = fh.read(_MAX_KILL_FILE_BYTES + 1)  # bounded: never slurp a large file
    if len(raw) > _MAX_KILL_FILE_BYTES:
        raise ValueError(f"kill-switch file larger than {_MAX_KILL_FILE_BYTES} bytes")
    # Strict decode: undecodable content is an error the caller reports as
    # 'unreadable', not silently 'released'. utf-8-sig accepts a BOM-prefixed
    # "true" written by a Windows editor.
    text = raw.decode("utf-8-sig")
    return text.strip().lower() in _HALT_VALUES


def kill_switch_state() -> str:
    """Three-valued arming evidence for startup/diagnostic logging:
    'engaged', 'released', 'not-mounted', or 'unreadable'.

    Distinct from agent_halted() on purpose: agent_halted() collapses every
    failure to False (fail-open containment decision), but arming EVIDENCE must
    not misreport a present-but-unreadable file as 'released' — a responder
    reading the startup line needs to know the switch is inoperable. Catches
    broadly: this runs in the startup hook, and a decode error on a binary
    file must not take the sidecar down.
    """
    try:
        return "engaged" if _read_kill_switch() else "released"
    except FileNotFoundError:
        return "not-mounted"
    except Exception:  # noqa: BLE001 — OSError, UnicodeDecodeError, ValueError, ...
        return "unreadable"


def agent_halted() -> bool:
    """True when the operator has tripped the runtime kill switch.

    This is a CONTAINMENT control, not an authorization gate: it can only ever
    further restrict what the authorization gate (write_tools_enabled) already
    allows. Fail-open on read errors is deliberate — a transient filesystem
    error or an absent mount must not disable the debugger; the fail-closed
    property lives in the authorization gate below. Unexpected (non-ENOENT)
    read errors are logged once per failure episode (the warning re-arms when
    a read succeeds again) so the fail-open is never silent.

    Never raises. Callers treat this as a boolean probe from places that must
    stay alive (the Grafana poll loop, tool bodies, REST routes), so every
    failure -- OSError, a non-UTF-8 `binaryData` value (UnicodeDecodeError),
    an oversized file -- collapses to False here rather than propagating.
    See docs/AI_INCIDENT_RESPONSE.md for the operational procedure.
    """
    global _halt_read_error_warned
    try:
        halted = _read_kill_switch()
    except FileNotFoundError:
        return False
    except Exception as e:  # noqa: BLE001 — see docstring: this probe must never raise
        if not _halt_read_error_warned:
            _halt_read_error_warned = True
            logger.warning(
                "kill-switch file unreadable (%s: %s) — failing OPEN (agent keeps "
                "running); the runtime kill switch is NOT operable until this "
                "is fixed", type(e).__name__, e,
            )
        return False
    if _halt_read_error_warned:
        # Recovery: the file reads again, so the switch is operable once more.
        # Say so (the warning above told the operator it was NOT), and re-arm
        # the latch so a later failure episode is reported, not swallowed.
        _halt_read_error_warned = False
        logger.info("kill-switch file readable again — the runtime kill switch is operable")
    return halted


def _environment() -> str:
    """Return 'nonprod', 'prod', or 'unknown' from DEPLOY_ENV.

    Exact segment match on '.', '-', '_' and '/' separators: 'nonprod' -> nonprod,
    'prod-us-east-1' -> prod, 'corp' -> unknown. A substring test cannot distinguish
    these reliably. Production is tested FIRST so a value naming both (e.g.
    'prod-test') resolves to the restrictive answer, never the permissive one.
    """
    env = os.getenv("DEPLOY_ENV", "").strip().lower()
    segments = set(re.split(r"[^a-z0-9]+", env)) - {""} if env else set()
    if segments & _PROD_SEGMENTS:
        return "prod"
    if segments & _NONPROD_SEGMENTS:
        return "nonprod"
    return "unknown"


def write_tools_enabled() -> bool:
    """Single gate for all cluster-mutating tools (agent tool path + REST endpoint).

    Deliberately INDEPENDENT of the runtime kill switch. This function is also
    called at agent construction (tool registration and the capabilities block
    of the system prompt), and a compiled graph cannot be changed live: an agent
    built while the switch was engaged would come up read-only and stay
    read-only after the operator released the switch, until the next rebuild
    (runbook step 3, pod deletion while engaged, produces exactly that). The
    halt is therefore enforced at the two places that run per operation --
    agent_halted() inside each write tool body and at the REST remediation
    routes -- never here.
    """
    flag = os.getenv("ENABLE_WRITE_TOOLS", "false").strip().lower() == "true"
    if not flag:
        return False

    env = _environment()
    if env == "nonprod":
        logger.info("write_tools_enabled: allowed (environment=nonprod)")
        return True

    # Explicit, logged local-development escape hatch. Never set in a manifest.
    # Only for an UNSET DEPLOY_ENV: a label that is set but unrecognised (corp,
    # live, a typo of prod) fails closed even with the hatch.
    if (env == "unknown" and not os.getenv("DEPLOY_ENV", "").strip()
            and os.getenv("ALLOW_WRITE_TOOLS_WITHOUT_ENV", "").strip().lower() == "true"):
        logger.warning(
            "write_tools_enabled: allowed via ALLOW_WRITE_TOOLS_WITHOUT_ENV with no "
            "DEPLOY_ENV set -- local development only"
        )
        return True

    # FAIL CLOSED: prod, or an environment we could not determine.
    logger.warning(
        "write_tools_enabled: denied (environment=%s, ENABLE_WRITE_TOOLS=true but the "
        "environment is production or could not be determined)", env
    )
    return False
