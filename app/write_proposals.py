# Copyright Yahoo, Licensed under the terms of the Apache 2.0 license. See LICENSE for terms.

"""Pending agent writes awaiting human approval.

The agent's write tools (update_flink_config, restart_flink_job,
apply_remediation with dry_run=false, create_github_pr) never act on their
own: they record a proposal here and return. A person approves or rejects it
through POST /api/remediation/approve or /reject (the UI's Approve / Reject
buttons). The model has no tool for those routes, and the proposal id never
enters model context: it reaches the UI through the run's result event (chat)
or GET /api/remediation/pending (alert-triggered runs, which have no chat).

Proposals are single use (taken on approve or reject), expire after
WRITE_PROPOSAL_TTL_SECONDS (default 600), and at most MAX_PENDING are kept
(the oldest is dropped first). State is process-local: the sidecar is a
single-process, single-replica deployment, and a restart drops pending
proposals, which is the safe direction.
"""
import hashlib
import os
import secrets
import threading
import time
from contextvars import ContextVar
from typing import Optional

MAX_PENDING = 50
_DEFAULT_TTL_SECONDS = 600

_lock = threading.Lock()
_proposals: "dict[str, dict]" = {}

# Proposals created during the CURRENT agent run, for the result event.
_run_proposals: ContextVar[Optional[list]] = ContextVar("run_proposals", default=None)


def ttl_seconds() -> int:
    try:
        return min(max(60, int(os.getenv("WRITE_PROPOSAL_TTL_SECONDS", str(_DEFAULT_TTL_SECONDS)))), 3600)
    except ValueError:
        return _DEFAULT_TTL_SECONDS


def proposal_ref(pid: str) -> str:
    """Short, non-secret reference for audit records (the id itself is a
    single-use capability and is not logged)."""
    return hashlib.sha256(pid.encode()).hexdigest()[:12]


def _sweep(now: float) -> None:
    ttl = ttl_seconds()
    for pid in [p for p, v in _proposals.items() if now - v["at"] > ttl]:
        del _proposals[pid]


def begin_run_tracking() -> list:
    run: list = []
    _run_proposals.set(run)
    return run


def run_proposals() -> list:
    return list(_run_proposals.get() or [])


# Bound on the human-readable detail (e.g. a proposed file) shown with a proposal.
# A longer detail is refused, never cut, so the approver always sees all of it.
DETAIL_MAX_CHARS = 60000


class DetailTooLong(ValueError):
    """The approver could not be shown the whole proposal."""


def propose(action: str, args: dict, summary: str, detail: str = "") -> str:
    """Record a pending write; return its unguessable single-use id. `detail`
    is shown to the approver in full (for a PR: the body and the new file);
    raises DetailTooLong when it exceeds DETAIL_MAX_CHARS."""
    if len(detail) > DETAIL_MAX_CHARS:
        raise DetailTooLong(f"proposal detail exceeds {DETAIL_MAX_CHARS} characters")
    now = time.monotonic()
    pid = secrets.token_urlsafe(24)
    with _lock:
        _sweep(now)
        while len(_proposals) >= MAX_PENDING:
            oldest = min(_proposals, key=lambda p: _proposals[p]["at"])
            del _proposals[oldest]
        record = {"action": action, "args": dict(args), "summary": summary,
                  "detail": detail, "at": now}
        _proposals[pid] = record
    run = _run_proposals.get()
    if run is not None:
        run.append(_view(pid, record, now))
    return pid


def _view(pid: str, p: dict, now: float) -> dict:
    return {"proposal_id": pid, "action": p["action"], "summary": p["summary"],
            "detail": p.get("detail", ""),
            "expires_in_seconds": max(0, int(ttl_seconds() - (now - p["at"])))}


def pending() -> list:
    """Every unexpired proposal, oldest first, for the approver's UI."""
    now = time.monotonic()
    with _lock:
        _sweep(now)
        items = sorted(_proposals.items(), key=lambda kv: kv[1]["at"])
        return [_view(pid, p, now) for pid, p in items]


def take(pid: str) -> Optional[dict]:
    """Remove and return the proposal, or None if unknown or expired."""
    if not isinstance(pid, str) or not pid:
        return None
    now = time.monotonic()
    with _lock:
        p = _proposals.pop(pid, None)
        _sweep(now)
    if p is None or now - p["at"] > ttl_seconds():
        return None
    return p


def clear() -> None:
    with _lock:
        _proposals.clear()
