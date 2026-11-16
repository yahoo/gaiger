"""Bounded in-process collections (CWE-770 / CWE-401).

Two collections previously grew for the pod's lifetime, ending in a sidecar
OOM restart. (Rollback records are in-memory only and still die on any restart;
this change removes the *self-inflicted* restart, it does not make them durable.)

  1. ``AutoRemediator.history`` — a plain list, appended on every remediation,
     returned in full by ``GET /api/remediation/history``, never trimmed.
  2. ``GrafanaAlertPoller._seen`` — dedup map keyed ``(fingerprint,
     startsAt)``; entries were inserted and refreshed, never deleted, so every
     firing episode of a flapping alert added one permanent key.

The fix bounds ``history`` with ``deque(maxlen=MAX_REMEDIATION_HISTORY)`` and
gives each ``RemediationResult`` a stable monotonic ``id`` that ``rollback()``
looks up (positional indexing into a bounded deque silently targets the WRONG
entry once eviction starts), and sweeps ``_seen`` keys older than 2x the
re-eval interval from ``_poll_once`` — before BOTH early returns (no matching
alert; nothing new after dedup), so quiet cycles still trim the map.

No cluster, no LLM, no aiohttp mocking required.
"""
import ast
import asyncio
from pathlib import Path

import pytest

APP_DIR = Path(__file__).resolve().parent.parent / "app"


def _ar():
    return pytest.importorskip("app.auto_remediator")


def _manual_action(ar):
    # The auto_applicable=False path appends to history without touching any
    # client, so hundreds of applies are cheap and dependency-free.
    return ar.RemediationAction(
        type=ar.RemediationType.CONVERT_BLOCKING_IO,
        description="manual",
        risk_level=ar.RiskLevel.MANUAL,
        requires_restart=True,
        auto_applicable=False,
    )


def _fill(remediator, ar, n):
    action = _manual_action(ar)

    async def _apply_all():
        for _ in range(n):
            # dry_run is keyword-only with no default since #104; the manual
            # path returns before it is consulted, so False (the old default)
            # keeps these appends identical to what they were.
            await remediator.apply_remediation(action, applied_by="test", dry_run=False)

    asyncio.run(_apply_all())


class _FakeFlink:
    """Savepoint-recording stand-in so the REAL apply path can run offline."""

    def __init__(self):
        self.savepoints = 0

    async def get_running_job_id(self):
        return "job-abc"

    async def trigger_savepoint(self, job_id):
        self.savepoints += 1
        return {"request-id": f"sp-{self.savepoints}"}

    async def get_savepoint_status(self, job_id, trigger_id):
        return {"status": {"id": "COMPLETED"}, "operation": {"location": "file:///sp"}}


def _live_remediator(ar):
    remediator = ar.AutoRemediator(flink_client=_FakeFlink(), k8s_client=None)

    async def _no_patch(config_changes):
        return None

    remediator._apply_config_via_k8s = _no_patch
    return remediator


def _apply(remediator, ar, *, dry_run, n=1):
    """Run the savepoint-then-patch path n times; returns the results."""
    action = remediator.create_action(ar.RemediationType.INCREASE_CHECKPOINT_TIMEOUT)

    async def _go():
        return [
            await remediator.apply_remediation(action, applied_by="test", dry_run=dry_run)
            for _ in range(n)
        ]

    return asyncio.run(_go())


# ── 1. History is bounded ────────────────────────────────────────────────────

def test_history_is_bounded_at_max():
    """Ticket acceptance test: maxlen + 50 appends leave exactly maxlen entries.

    Fails before the fix with len == maxlen + 50.
    """
    ar = _ar()
    remediator = ar.AutoRemediator(flink_client=None, k8s_client=None)
    _fill(remediator, ar, ar.MAX_REMEDIATION_HISTORY + 50)
    assert len(remediator.history) == ar.MAX_REMEDIATION_HISTORY


def test_history_evicts_oldest_first():
    ar = _ar()
    remediator = ar.AutoRemediator(flink_client=None, k8s_client=None)
    _fill(remediator, ar, ar.MAX_REMEDIATION_HISTORY + 50)
    ids = [r.id for r in remediator.history]
    assert ids[0] == 50  # the 50 oldest were evicted
    assert ids == list(range(50, ar.MAX_REMEDIATION_HISTORY + 50))


# ── 2. Stable ids ────────────────────────────────────────────────────────────

def test_result_ids_are_monotonic_and_exposed():
    ar = _ar()
    remediator = ar.AutoRemediator(flink_client=None, k8s_client=None)
    _fill(remediator, ar, 5)
    assert [r.id for r in remediator.history] == [0, 1, 2, 3, 4]
    dumped = remediator.get_history()
    assert [d["id"] for d in dumped] == [0, 1, 2, 3, 4]


# ── 3. Rollback correctness under eviction ───────────────────────────────────

def test_rollback_by_id_survives_eviction():
    """The silent-wrong-rollback hazard: after eviction, positional indexing
    resolves an old id to a DIFFERENT entry. Lookup must be by stable id.

    Before the fix, rollback(entry.id) positionally hits another entry (no
    rollback_info planted there) and this test fails.
    """
    ar = _ar()
    remediator = _live_remediator(ar)
    _fill(remediator, ar, 60)
    (real,) = _apply(remediator, ar, dry_run=False)  # id == 60
    _fill(remediator, ar, ar.MAX_REMEDIATION_HISTORY + 50 - 61)
    assert real.id == 60
    assert remediator.history[10].id == 60  # position 10 after 50 evictions
    assert remediator.history[60].id == 110

    result = asyncio.run(remediator.rollback(60))
    assert result["success"] is True
    assert result["savepoint_info"] == {"savepoint_trigger_id": "sp-1", "job_id": "job-abc"}

    # The reviewer's reproduction: the entry at POSITION 60 (id 110) is a manual
    # result with nothing to roll back to, so addressing "60" must never land
    # there with success: true.
    result = asyncio.run(remediator.rollback(110))
    assert result == {"success": False, "message": "No rollback information available"}


def test_rollback_evicted_or_unknown_id_cleanly_rejected():
    ar = _ar()
    remediator = ar.AutoRemediator(flink_client=None, k8s_client=None)
    _fill(remediator, ar, ar.MAX_REMEDIATION_HISTORY + 50)
    for bad_id in (0, 49, -1, 10**9, None):  # 0..49 were evicted; None never assigned
        result = asyncio.run(remediator.rollback(bad_id))
        assert result == {"success": False, "message": "Invalid remediation id"}


def test_rollback_pre_eviction_contract_unchanged():
    """Until the deque fills, id == position, so callers that passed positional
    indices (the pre-fix REST contract) observe byte-identical behaviour."""
    ar = _ar()
    remediator = _live_remediator(ar)
    _fill(remediator, ar, 1)
    (real,) = _apply(remediator, ar, dry_run=False)  # id == 1
    _fill(remediator, ar, 1)
    assert real.id == 1

    result = asyncio.run(remediator.rollback(1))
    assert result["success"] is True
    assert result["savepoint_info"] == {"savepoint_trigger_id": "sp-1", "job_id": "job-abc"}

    # An in-range entry without rollback_info keeps its pre-fix message.
    result = asyncio.run(remediator.rollback(2))
    assert result == {"success": False, "message": "No rollback information available"}


def test_unassigned_id_is_not_addressable():
    """A RemediationResult built outside AutoRemediator has id None (not a
    sentinel int), so nothing a caller can post resolves to it."""
    ar = _ar()
    remediator = ar.AutoRemediator(flink_client=None, k8s_client=None)
    stray = ar.RemediationResult(success=True, message="", remediation_type="x")
    assert stray.id is None
    stray.rollback_info = {"savepoint_trigger_id": "sp-stray", "job_id": "job-z"}
    remediator.history.append(stray)
    for probe in (-1, 0, None):
        result = asyncio.run(remediator.rollback(probe))
        assert result == {"success": False, "message": "Invalid remediation id"}


def test_dry_runs_do_not_evict_a_real_apply_from_rollback():
    """Review round 3, item 2: one real apply followed by MAX_REMEDIATION_HISTORY
    previews used to make rollback(<real id>) fail with "Invalid remediation id"
    while the savepoint still existed, because dry runs shared the one deque.
    The rollback store is populated by real applies only."""
    ar = _ar()
    remediator = _live_remediator(ar)
    (real,) = _apply(remediator, ar, dry_run=False)
    previews = _apply(remediator, ar, dry_run=True, n=ar.MAX_REMEDIATION_HISTORY)
    assert remediator.flink_client.savepoints == 1, "previews must not savepoint"

    # The display history HAS evicted the real entry...
    assert len(remediator.history) == ar.MAX_REMEDIATION_HISTORY
    assert real.id not in {r.id for r in remediator.history}

    # ...but its savepoint is still addressable for rollback.
    result = asyncio.run(remediator.rollback(real.id))
    assert result["success"] is True
    assert result["savepoint_info"] == {"savepoint_trigger_id": "sp-1", "job_id": "job-abc"}

    # A preview's id is a known entry with nothing to roll back to — never a
    # savepoint borrowed from someone else.
    result = asyncio.run(remediator.rollback(previews[-1].id))
    assert result == {"success": False, "message": "No rollback information available"}
    assert previews[-1].rollback_info is None
    assert set(remediator._rollbacks) == {real.id}


def test_rollback_store_is_bounded_and_evicts_oldest_real_apply():
    ar = _ar()
    remediator = _live_remediator(ar)
    results = _apply(remediator, ar, dry_run=False, n=ar.MAX_ROLLBACK_ENTRIES + 5)
    assert len(remediator._rollbacks) == ar.MAX_ROLLBACK_ENTRIES
    assert list(remediator._rollbacks) == [r.id for r in results[5:]]
    for evicted in results[:5]:
        # Gone from both stores (every apply also appended to history).
        result = asyncio.run(remediator.rollback(evicted.id))
        assert result == {"success": False, "message": "Invalid remediation id"}
    kept = asyncio.run(remediator.rollback(results[5].id))
    assert kept["success"] is True
    assert kept["savepoint_info"]["savepoint_trigger_id"] == "sp-6"


def test_rollback_request_rejects_positional_index():
    """Review round 3, item 1: ``index`` was aliased to ``id``, so an old-contract
    ``{"index": 60}`` after eviction rolled back id 60 (position 10) with
    success: true. The key is now rejected outright, with a message that points
    the caller at ``history[].id``; an ambiguous body is rejected the same way."""
    main = pytest.importorskip("app.main")
    pydantic = pytest.importorskip("pydantic")
    assert main.RollbackRequest.model_validate({"id": 7}).id == 7

    for body in ({"index": 60}, {"id": 5, "index": 60}, {"index": 0}):
        with pytest.raises(pydantic.ValidationError) as excinfo:
            main.RollbackRequest.model_validate(body)
        assert "history[].id" in str(excinfo.value), body

    with pytest.raises(pydantic.ValidationError):
        main.RollbackRequest.model_validate({})


def test_remediation_audit_event_carries_id():
    """The ``remediation`` audit event must record the stable id so a later
    ``rollback_lookup`` (which audits the id it was asked for) can be joined to
    it in the log backend even after the in-memory history has evicted the entry."""
    import json
    import logging

    audit = pytest.importorskip("app.audit")
    ar = _ar()
    remediator = ar.AutoRemediator(flink_client=None, k8s_client=None)
    _fill(remediator, ar, 3)
    entry = remediator.history[2]

    records = []

    class _H(logging.Handler):
        def emit(self, record):
            records.append(record.getMessage())

    logger = logging.getLogger("app.audit")
    handler = _H()
    logger.addHandler(handler)
    try:
        audit.audit_remediation(entry)
    finally:
        logger.removeHandler(handler)

    assert len(records) == 1
    rec = json.loads(records[0])
    assert rec["event"] == "remediation"
    assert rec["id"] == entry.id == 2


# ── 4. Grafana dedup map eviction ────────────────────────────────────────────

def _poller():
    gp = pytest.importorskip("app.grafana_poller")
    return gp.GrafanaAlertPoller(None, None)


def test_evict_stale_removes_expired_keys_only():
    p = _poller()
    now = 10_000.0
    ttl = p._re_eval_interval
    p._seen[("fp1", "t1")] = now - (2 * ttl) - 1  # stale — evicted
    p._seen[("fp2", "t2")] = now - ttl            # re-evaluable, not stale — kept
    p._seen[("fp3", "t3")] = now                  # fresh — kept
    p._evict_stale(now)
    assert ("fp1", "t1") not in p._seen
    assert ("fp2", "t2") in p._seen
    assert ("fp3", "t3") in p._seen


def test_evict_stale_boundary_is_strict():
    """A key exactly at 2x the interval is kept (strict <): eviction must only
    remove keys that provably cannot change a dedup decision."""
    p = _poller()
    now = 10_000.0
    key = ("fp", "t")
    p._seen[key] = now - 2 * p._re_eval_interval
    p._evict_stale(now)
    assert key in p._seen


def test_refreshed_key_survives_sweep():
    p = _poller()
    ttl = p._re_eval_interval
    key = ("fp", "t")
    p._seen[key] = 0.0
    p._seen[key] = 3.0 * ttl  # refreshed, as the dedup loop does
    p._evict_stale(3.0 * ttl + 1)
    assert key in p._seen


def test_seen_stays_bounded_under_continuous_flapping():
    """A flapping alert adds one key per firing episode; with the sweep the map
    retains only the episodes inside the 2x re-eval window. Before the fix this
    reaches 1000 entries."""
    p = _poller()
    ttl = float(p._re_eval_interval)
    for episode in range(1000):
        t = episode * ttl
        p._seen[("fp", f"start-{episode}")] = t
        p._evict_stale(t)
    assert len(p._seen) <= 3


# ── 5. Sweep placement (structural pin) ──────────────────────────────────────

@pytest.mark.parametrize("guard_name", ["matching", "new_alerts"])
def test_poll_once_sweeps_before_each_early_return(guard_name):
    """_poll_once has two early returns after the alerts are fetched: no alert
    matches this deployment (the common quiet state) and nothing is new after
    dedup. The sweep must sit BEFORE both, or it is skipped on exactly the quiet
    cycles where nothing else trims the map."""
    tree = ast.parse((APP_DIR / "grafana_poller.py").read_text())
    poll = next(
        n for n in ast.walk(tree)
        if isinstance(n, ast.AsyncFunctionDef) and n.name == "_poll_once"
    )
    evict_calls = [
        n.lineno for n in ast.walk(poll)
        if isinstance(n, ast.Call)
        and isinstance(n.func, ast.Attribute)
        and n.func.attr == "_evict_stale"
    ]
    guards = [
        n.lineno for n in ast.walk(poll)
        if isinstance(n, ast.If)
        and isinstance(n.test, ast.UnaryOp)
        and isinstance(n.test.op, ast.Not)
        and isinstance(n.test.operand, ast.Name)
        and n.test.operand.id == guard_name
    ]
    assert evict_calls, "_poll_once no longer calls _evict_stale"
    assert guards, f"`if not {guard_name}:` guard not found in _poll_once"
    assert min(evict_calls) < min(guards), (
        f"_evict_stale must be called BEFORE the `if not {guard_name}: return` "
        "guard, otherwise the sweep never runs on that kind of quiet cycle"
    )
