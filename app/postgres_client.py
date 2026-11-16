# Copyright Yahoo, Licensed under the terms of the Apache 2.0 license. See LICENSE for terms.

import os
import json
import ssl
import asyncio
import logging
import time
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from typing import Dict, List, Optional

import asyncpg

from app import secret_provider
from app.egress_policy import validate_host
from app.safe_errors import client_error

logger = logging.getLogger(__name__)

# LIKE escape character, stated explicitly in every query via `ESCAPE '\'`
# rather than inherited from the server default.
LIKE_ESCAPE = "\\"


def _like_contains(value: str) -> str:
    """Build a LIKE contains-pattern in which `value` is matched literally.

    `%` and `_` are LIKE metacharacters: left unescaped, a value containing
    them would broaden the match (a bare `%` matches every row). The escape
    character itself must be escaped first, or the later substitutions would
    double the backslashes they introduce. Must be used with a query whose
    pattern placeholder carries the explicit `ESCAPE '\\'` clause.
    """
    escaped = (
        value.replace(LIKE_ESCAPE, LIKE_ESCAPE * 2)
        .replace("%", LIKE_ESCAPE + "%")
        .replace("_", LIKE_ESCAPE + "_")
    )
    return f"%{escaped}%"


# Cap concurrent pool holds (CWE-770) across the WHOLE process: an unbounded
# 8-way gather holds 8 of the pool's max_size=10 connections at once — and the
# target is the Flink operator's SHARED autoscaler state store, so saturating it
# degrades autoscaling for every FlinkDeployment the operator manages.
AUTOSCALER_GATHER_CONCURRENCY = 2

# One semaphore per running loop (pytest creates a fresh loop per test, and a
# semaphore bound to a dead loop misbehaves).
_autoscaler_semaphores: "dict[object, asyncio.Semaphore]" = {}


def _autoscaler_gather_semaphore() -> asyncio.Semaphore:
    loop = asyncio.get_running_loop()
    sem = _autoscaler_semaphores.get(loop)
    if sem is None:
        sem = asyncio.Semaphore(AUTOSCALER_GATHER_CONCURRENCY)
        _autoscaler_semaphores[loop] = sem
    return sem

# Bound every Pool.acquire() wait (CWE-1088): asyncpg's default is timeout=None,
# so a saturated pool blocks callers indefinitely. NOTE: `timeout=` on
# create_pool is NOT the same lever — asyncpg forwards it to connect() and it
# bounds connection establishment only; the acquire wait must be bounded at
# each acquire() call (all of which go through PostgresStateReader._acquire).
POOL_ACQUIRE_TIMEOUT_SECONDS = 5


def postgres_enabled() -> bool:
    """PostgreSQL autoscaler integration is OPT-IN (default off).

    The integration reaches an external RDS instance with real credentials, so it
    must never be live implicitly: a deployment enables it by setting
    POSTGRES_ENABLED=true explicitly. Deployment manifests should set the variable
    explicitly (the example manifest sets 'false'), so this default only governs
    bare/dev runs — which must be
    fail-secure.
    """
    return os.getenv("POSTGRES_ENABLED", "false").lower() == "true"


class PostgresStateReader:
    def __init__(self):
        self.enabled = postgres_enabled()
        self.host: Optional[str] = None
        self.port: Optional[int] = None
        self.database: Optional[str] = None
        self.user: Optional[str] = None
        self.pool: Optional[asyncpg.Pool] = None
        # Disabled (the shipped default): nothing is read or validated. The
        # POSTGRES_* variables are then inert and may be absent, stale or point
        # at a host outside EGRESS_ALLOWED_HOSTS without affecting startup —
        # no credential will ever be sent there because connect() is gated on
        # the same flag. Enabled: validate at construction (fail closed).
        if self.enabled:
            self._configure()

    def _configure(self) -> None:
        # The connection carries the DB password from the secret provider, so the host is
        # subject to EGRESS_ALLOWED_HOSTS like every other credential-bearing
        # destination (fail closed at construction). Transport encryption is
        # enforced separately in connect() via ssl.create_default_context().
        self.host = validate_host(
            os.getenv("POSTGRES_HOST", "localhost"), name="POSTGRES_HOST",
            allow_loopback=True,
        )
        self.port = int(os.getenv("POSTGRES_PORT", "5432"))
        self.database = os.getenv("POSTGRES_DB", "flink_autoscaler")
        self.user = os.getenv("POSTGRES_USER", "flink")

    @staticmethod
    def _password() -> str:
        # Evaluated by asyncpg for EACH new (pool-spawned) connection, so a
        # password rotated in a live secret backend propagates to reconnects without a
        # restart (SECRET_PROVIDER=env values change only on a pod restart).
        # Deliberately a non-refetching peek: asyncpg calls this inside
        # Pool.acquire(timeout=POOL_ACQUIRE_TIMEOUT_SECONDS), where a secret-backend
        # round-trip would blow the acquire timeout. The TTL /
        # invalidation re-fetch happens in _refresh_password, off the event
        # loop and BEFORE the acquire, so this only reads what it produced.
        return secret_provider.peek_postgres_password()

    @staticmethod
    async def _refresh_password() -> None:
        # TTL / invalidation re-fetch (possibly a secret-backend round-trip) — in a worker
        # thread, outside any acquire timeout. Raises (fail closed) when an
        # invalidated password's re-fetch failed.
        await asyncio.to_thread(secret_provider.get_postgres_password)

    async def _acquire(self) -> asyncpg.Connection:
        """Acquire a pooled connection, invalidating the cached password and
        retrying once when the server rejects it (SQLSTATE class 28,
        InvalidAuthorizationSpecificationError — the parent of 28P01
        InvalidPasswordError) — a rotation during the run must not fail new
        connections until the TTL expires. Established connections are
        unaffected: Postgres does not re-authenticate a live session."""
        await self._refresh_password()
        try:
            return await self.pool.acquire(timeout=POOL_ACQUIRE_TIMEOUT_SECONDS)
        except asyncpg.exceptions.InvalidAuthorizationSpecificationError:
            # Message carries no secret.
            logger.warning("PostgreSQL authentication failed — invalidating cached password and retrying with a fresh fetch")
            secret_provider.invalidate_postgres_password()
            await self._refresh_password()
            return await self.pool.acquire(timeout=POOL_ACQUIRE_TIMEOUT_SECONDS)

    @asynccontextmanager
    async def _connection(self):
        conn = await self._acquire()
        try:
            yield conn
        finally:
            await self.pool.release(conn)

    async def connect(self):
        # Constructed disabled but connected anyway (a caller bypassing the
        # POSTGRES_ENABLED gate): validate the host now — a credential never
        # leaves for an unvalidated destination.
        if self.host is None:
            self._configure()

        async def _create_pool():
            await self._refresh_password()
            ssl_context = ssl.create_default_context()
            return await asyncpg.create_pool(
                host=self.host,
                port=self.port,
                database=self.database,
                user=self.user,
                password=self._password,
                ssl=ssl_context,
                min_size=2,
                max_size=10,
                command_timeout=30,
            )

        try:
            try:
                self.pool = await _create_pool()
            except asyncpg.exceptions.InvalidAuthorizationSpecificationError:
                # Cached password is stale (rotated in the secret backend): invalidate to force
                # a fresh fetch, then retry once. Class 28 (28000 and its child
                # 28P01) covers every authentication rejection. Message carries no secret.
                logger.warning("PostgreSQL authentication failed — invalidating cached password and retrying with a fresh fetch")
                secret_provider.invalidate_postgres_password()
                self.pool = await _create_pool()
            logger.info("Connected to PostgreSQL at %s:%s/%s (TLS enabled)", self.host, self.port, self.database)
        except Exception as e:
            logger.error("Failed to connect to PostgreSQL: %s", e)
            raise

    async def close(self):
        if self.pool:
            await self.pool.close()
            logger.info("PostgreSQL connection pool closed")

    # ── State Store Methods ──────────────────────────────────────────

    async def get_autoscaler_state(self, job_id: str) -> Dict:
        if not self.pool:
            return {"error": "Not connected to PostgreSQL"}
        try:
            async with self._connection() as conn:
                rows = await conn.fetch(
                    """
                    SELECT job_key, state_value, update_time
                    FROM t_flink_autoscaler_state_store
                    WHERE job_key LIKE $1 ESCAPE '\\'
                    ORDER BY update_time DESC
                    """,
                    _like_contains(job_id),
                )
                if not rows:
                    return {"state": None, "message": "No autoscaler state found"}
                states = []
                for row in rows:
                    try:
                        state_value = json.loads(row["state_value"])
                    except (json.JSONDecodeError, TypeError):
                        state_value = row["state_value"]
                    states.append({
                        "job_key": row["job_key"],
                        "state": state_value,
                        "last_update": row["update_time"].isoformat(),
                    })
                return {
                    "current_state": states[0] if states else None,
                    "all_states": states,
                    "total_entries": len(states),
                }
        except Exception as e:
            # Inert on the shipped config (POSTGRES_ENABLED=false) — fixed for
            # consistency with the client-layer opaque-error idiom (CWE-209).
            return {"error": client_error("read autoscaler state", e)}

    async def get_scaling_history(self, job_id: str, hours: int = 5) -> List[Dict]:
        if not self.pool:
            return []
        try:
            cutoff = datetime.utcnow() - timedelta(hours=hours)
            async with self._connection() as conn:
                rows = await conn.fetch(
                    """
                    SELECT job_key, state_value, update_time
                    FROM t_flink_autoscaler_state_store
                    WHERE job_key LIKE $1 ESCAPE '\\' AND update_time >= $2
                    ORDER BY update_time DESC
                    """,
                    _like_contains(job_id),
                    cutoff,
                )
                history = []
                for row in rows:
                    try:
                        state_value = json.loads(row["state_value"])
                    except (json.JSONDecodeError, TypeError):
                        state_value = row["state_value"]
                    parallelism = {}
                    metrics = {}
                    if isinstance(state_value, dict):
                        parallelism = state_value.get("parallelism", {})
                        metrics = state_value.get("scalingMetrics", {})
                    history.append({
                        "job_key": row["job_key"],
                        "timestamp": row["update_time"].isoformat(),
                        "parallelism": parallelism,
                        "metrics": metrics,
                    })
                return history
        except Exception as e:
            logger.error("Error fetching scaling history: %s", e)
            return []

    async def get_scaling_decisions(self, job_id: str, hours: int = 5) -> List[Dict]:
        if not self.pool:
            return []
        try:
            cutoff = datetime.utcnow() - timedelta(hours=hours)
            async with self._connection() as conn:
                rows = await conn.fetch(
                    """
                    SELECT job_key, state_value, update_time
                    FROM t_flink_autoscaler_state_store
                    WHERE job_key LIKE $1 ESCAPE '\\' AND update_time >= $2
                    ORDER BY update_time DESC
                    """,
                    _like_contains(job_id),
                    cutoff,
                )
                decisions = []
                for row in rows:
                    try:
                        state_value = json.loads(row["state_value"])
                    except (json.JSONDecodeError, TypeError):
                        continue
                    if isinstance(state_value, dict) and "scalingDecision" in state_value:
                        decisions.append({
                            "job_key": row["job_key"],
                            "timestamp": row["update_time"].isoformat(),
                            "decision": state_value["scalingDecision"],
                            "reason": state_value.get("scalingReason", ""),
                            "parallelism": state_value.get("parallelism", {}),
                        })
                return decisions
        except Exception as e:
            logger.error("Error fetching scaling decisions: %s", e)
            return []

    async def get_metrics_history(self, job_id: str, hours: int = 5) -> List[Dict]:
        if not self.pool:
            return []
        try:
            cutoff = datetime.utcnow() - timedelta(hours=hours)
            async with self._connection() as conn:
                rows = await conn.fetch(
                    """
                    SELECT job_key, state_value, update_time
                    FROM t_flink_autoscaler_state_store
                    WHERE job_key LIKE $1 ESCAPE '\\' AND update_time >= $2
                    ORDER BY update_time ASC
                    """,
                    _like_contains(job_id),
                    cutoff,
                )
                metrics_list = []
                for row in rows:
                    try:
                        state_value = json.loads(row["state_value"])
                    except (json.JSONDecodeError, TypeError):
                        continue
                    if isinstance(state_value, dict):
                        metrics_list.append({
                            "timestamp": row["update_time"].isoformat(),
                            "metrics": state_value.get("scalingMetrics", {}),
                            "parallelism": state_value.get("parallelism", {}),
                        })
                return metrics_list
        except Exception as e:
            logger.error("Error fetching metrics history: %s", e)
            return []

    async def get_configuration_changes(self, job_id: str, hours: int = 24) -> List[Dict]:
        if not self.pool:
            return []
        try:
            cutoff = datetime.utcnow() - timedelta(hours=hours)
            async with self._connection() as conn:
                rows = await conn.fetch(
                    """
                    SELECT job_key, state_value, update_time
                    FROM t_flink_autoscaler_state_store
                    WHERE job_key LIKE $1 ESCAPE '\\' AND update_time >= $2
                    ORDER BY update_time ASC
                    """,
                    _like_contains(job_id),
                    cutoff,
                )
                changes = []
                prev_config = None
                for row in rows:
                    try:
                        state_value = json.loads(row["state_value"])
                    except (json.JSONDecodeError, TypeError):
                        continue
                    if isinstance(state_value, dict):
                        current_config = state_value.get("configuration", {})
                        if prev_config is not None and current_config != prev_config:
                            changes.append({
                                "timestamp": row["update_time"].isoformat(),
                                "previous": prev_config,
                                "current": current_config,
                            })
                        prev_config = current_config
                return changes
        except Exception as e:
            logger.error("Error fetching configuration changes: %s", e)
            return []

    # ── Event Store Methods ──────────────────────────────────────────

    async def get_autoscaler_events(
        self,
        job_id: str,
        hours: int = 24,
        event_types: Optional[List[str]] = None,
    ) -> List[Dict]:
        if not self.pool:
            return []
        try:
            cutoff = datetime.utcnow() - timedelta(hours=hours)
            async with self._connection() as conn:
                if event_types:
                    rows = await conn.fetch(
                        """
                        SELECT event_key, job_key, event_type, reason, message,
                               event_count, create_time, update_time
                        FROM t_flink_autoscaler_event_handler
                        WHERE job_key LIKE $1 ESCAPE '\\' AND update_time >= $2 AND event_type = ANY($3)
                        ORDER BY update_time DESC
                        """,
                        _like_contains(job_id),
                        cutoff,
                        event_types,
                    )
                else:
                    rows = await conn.fetch(
                        """
                        SELECT event_key, job_key, event_type, reason, message,
                               event_count, create_time, update_time
                        FROM t_flink_autoscaler_event_handler
                        WHERE job_key LIKE $1 ESCAPE '\\' AND update_time >= $2
                        ORDER BY update_time DESC
                        """,
                        _like_contains(job_id),
                        cutoff,
                    )
                return [
                    {
                        "event_key": row["event_key"],
                        "job_key": row["job_key"],
                        "event_type": row["event_type"],
                        "reason": row["reason"],
                        "message": row["message"],
                        "event_count": row["event_count"],
                        "create_time": row["create_time"].isoformat(),
                        "update_time": row["update_time"].isoformat(),
                    }
                    for row in rows
                ]
        except Exception as e:
            logger.error("Error fetching autoscaler events: %s", e)
            return []

    async def get_scaling_events(self, job_id: str, hours: int = 24) -> List[Dict]:
        return await self.get_autoscaler_events(
            job_id, hours, event_types=["ScalingReport"]
        )

    async def get_autoscaler_errors(self, job_id: str, hours: int = 24) -> List[Dict]:
        return await self.get_autoscaler_events(
            job_id, hours, event_types=["AutoscalerError", "Warning"]
        )

    async def analyze_autoscaler_events(self, job_id: str, hours: int = 24) -> Dict:
        events = await self.get_autoscaler_events(job_id, hours)
        if not events:
            return {
                "total_events": 0,
                "event_types": {},
                "reasons": {},
                "error_count": 0,
                "warning_count": 0,
                "recent_errors": [],
            }

        event_type_counts: Dict[str, int] = {}
        reason_counts: Dict[str, int] = {}
        errors = []
        warnings = []

        for event in events:
            et = event.get("event_type", "Unknown")
            event_type_counts[et] = event_type_counts.get(et, 0) + 1
            reason = event.get("reason", "Unknown")
            reason_counts[reason] = reason_counts.get(reason, 0) + 1
            if et == "AutoscalerError":
                errors.append(event)
            elif et == "Warning":
                warnings.append(event)

        return {
            "total_events": len(events),
            "event_types": event_type_counts,
            "reasons": reason_counts,
            "error_count": len(errors),
            "warning_count": len(warnings),
            "recent_errors": errors[:10],
            "recent_warnings": warnings[:10],
            "time_range_hours": hours,
        }

    # ── Comprehensive Info ───────────────────────────────────────────

    async def get_comprehensive_autoscaler_info(
        self, job_id: str, hours: int = 5
    ) -> Dict:
        # Process-wide bound, not per-call: constructed inside this method every
        # caller got its OWN semaphore, so 5 concurrent /api/diagnostics/full
        # still took 10 of the pool's 10 connections. The acceptance test asserts
        # a peak over pg_stat_activity, which only a shared bound can satisfy.
        semaphore = _autoscaler_gather_semaphore()

        async def _bounded(coro):
            async with semaphore:
                return await coro

        results = await asyncio.gather(
            _bounded(self.get_autoscaler_state(job_id)),
            _bounded(self.get_scaling_history(job_id, hours)),
            _bounded(self.get_scaling_decisions(job_id, hours)),
            _bounded(self.get_autoscaler_events(job_id, hours * 5)),
            _bounded(self.get_autoscaler_errors(job_id, hours * 5)),
            _bounded(self.analyze_autoscaler_events(job_id, hours * 5)),
            _bounded(self.get_metrics_history(job_id, hours)),
            _bounded(self.get_configuration_changes(job_id, hours * 5)),
            return_exceptions=True,
        )

        def safe_result(idx, default):
            r = results[idx]
            return default if isinstance(r, Exception) else r

        return {
            "current_state": safe_result(0, {}),
            "state_history": safe_result(1, []),
            "scaling_decisions": safe_result(2, []),
            "all_events": safe_result(3, []),
            "error_events": safe_result(4, []),
            "event_analysis": safe_result(5, {}),
            "metrics_history": safe_result(6, []),
            "config_changes": safe_result(7, []),
        }

    # ── Utilities ────────────────────────────────────────────────────

    async def verify_tables_exist(self) -> Dict:
        if not self.pool:
            return {"connected": False, "error": "Not connected to PostgreSQL"}
        try:
            async with self._connection() as conn:
                tables = await conn.fetch(
                    """
                    SELECT table_name FROM information_schema.tables
                    WHERE table_schema = 'public'
                    AND table_name IN ('t_flink_autoscaler_state_store', 't_flink_autoscaler_event_handler')
                    """
                )
                found = [row["table_name"] for row in tables]
                return {
                    "connected": True,
                    "state_store_exists": "t_flink_autoscaler_state_store" in found,
                    "event_store_exists": "t_flink_autoscaler_event_handler" in found,
                    "tables_found": found,
                }
        except Exception as e:
            return {"connected": False, "error": client_error("verify PostgreSQL tables", e)}

    # Four full-table scans per call: cache a successful result briefly so a
    # polling client cannot turn the status route into a database load.
    _STATS_CACHE_SECONDS = 30.0

    async def get_table_statistics(self) -> Dict:
        if not self.pool:
            return {"error": "Not connected to PostgreSQL"}
        cached = getattr(self, "_stats_cache", None)
        now = time.monotonic()
        if cached is not None and now - cached[0] < self._STATS_CACHE_SECONDS:
            return cached[1]
        result = await self._read_table_statistics()
        if "error" not in result:
            self._stats_cache = (now, result)
        return result

    async def _read_table_statistics(self) -> Dict:
        try:
            async with self._connection() as conn:
                state_count = await conn.fetchval(
                    "SELECT COUNT(*) FROM t_flink_autoscaler_state_store"
                )
                event_count = await conn.fetchval(
                    "SELECT COUNT(*) FROM t_flink_autoscaler_event_handler"
                )
                latest_state = await conn.fetchval(
                    "SELECT MAX(update_time) FROM t_flink_autoscaler_state_store"
                )
                latest_event = await conn.fetchval(
                    "SELECT MAX(update_time) FROM t_flink_autoscaler_event_handler"
                )
                return {
                    "state_store": {
                        "row_count": state_count,
                        "latest_update": latest_state.isoformat() if latest_state else None,
                    },
                    "event_store": {
                        "row_count": event_count,
                        "latest_update": latest_event.isoformat() if latest_event else None,
                    },
                }
        except Exception as e:
            return {"error": client_error("read table statistics", e)}
