# Copyright Yahoo, Licensed under the terms of the Apache 2.0 license. See LICENSE for terms.

import itertools
import os
import json
import logging
import asyncio
from collections import OrderedDict, deque
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional
from dataclasses import dataclass, field

import aiohttp
from kubernetes.client.rest import ApiException

from app import telemetry
from app.kubernetes_client import (
    ALLOWED_FLINK_CONFIG_KEYS,
    K8S_REQUEST_TIMEOUT,
    flink_config_rejections,
    k8s_call,
)
from app.safe_errors import client_error

logger = logging.getLogger(__name__)


class RiskLevel(str, Enum):
    SAFE = "safe"
    MEDIUM = "medium"
    MANUAL = "manual"


class RemediationType(str, Enum):
    INCREASE_CHECKPOINT_TIMEOUT = "increase_checkpoint_timeout"
    ENABLE_INCREMENTAL_CHECKPOINTS = "enable_incremental_checkpoints"
    ADJUST_CHECKPOINT_INTERVAL = "adjust_checkpoint_interval"
    STABILIZE_AUTOSCALER = "stabilize_autoscaler"
    CREATE_EMERGENCY_SAVEPOINT = "create_emergency_savepoint"
    INCREASE_TM_MEMORY = "increase_tm_memory"
    INCREASE_NETWORK_BUFFERS = "increase_network_buffers"
    CONVERT_BLOCKING_IO = "convert_blocking_io"
    FIX_DATA_SKEWNESS = "fix_data_skewness"


REMEDIATION_CATALOG = {
    RemediationType.INCREASE_CHECKPOINT_TIMEOUT: {
        "description": "Increase checkpoint timeout to prevent checkpoint failures due to slow operations",
        "risk_level": RiskLevel.SAFE,
        "requires_restart": False,
        "auto_applicable": True,
        "config_key": "execution.checkpointing.timeout",
        "default_value": "600000",  # 10 minutes
    },
    RemediationType.ENABLE_INCREMENTAL_CHECKPOINTS: {
        "description": "Enable incremental checkpoints to reduce checkpoint size and duration",
        "risk_level": RiskLevel.SAFE,
        "requires_restart": False,
        "auto_applicable": True,
        "config_key": "state.backend.incremental",
        "default_value": "true",
    },
    RemediationType.ADJUST_CHECKPOINT_INTERVAL: {
        "description": "Adjust checkpoint interval to balance recovery time vs performance overhead",
        "risk_level": RiskLevel.SAFE,
        "requires_restart": False,
        "auto_applicable": True,
        "config_key": "execution.checkpointing.interval",
        "default_value": "180000",  # 3 minutes
    },
    RemediationType.STABILIZE_AUTOSCALER: {
        "description": "Adjust autoscaler settings to prevent scaling oscillation (increase stabilization window, adjust thresholds)",
        "risk_level": RiskLevel.SAFE,
        "requires_restart": False,
        "auto_applicable": True,
        "config_changes": {
            "job.autoscaler.stabilization.interval": "5min",
            "job.autoscaler.scale-down.max-factor": "0.5",
            "job.autoscaler.metrics.window": "10min",
        },
    },
    RemediationType.CREATE_EMERGENCY_SAVEPOINT: {
        "description": "Create an emergency savepoint for the running job",
        "risk_level": RiskLevel.SAFE,
        "requires_restart": False,
        "auto_applicable": True,
    },
    RemediationType.INCREASE_TM_MEMORY: {
        "description": "Increase TaskManager memory allocation to prevent OOM errors (requires pod restart)",
        "risk_level": RiskLevel.MEDIUM,
        "requires_restart": True,
        "auto_applicable": True,
        "config_key": "taskmanager.memory.process.size",
        "default_value": "4096m",
    },
    RemediationType.INCREASE_NETWORK_BUFFERS: {
        "description": "Increase network buffer count to reduce backpressure (requires pod restart)",
        "risk_level": RiskLevel.MEDIUM,
        "requires_restart": True,
        "auto_applicable": True,
        "config_key": "taskmanager.network.memory.fraction",
        "default_value": "0.15",
    },
    RemediationType.CONVERT_BLOCKING_IO: {
        "description": "Convert blocking I/O calls to async operations to eliminate thread blocking",
        "risk_level": RiskLevel.MANUAL,
        "requires_restart": True,
        "auto_applicable": False,
        "code_example": """
// Instead of blocking JDBC calls in processElement():
// BAD:
public void processElement(Event event, Context ctx, Collector<Result> out) {
    Result result = jdbcTemplate.query(sql, params);  // BLOCKS!
    out.collect(result);
}

// GOOD - Use AsyncFunction:
public class AsyncDatabaseLookup extends RichAsyncFunction<Event, Result> {
    @Override
    public void asyncInvoke(Event event, ResultFuture<Result> resultFuture) {
        CompletableFuture.supplyAsync(() -> {
            return jdbcTemplate.query(sql, params);
        }, executor).thenAccept(result -> {
            resultFuture.complete(Collections.singleton(result));
        });
    }
}

// Apply with:
AsyncDataStream.unorderedWait(inputStream, new AsyncDatabaseLookup(),
    30, TimeUnit.SECONDS, 100);
""",
    },
    RemediationType.FIX_DATA_SKEWNESS: {
        "description": "Fix data skewness by implementing better partitioning strategies",
        "risk_level": RiskLevel.MANUAL,
        "requires_restart": True,
        "auto_applicable": False,
        "code_example": """
// Strategy 1: Add salt key for hot keys
stream.keyBy(event -> event.getKey() + "_" + (event.hashCode() % NUM_SALT_BUCKETS))

// Strategy 2: Use rebalance() before heavy operators
stream.rebalance()
      .process(new HeavyProcessFunction());

// Strategy 3: Two-phase aggregation
// Phase 1: Pre-aggregate with salted keys
stream.keyBy(event -> event.getKey() + "_" + random.nextInt(10))
      .window(TumblingEventTimeWindows.of(Time.minutes(1)))
      .reduce(new PreAggregator())
// Phase 2: Final aggregation with original key
      .keyBy(result -> result.getOriginalKey())
      .window(TumblingEventTimeWindows.of(Time.minutes(1)))
      .reduce(new FinalAggregator());
""",
    },
}


@dataclass
class RemediationAction:
    type: RemediationType
    description: str
    risk_level: RiskLevel
    requires_restart: bool
    auto_applicable: bool
    config_changes: Dict = field(default_factory=dict)
    code_example: Optional[str] = None
    rollback_possible: bool = True

    def to_dict(self) -> Dict:
        return {
            "type": self.type.value,
            "description": self.description,
            "risk_level": self.risk_level.value,
            "requires_restart": self.requires_restart,
            "auto_applicable": self.auto_applicable,
            "config_changes": self.config_changes,
            "code_example": self.code_example,
            "rollback_possible": self.rollback_possible,
        }


@dataclass
class RemediationResult:
    success: bool
    message: str
    remediation_type: str
    applied_at: str = ""
    applied_by: str = ""
    dry_run: bool = False
    backup_created: Optional[str] = None
    changes_made: Dict = field(default_factory=dict)
    rollback_info: Optional[Dict] = None
    # Stable identity for rollback lookup: assigned once by AutoRemediator at
    # construction and never reused. The history collection is a bounded deque,
    # so a POSITION in it changes meaning once eviction starts; this id does not.
    # None (not a sentinel int) for a result built outside AutoRemediator, so an
    # unassigned id can never be addressed through rollback().
    id: Optional[int] = None

    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "success": self.success,
            "message": self.message,
            "remediation_type": self.remediation_type,
            "applied_at": self.applied_at,
            "applied_by": self.applied_by,
            "dry_run": self.dry_run,
            "backup_created": self.backup_created,
            "changes_made": self.changes_made,
            "rollback_info": self.rollback_info,
        }


# Bound on the in-memory remediation history (CWE-770). Remediations are rare,
# operator- or alert-triggered events, so 200 entries is far more than a single
# pod lifetime produces; the bound also caps the GET /api/remediation/history
# response, which returns the whole collection with no pagination. Mirrors the
# bounded-deque pattern in app/metrics_collector.py (MAX_HISTORY_SIZE).
MAX_REMEDIATION_HISTORY = 200

# Bound on the rollback lookup store (id -> rollback_info). Kept SEPARATE from
# ``history`` so that display-only outcomes (dry-run previews, manual/no-op
# results, "no running job") cannot evict a real apply's savepoint reference:
# with a single shared deque, one real apply followed by 200 previews made
# ``rollback(<real id>)`` fail with "Invalid remediation id" while the
# savepoint still existed. Only real applies that recorded a savepoint enter
# this map, so 200 entries here means 200 REAL applies in one pod lifetime.
MAX_ROLLBACK_ENTRIES = MAX_REMEDIATION_HISTORY


def _env_seconds(name: str, default: float, lo: float, hi: float) -> float:
    """Finite, clamped seconds from the environment; never raises."""
    try:
        value = float(os.getenv(name, "").strip() or default)
    except ValueError:
        return default
    if value != value or value in (float("inf"), float("-inf")):
        return default
    return min(max(value, lo), hi)


class AutoRemediator:
    def __init__(self, flink_client, k8s_client):
        self.flink_client = flink_client
        self.k8s_client = k8s_client
        # Bounded (CWE-770/CWE-401): a plain list grew for the pod's lifetime.
        # deque(maxlen=...) evicts the oldest entry in O(1) on append, so the
        # memory footprint is a function of configuration, not of uptime.
        self.history: deque = deque(maxlen=MAX_REMEDIATION_HISTORY)
        # Rollback lookup store: RemediationResult.id -> rollback_info, populated
        # ONLY where a real (non-dry-run) apply records a savepoint. Insertion-
        # ordered so the oldest real apply is the one evicted at the bound.
        self._rollbacks: "OrderedDict[int, Dict]" = OrderedDict()
        # Monotonic source for RemediationResult.id — never reset or reused, so
        # an id handed out via GET /api/remediation/history stays meaningful
        # (resolves to its entry, or is cleanly rejected once evicted) even
        # after the deque starts evicting. itertools.count (as in app/audit.py)
        # is a single C-level next() call, so no read-then-increment window.
        self._next_result_id = itertools.count()

    def generate_remediations(
        self, issues: List[Dict], context: Dict
    ) -> List[RemediationAction]:
        remediations = []
        seen_types = set()

        for issue in issues:
            issue_type = issue.get("type", "")
            severity = issue.get("severity", "")
            message = (issue.get("message", "") or "").lower()

            # Checkpoint issues
            if any(k in issue_type for k in ["checkpoint", "slow_checkpoint"]) or "checkpoint" in message:
                if RemediationType.INCREASE_CHECKPOINT_TIMEOUT not in seen_types:
                    remediations.append(self._create_action(RemediationType.INCREASE_CHECKPOINT_TIMEOUT))
                    seen_types.add(RemediationType.INCREASE_CHECKPOINT_TIMEOUT)
                if RemediationType.ENABLE_INCREMENTAL_CHECKPOINTS not in seen_types:
                    remediations.append(self._create_action(RemediationType.ENABLE_INCREMENTAL_CHECKPOINTS))
                    seen_types.add(RemediationType.ENABLE_INCREMENTAL_CHECKPOINTS)
                if "high_failure_rate" in issue_type:
                    if RemediationType.ADJUST_CHECKPOINT_INTERVAL not in seen_types:
                        remediations.append(self._create_action(RemediationType.ADJUST_CHECKPOINT_INTERVAL))
                        seen_types.add(RemediationType.ADJUST_CHECKPOINT_INTERVAL)

            # Backpressure issues
            if "backpressure" in issue_type or "backpressure" in message:
                if RemediationType.INCREASE_NETWORK_BUFFERS not in seen_types:
                    remediations.append(self._create_action(RemediationType.INCREASE_NETWORK_BUFFERS))
                    seen_types.add(RemediationType.INCREASE_NETWORK_BUFFERS)

            # Blocked threads / I/O
            if "blocked" in issue_type or "io_waiting" in issue_type or "blocking" in message:
                if RemediationType.CONVERT_BLOCKING_IO not in seen_types:
                    remediations.append(self._create_action(RemediationType.CONVERT_BLOCKING_IO))
                    seen_types.add(RemediationType.CONVERT_BLOCKING_IO)

            # OOM
            if "oom" in issue_type or "memory" in message or "out of memory" in message:
                if RemediationType.INCREASE_TM_MEMORY not in seen_types:
                    remediations.append(self._create_action(RemediationType.INCREASE_TM_MEMORY))
                    seen_types.add(RemediationType.INCREASE_TM_MEMORY)

            # Skewness
            if "skew" in issue_type or "skew" in message:
                if RemediationType.FIX_DATA_SKEWNESS not in seen_types:
                    remediations.append(self._create_action(RemediationType.FIX_DATA_SKEWNESS))
                    seen_types.add(RemediationType.FIX_DATA_SKEWNESS)

            # Autoscaler oscillation
            if "autoscaler" in issue_type or "oscillat" in message or "scaling" in message:
                if RemediationType.STABILIZE_AUTOSCALER not in seen_types:
                    remediations.append(self._create_action(RemediationType.STABILIZE_AUTOSCALER))
                    seen_types.add(RemediationType.STABILIZE_AUTOSCALER)

        return remediations

    def create_action(self, rtype: RemediationType) -> RemediationAction:
        """Build a RemediationAction from the catalog, handling BOTH catalog
        shapes (`config_key`/`default_value` and `config_changes`).

        This is the ONLY sanctioned constructor for catalogued actions: every
        caller (REST route, agent tool, internal generator) must use it. A
        hand-built action that reads only `config_changes` silently produces an
        empty change set for the five `config_key`-shaped types — which fired a
        real savepoint and then applied nothing (CWE-670).
        """
        catalog = REMEDIATION_CATALOG[rtype]
        config_changes = {}
        if "config_key" in catalog:
            config_changes[catalog["config_key"]] = catalog["default_value"]
        elif "config_changes" in catalog:
            config_changes = catalog["config_changes"]

        return RemediationAction(
            type=rtype,
            description=catalog["description"],
            risk_level=catalog["risk_level"],
            requires_restart=catalog["requires_restart"],
            auto_applicable=catalog["auto_applicable"],
            config_changes=config_changes,
            code_example=catalog.get("code_example"),
        )

    # Backwards-compatible alias: existing call sites / tests use the private
    # name. New code should call create_action.
    _create_action = create_action

    async def apply_remediation(
        self,
        remediation: RemediationAction,
        applied_by: str = "system",
        *,
        # No default, keyword-only: this is the savepoint-triggering sink, and the
        # live path fires a REAL savepoint against the running job before
        # patching. Every caller must state intent by name — omission is a
        # TypeError, never a silent apply and never a silent preview. The
        # preview-by-default posture lives at the two surfaces where a caller can
        # actually omit the flag: the agent tool schema (langgraph_agent.py) and
        # the REST RemediationRequest model (main.py), both of which default to
        # dry_run=True and pass it through here explicitly.
        dry_run: bool,
    ) -> RemediationResult:
        result = RemediationResult(
            success=False,
            message="",
            remediation_type=remediation.type.value,
            applied_at=datetime.utcnow().isoformat(),
            applied_by=applied_by,
            dry_run=dry_run,
            id=next(self._next_result_id),
        )

        if not remediation.auto_applicable:
            result.message = (
                f"This remediation ({remediation.type.value}) requires manual code changes. "
                f"See the code example for guidance."
            )
            result.changes_made = {"code_example": remediation.code_example}
            self.history.append(result)
            return result

        # Fail-early integrity guard (CWE-670): an auto-applicable remediation
        # with no config changes (other than the savepoint-only type) is a
        # construction defect. Refuse BEFORE the savepoint fires so a real
        # savepoint is never taken for a patch that cannot happen, and the
        # caller gets an explicit failure instead of a success-shaped result
        # with an empty message. Applies to dry runs too, so the preview is
        # honest rather than "success: true" with empty changes.
        if (
            remediation.type != RemediationType.CREATE_EMERGENCY_SAVEPOINT
            and not remediation.config_changes
        ):
            result.message = (
                f"No configuration changes are defined for {remediation.type.value} — "
                "nothing was applied. This is a defect in how the remediation action "
                "was constructed, not a successful no-op."
            )
            telemetry.record_remediation(remediation.type.value, dry_run, "error")
            self.history.append(result)
            return result

        # Create savepoint backup before making changes
        job_id = await self.flink_client.get_running_job_id()
        if not job_id:
            result.message = "No running Flink job found"
            self.history.append(result)
            return result

        # A live remediation patches the job only after its backup savepoint has
        # COMPLETED (CWE-636). A trigger id only means Flink accepted the
        # request; the savepoint can still fail later (no savepoint directory,
        # storage error, timeout). Any failure here stops the remediation and is
        # reported, so a patch never lands with nothing to roll back to. The
        # emergency-savepoint type IS the savepoint and is handled below.
        if (
            remediation.rollback_possible
            and not dry_run
            and remediation.type != RemediationType.CREATE_EMERGENCY_SAVEPOINT
        ):
            try:
                trigger_id = await self._completed_savepoint(job_id)
            except Exception as e:
                result.message = client_error("create savepoint before remediation", e)
                telemetry.record_remediation(remediation.type.value, dry_run, "error")
                self.history.append(result)
                return result
            result.backup_created = trigger_id
            result.rollback_info = {
                "savepoint_trigger_id": trigger_id,
                "job_id": job_id,
            }
            self._remember_rollback(result.id, result.rollback_info)
            logger.info("Savepoint completed before remediation: %s", trigger_id)

        if dry_run:
            result.success = True
            result.message = f"DRY RUN: Would apply {remediation.type.value}"
            result.changes_made = remediation.config_changes
            telemetry.record_remediation(remediation.type.value, dry_run, "ok")
            self.history.append(result)
            return result

        # Handle emergency savepoint specially
        if remediation.type == RemediationType.CREATE_EMERGENCY_SAVEPOINT:
            try:
                trigger_id = await self._completed_savepoint(job_id)
                result.success = True
                result.message = "Emergency savepoint completed successfully"
                result.changes_made = {"savepoint": {"request-id": trigger_id, "status": "COMPLETED"}}
            except Exception as e:
                # result.message is returned via /api/remediation/apply and
                # /api/remediation/history — keep it opaque (CWE-209).
                result.message = client_error("create savepoint", e)
            telemetry.record_remediation(remediation.type.value, dry_run, "ok" if result.success else "error")
            self.history.append(result)
            return result

        # Apply config changes via Flink Kubernetes Operator CRD patch
        if remediation.config_changes:
            try:
                await self._apply_config_via_k8s(remediation.config_changes)
                result.success = True
                result.message = f"Applied {remediation.type.value} successfully"
                result.changes_made = remediation.config_changes
                if remediation.requires_restart:
                    result.message += " (pod restart required — will happen automatically)"
            except Exception as e:
                # Same rule: caller-visible message stays opaque; the full
                # exception is logged server-side by client_error (CWE-209).
                result.message = client_error(f"apply {remediation.type.value}", e)
        else:
            # Defence in depth behind the fail-early guard above: no code path
            # may end here silently with an empty message beside a populated
            # backup_created — that shape invites a false "success" rendering.
            result.message = (
                f"No configuration changes are defined for {remediation.type.value} — "
                "nothing was applied. This is a defect, not a successful no-op."
            )

        telemetry.record_remediation(remediation.type.value, dry_run, "ok" if result.success else "error")
        self.history.append(result)
        return result

    async def _completed_savepoint(self, job_id: str) -> str:
        """Trigger a savepoint and wait (bounded) until Flink reports it COMPLETED.

        Returns the trigger id. Raises if the trigger returns no id, the
        savepoint finishes with a failure cause, or it does not complete within
        SAVEPOINT_COMPLETION_TIMEOUT_SECONDS (default 300).
        """
        savepoint = await self.flink_client.trigger_savepoint(job_id) or {}
        trigger_id = savepoint.get("request-id", savepoint.get("trigger-id", ""))
        if not trigger_id:
            raise RuntimeError("savepoint trigger returned no request id")
        if not await self._savepoint_completed(job_id, trigger_id):
            raise RuntimeError("savepoint did not complete")
        return trigger_id

    async def _savepoint_completed(self, job_id: str, trigger_id: str) -> bool:
        """Poll the savepoint status until COMPLETED or the bounded timeout."""
        timeout_s = _env_seconds("SAVEPOINT_COMPLETION_TIMEOUT_SECONDS", 300.0, 1.0, 3600.0)
        every_s = _env_seconds("SAVEPOINT_POLL_INTERVAL_SECONDS", 5.0, 0.01, 60.0)
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout_s
        while True:
            st = await self.flink_client.get_savepoint_status(job_id, trigger_id) or {}
            if ((st.get("status") or {}).get("id")) == "COMPLETED":
                operation = st.get("operation") or {}
                return "failure-cause" not in operation
            if loop.time() + every_s > deadline:
                return False
            await asyncio.sleep(every_s)

    # Bounded retry for CRD patch conflicts: a legitimate concurrent write (the
    # operator, the autoscaler, a human kubectl) must not surface as a hard
    # failure, but the retry must not spin forever either.
    _CRD_PATCH_MAX_ATTEMPTS = 3

    async def _apply_config_via_k8s(self, config_changes: Dict):
        """Apply config changes by patching the FlinkDeployment CRD.

        Patches ONLY the keys being changed — JSON merge-patch merges maps, so
        concurrent changes to OTHER keys survive instead of being silently
        reverted by a whole-map read-modify-write (CWE-362). The patch carries
        the read's resourceVersion as a precondition, so the API server rejects
        the write with 409 Conflict if the object changed between our read and
        write; a lost race is retried (re-read, re-patch) a bounded number of
        times.
        """
        # Backstop allowlist enforcement (defence in depth): this is the second
        # write site into spec.flinkConfiguration (the first is
        # KubernetesClient.patch_flink_config). The catalogued apply_remediation
        # path reaches the CR here, bypassing the tool-boundary check, so the same
        # closed allowlist must gate this write too. Fail closed — reject the whole
        # batch if any key is disallowed, and log only a COUNT of disallowed keys,
        # never the key names/values.
        disallowed = [k for k in config_changes if k not in ALLOWED_FLINK_CONFIG_KEYS]
        if disallowed:
            logger.warning(
                "_apply_config_via_k8s: rejected %d disallowed config key(s)",
                len(disallowed),
            )
            raise Exception("Configuration key not permitted.")
        # Same value schema as KubernetesClient.patch_flink_config (CWE-20):
        # bounded single-line values matching each key's shape. Count only.
        bad_values = flink_config_rejections(config_changes)
        if bad_values:
            logger.warning(
                "_apply_config_via_k8s: rejected %d config value(s) outside the schema",
                bad_values,
            )
            raise Exception("Configuration value not permitted.")

        try:
            # kubeconfig load + every K8s API call below are synchronous
            # (urllib3-backed) — run them on a worker thread so they never block
            # the event loop (same idiom as the secret-provider calls in app/main.py).
            await k8s_call(self.k8s_client._ensure_initialized)
            if not self.k8s_client._initialized:
                raise Exception("Kubernetes client not initialized")

            api = self.k8s_client.custom_api
            namespace = self.k8s_client.namespace
            deployment_name = self.k8s_client.deployment_name

            for attempt in range(self._CRD_PATCH_MAX_ATTEMPTS):
                # Read for the resourceVersion precondition only — the patch
                # body deliberately does NOT echo the whole flinkConfiguration
                # map back.
                current = await k8s_call(
                    api.get_namespaced_custom_object,
                    group="flink.apache.org",
                    version="v1beta1",
                    namespace=namespace,
                    plural="flinkdeployments",
                    name=deployment_name,
                    _request_timeout=K8S_REQUEST_TIMEOUT,
                )

                # Send ONLY the keys being changed: merge-patch merges maps, so
                # concurrent changes to other keys survive. resourceVersion
                # makes the server reject the write with 409 if anything
                # changed since the read.
                resource_version = (current.get("metadata") or {}).get("resourceVersion")
                if not resource_version:
                    # FAIL CLOSED. Building the precondition under `if
                    # resource_version:` silently degrades to a bare merge-patch
                    # with no CAS guard — exactly the concurrent-write clobber
                    # this precondition exists to prevent (CWE-362). A read that
                    # returned no resourceVersion is not a licence to write
                    # unguarded.
                    raise RuntimeError(
                        "FlinkDeployment read returned no metadata.resourceVersion — "
                        "refusing to patch without a concurrency precondition"
                    )
                patch = {
                    "metadata": {"resourceVersion": resource_version},
                    "spec": {"flinkConfiguration": dict(config_changes)},
                }

                try:
                    await k8s_call(
                        api.patch_namespaced_custom_object,
                        group="flink.apache.org",
                        version="v1beta1",
                        namespace=namespace,
                        plural="flinkdeployments",
                        name=deployment_name,
                        body=patch,
                        _request_timeout=K8S_REQUEST_TIMEOUT,
                    )
                    # Log KEYS only — values may carry secrets and this reaches the
                    # durable audit sink (CWE-532); mirrors patch_flink_config.
                    logger.info(
                        "FlinkDeployment CRD patched with keys: %s", sorted(config_changes)
                    )
                    return
                except ApiException as e:
                    if e.status == 409 and attempt < self._CRD_PATCH_MAX_ATTEMPTS - 1:
                        logger.info(
                            "FlinkDeployment patch conflict (409) on attempt %d/%d — "
                            "re-reading and retrying",
                            attempt + 1, self._CRD_PATCH_MAX_ATTEMPTS,
                        )
                        continue
                    raise
        except Exception as e:
            logger.error("Failed to patch FlinkDeployment CRD: %s", e)
            raise

    def _remember_rollback(self, result_id: Optional[int], rollback_info: Dict) -> None:
        # Only real applies reach here (rollback_info is set solely on the
        # non-dry-run savepoint path), so previews can never displace one.
        if result_id is None:
            return
        self._rollbacks[result_id] = rollback_info
        while len(self._rollbacks) > MAX_ROLLBACK_ENTRIES:
            self._rollbacks.popitem(last=False)

    async def rollback(self, result_id: Optional[int]) -> Dict:
        # Look up by RemediationResult.id (the "id" field each entry exposes via
        # GET /api/remediation/history), NOT by position: history is a bounded
        # deque, so a positional index silently shifts meaning once eviction
        # starts and a stale index would roll back the WRONG entry. The lookup
        # goes through ``_rollbacks`` — the store only real applies populate —
        # not through ``history``, whose eviction is driven by EVERY outcome
        # (dry runs included) and would otherwise forget a live savepoint.
        # None is rejected up front so an entry whose id was never assigned is
        # unaddressable.
        if result_id is None:
            return {"success": False, "message": "Invalid remediation id"}
        info = self._rollbacks.get(result_id)
        if info:
            return {
                "success": True,
                "message": "Rollback initiated. Restore from savepoint to revert changes.",
                "savepoint_info": info,
            }

        # Known id with nothing to roll back to (preview, manual, no-op, failed
        # savepoint) vs an id we have never seen or have evicted.
        if any(r.id == result_id for r in self.history):
            return {"success": False, "message": "No rollback information available"}
        return {"success": False, "message": "Invalid remediation id"}

    def get_history(self) -> List[Dict]:
        return [r.to_dict() for r in self.history]
