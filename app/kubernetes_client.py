# Copyright Yahoo, Licensed under the terms of the Apache 2.0 license. See LICENSE for terms.

import asyncio
import os
import re
import logging
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

from kubernetes import client, config

from app.safe_errors import client_error

logger = logging.getLogger(__name__)

# Closed allowlist of Flink configuration keys that may be written into
# spec.flinkConfiguration. Without it, a model-chosen key flows straight into the
# patched CR and reaches argument-injection surfaces — env.java.opts* (JVM args →
# RCE, CWE-88), state/checkpoint-storage redirection, containerized.*.env.*,
# fs.s3a.*, kubernetes.*. The set is the union of the operator-facing config keys
# the agent legitimately tunes and every key REMEDIATION_CATALOG writes, so
# catalogued remediations still pass the gate.
#
# Defined in this module (not in langgraph_agent) so the code that performs the
# actual patch owns the canonical set: langgraph_agent imports FROM here, and this
# module imports nothing from langgraph_agent, so there is no import cycle.
ALLOWED_FLINK_CONFIG_KEYS = frozenset({
    "job.autoscaler.vertex.max-parallelism",
    "job.autoscaler.target.utilization",
    "job.autoscaler.stabilization.interval",
    "job.autoscaler.scale-down.max-factor",
    "job.autoscaler.scale-up.max-factor",
    "job.autoscaler.metrics.window",         # REMEDIATION_CATALOG: stabilize_autoscaler
    "parallelism.default",
    "taskmanager.memory.process.size",
    "taskmanager.numberOfTaskSlots",
    "taskmanager.network.memory.fraction",   # REMEDIATION_CATALOG: increase_network_buffers
    "execution.checkpointing.interval",
    "execution.checkpointing.timeout",
    "state.backend.incremental",
})


# Value schema for every allowlisted key (CWE-20). The key allowlist alone let
# any VALUE through, and a value carrying a line break can smuggle a second key
# (for example a JVM-options key) into the rendered flink-conf.yaml. Each value
# must be a short string that FULLY matches its key's pattern (fullmatch: no
# CR/LF, no trailing text), and integer keys are range-bounded. Tune the bounds
# to your clusters. Both write sites call flink_config_value_allowed():
# KubernetesClient.patch_flink_config and AutoRemediator._apply_config_via_k8s.
MAX_FLINK_CONFIG_VALUE_LEN = 32
_CFG_INT = re.compile(r"[1-9][0-9]{0,5}")
_CFG_FRACTION = re.compile(r"(?:0?\.[0-9]{1,4}|1(?:\.0{1,4})?)")
_CFG_FACTOR = re.compile(r"[0-9]{1,3}(?:\.[0-9]{1,4})?")
_CFG_DURATION = re.compile(r"[1-9][0-9]{0,8}(?:ms|s|min|h)?")
_CFG_MEMORY = re.compile(r"[1-9][0-9]{0,6}(?:m|mb|g|gb)", re.IGNORECASE)
_CFG_BOOL = re.compile(r"(?:true|false)")
FLINK_CONFIG_VALUE_SCHEMA = {
    "job.autoscaler.vertex.max-parallelism": (_CFG_INT, 1, 32768),
    "job.autoscaler.target.utilization": (_CFG_FRACTION, None, None),
    "job.autoscaler.stabilization.interval": (_CFG_DURATION, None, None),
    "job.autoscaler.scale-down.max-factor": (_CFG_FRACTION, None, None),
    "job.autoscaler.scale-up.max-factor": (_CFG_FACTOR, None, None),
    "job.autoscaler.metrics.window": (_CFG_DURATION, None, None),
    "parallelism.default": (_CFG_INT, 1, 1024),
    "taskmanager.memory.process.size": (_CFG_MEMORY, None, None),
    "taskmanager.numberOfTaskSlots": (_CFG_INT, 1, 64),
    "taskmanager.network.memory.fraction": (_CFG_FRACTION, None, None),
    "execution.checkpointing.interval": (_CFG_DURATION, None, None),
    "execution.checkpointing.timeout": (_CFG_DURATION, None, None),
    "state.backend.incremental": (_CFG_BOOL, None, None),
}
assert set(FLINK_CONFIG_VALUE_SCHEMA) == set(ALLOWED_FLINK_CONFIG_KEYS)


def flink_config_value_allowed(key, value) -> bool:
    """True only for an allowlisted key whose value is a bounded, single-line
    string matching that key's schema. Fails closed on anything else."""
    if not isinstance(key, str) or not isinstance(value, str):
        return False
    if key not in ALLOWED_FLINK_CONFIG_KEYS or key not in FLINK_CONFIG_VALUE_SCHEMA:
        return False
    if not value or len(value) > MAX_FLINK_CONFIG_VALUE_LEN:
        return False
    if any(not ch.isprintable() or ch in "\r\n" for ch in value):
        return False
    pattern, lo, hi = FLINK_CONFIG_VALUE_SCHEMA[key]
    if not pattern.fullmatch(value):
        return False
    return lo is None or lo <= int(value) <= hi


def flink_config_rejections(config_updates) -> int:
    """Count of entries that fail the key allowlist or the value schema."""
    if not isinstance(config_updates, dict):
        return 1
    return sum(1 for k, v in config_updates.items() if not flink_config_value_allowed(k, v))


# Hard ceilings for pod-log reads (CWE-400 / CWE-770). tail_lines is clamped at
# the SINK so every caller — agent tools, REST routes, future code — is bounded
# even if a boundary check is missed; the Annotated bound on the tool signatures
# is what the model sees, this is what actually holds. limit_bytes maps to the
# Kubernetes API's limitBytes and is the only bound that caps memory rather than
# line count.
MAX_TAIL_LINES = 5000
LOG_LIMIT_BYTES = 10 * 1024 * 1024  # 10 MiB per pod-log read


class _NamespaceWide:
    """Sentinel type for NAMESPACE_WIDE (see below)."""
    __slots__ = ()

    def __repr__(self) -> str:
        return "NAMESPACE_WIDE"


# Deployment scope is applied at the SINK, the same way tail_lines is clamped
# above: get_events / get_pods / get_operator_logs default to THIS deployment,
# and a caller that genuinely needs the whole namespace must say so with this
# sentinel. Nothing falsy widens a read — ``None`` and ``""`` both resolve to
# the deployment scope — so an empty FLINK_DEPLOYMENT_NAME, a forgotten
# argument or a caller-supplied value can never turn a scoped read into a
# namespace-wide one (CWE-200 / least privilege).
NAMESPACE_WIDE = _NamespaceWide()

# One ownership predicate for every read path. The Flink Kubernetes Operator
# derives every resource name it creates for a FlinkDeployment ``X`` from ``X``
# with a fixed shape:
#   X                          FlinkDeployment / Deployment / JobManager Service
#   X-rest                     REST Service
#   X-<rs-hash>                JobManager ReplicaSet (8-10 chars, lower-alnum)
#   X-<rs-hash>-<pod-hash>     JobManager pod (5-char lower-alnum pod suffix)
#   X-taskmanager-<n>-<m>      TaskManager pods
#   X-cluster-config-map       HA ConfigMap
# A neighbouring deployment "X-extra" (and its pods "X-extra-taskmanager-1-1")
# shares the prefix but matches none of these shapes, so a bare
# startswith("X-") test is too wide and a bare delimited "X" token is too
# narrow (it drops this deployment's own "X-taskmanager-1-3" lines). Both
# get_events and get_operator_logs use THIS pattern, so the two predicates
# cannot disagree.
_OWNED_SUFFIX = (
    r"(?:-(?:taskmanager-\d+-\d+"
    r"|rest"
    r"|cluster-config-map"
    r"|[a-z0-9]{8,10}(?:-[a-z0-9]{5})?))?"
)


def _owned_name_regex(deployment_name: str) -> "re.Pattern[str]":
    """Compile the ownership pattern for one deployment (fixed-width, re.escape'd)."""
    return re.compile(rf"{re.escape(deployment_name)}{_OWNED_SUFFIX}")


def _is_owned(obj_name: str, owned: "re.Pattern[str]") -> bool:
    return bool(obj_name) and owned.fullmatch(obj_name) is not None


def _env_int(name: str, default: int, minimum: int = 1, maximum: int = 1000) -> int:
    """Parse a positive int from the environment, clamped at BOTH ends, never raising.

    A malformed value must degrade to the default rather than crash the process
    at import time (CrashLoopBackOff). The upper clamp matters just as much as
    the lower one: these values ARE the resource bounds, so an unbounded
    override (K8S_MAX_CONCURRENCY=100000, K8S_READ_TIMEOUT_SECONDS=86400)
    silently defeats the control it configures. Same both-ends idiom as
    audit._trusted_proxy_hops and the tail_lines sink clamp.
    """
    try:
        return min(max(minimum, int(os.getenv(name, "").strip() or default)), maximum)
    except (TypeError, ValueError):
        return default


# Every Kubernetes call is synchronous urllib3 underneath. Without an explicit
# timeout a blackholed API server blocks the worker thread FOREVER: the
# to_thread pool fills, and every later to_thread in the process — including the
# startup permission self-check and the whole CRD patch path — hangs behind it,
# while /api/health (process-only) still answers 200 so liveness never restarts
# the pod. An untimed read turns a visible, self-correcting stall into an
# invisible permanent wedge (CWE-1088). (connect, read) seconds.
K8S_CONNECT_TIMEOUT = _env_int("K8S_CONNECT_TIMEOUT_SECONDS", 5, maximum=60)
K8S_READ_TIMEOUT = _env_int("K8S_READ_TIMEOUT_SECONDS", 30, maximum=120)
K8S_REQUEST_TIMEOUT = (K8S_CONNECT_TIMEOUT, K8S_READ_TIMEOUT)

# Bound how many Kubernetes reads run at once. asyncio.to_thread uses the loop's
# DEFAULT executor, sized min(32, cpu_count + 4) — and cpu_count() reports HOST
# CPUs, not the 500m cgroup quota, so the default is wildly oversized here.
# Unbounded, LOG_LIMIT_BYTES (10 MiB) x up to 5 TaskManager pods x 10 concurrent
# requests is ~500 MiB of log buffers in a 1 GiB pod. RATE_LIMIT_LOGS_PER_MINUTE
# caps the RATE, not the CONCURRENCY. The event loop used to serialize these
# implicitly; moving them to threads removed that accidental bound, so it has to
# be made explicit (CWE-400).
K8S_MAX_CONCURRENCY = _env_int("K8S_MAX_CONCURRENCY", 4, maximum=32)

# One semaphore per running loop. A module-level asyncio.Semaphore bound to one
# loop misbehaves if another loop runs later (pytest creates a fresh loop per
# test), so the instance is cached against the loop that created it.
_k8s_semaphores: "dict[object, asyncio.Semaphore]" = {}


def _k8s_semaphore() -> asyncio.Semaphore:
    loop = asyncio.get_running_loop()
    sem = _k8s_semaphores.get(loop)
    if sem is None:
        sem = asyncio.Semaphore(K8S_MAX_CONCURRENCY)
        _k8s_semaphores[loop] = sem
    return sem


async def k8s_call(_fn, *args, **kwargs):
    """Run one blocking KubernetesClient method off the event loop, bounded.

    The single chokepoint for Kubernetes I/O from async code: it keeps the call
    off the loop (as plain asyncio.to_thread did) AND caps how many such calls
    occupy the shared thread pool at once.
    """
    async with _k8s_semaphore():
        return await asyncio.to_thread(_fn, *args, **kwargs)


class KubernetesClient:
    def __init__(self):
        self.namespace = os.getenv("POD_NAMESPACE", "flink")
        self.pod_name = os.getenv("POD_NAME", "")
        # `or`, not the getenv default: FLINK_DEPLOYMENT_NAME="" (set but empty)
        # must resolve to the default name, never to "" — an empty deployment
        # name would turn every scoped read into "app=" / an unfiltered log.
        self.deployment_name = os.getenv("FLINK_DEPLOYMENT_NAME") or "flink-job-with-ai-debugger"
        self._initialized = False

    def _resolve_scope(self, deployment_name) -> Optional[str]:
        """Map a caller's scope argument onto the deployment to filter for.

        None / "" (anything falsy) → this deployment; NAMESPACE_WIDE → None
        (no filter); any other string → that deployment.
        """
        if deployment_name is NAMESPACE_WIDE:
            return None
        return deployment_name or self.deployment_name

    def _ensure_initialized(self):
        if self._initialized:
            return
        try:
            config.load_incluster_config()
        except config.ConfigException:
            try:
                config.load_kube_config()
            except config.ConfigException:
                logger.warning("Could not load Kubernetes config; K8s features disabled")
                return
        self.core_v1 = client.CoreV1Api()
        self.apps_v1 = client.AppsV1Api()
        self.custom_api = client.CustomObjectsApi()
        self.authz_v1 = client.AuthorizationV1Api()
        self._initialized = True

    def check_write_permissions(self) -> dict:
        """Best-effort RBAC self-check for the cluster-mutate verbs the write path uses.

        Issues a SelfSubjectAccessReview for the pod's OWN identity (no impersonation),
        checking `patch` on flinkdeployments and on Deployments — the two writes the
        remediation tools perform. Returns a map of readable verb/resource → allowed,
        where the value is True/False (resolved) or None (could not be determined).

        Never raises: returns {} if the K8s client is not initialized, and records None
        for any individual check that errors so a flaky API call can't break startup.
        """
        self._ensure_initialized()
        if not self._initialized:
            return {}

        checks = [
            ("patch flinkdeployments.flink.apache.org", "flink.apache.org", "flinkdeployments"),
            ("patch deployments.apps", "apps", "deployments"),
        ]
        results: dict = {}
        for label, group, resource in checks:
            try:
                review = client.V1SelfSubjectAccessReview(
                    spec=client.V1SelfSubjectAccessReviewSpec(
                        resource_attributes=client.V1ResourceAttributes(
                            namespace=self.namespace,
                            group=group,
                            resource=resource,
                            verb="patch",
                            # By name: the writes target this deployment only,
                            # so a name-scoped grant must read as allowed.
                            name=self.deployment_name or None,
                        )
                    )
                )
                resp = self.authz_v1.create_self_subject_access_review(review)
                results[label] = bool(resp.status.allowed)
            except Exception as e:
                logger.warning("RBAC self-check failed for %s: %s", label, e)
                results[label] = None
        return results

    # ── Events ───────────────────────────────────────────────────────

    def get_events(
        self,
        namespace: Optional[str] = None,
        field_selector: Optional[str] = None,
        hours_back: int = 4,
        deployment_name=None,
        include_cross_deployment_warnings: bool = True,
    ) -> List[Dict]:
        """List recent K8s events, scoped to this deployment by default.

        Scope is resolved at this sink: `deployment_name=None` (the default)
        means THIS deployment; a caller that needs every object in the
        namespace must pass `NAMESPACE_WIDE` explicitly.

        Scoped reads return events whose involved object the operator derived
        from the deployment name (`_owned_name_regex`: the FlinkDeployment
        itself, its JobManager/TaskManager pods, ReplicaSet, Services, HA
        ConfigMap), PLUS — with `include_cross_deployment_warnings=True`, the
        default — any type=Warning event anywhere in the namespace within the
        window, so neighbour-induced problems remain visible: shared TM pool,
        kube-apiserver QPS, autoscaler thrash, and the kubelet's Node-scoped
        OOMKilling/SystemOOM events, which are how a TaskManager OOM actually
        surfaces. Settled design decision of 2026-05-11
        ("deployment-scoped-with-cross-deployment-warnings"; recorded in the
        team's internal decision log, not vendored in this repo).

        Default `hours_back=4` (long enough to catch patterns that emerged
        earlier in the firing window, short enough to skip ancient noise).
        """
        self._ensure_initialized()
        if not self._initialized:
            return []
        ns = namespace or self.namespace
        scope = self._resolve_scope(deployment_name)
        owned = _owned_name_regex(scope) if scope else None
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours_back)
        try:
            kwargs = {"namespace": ns, "_request_timeout": K8S_REQUEST_TIMEOUT}
            if field_selector:
                kwargs["field_selector"] = field_selector
            events = self.core_v1.list_namespaced_event(**kwargs)
            result = []
            for event in events.items:
                event_time = event.last_timestamp or event.event_time or event.metadata.creation_timestamp
                if event_time and event_time.replace(tzinfo=timezone.utc) < cutoff:
                    continue

                obj_name = event.involved_object.name or ""
                if owned is None:
                    event_scope = "all"
                elif _is_owned(obj_name, owned):
                    event_scope = "mine"
                elif include_cross_deployment_warnings and event.type == "Warning":
                    event_scope = "namespace_warning"
                else:
                    continue

                result.append({
                    "type": event.type,
                    "reason": event.reason,
                    "message": event.message,
                    "object": f"{event.involved_object.kind}/{event.involved_object.name}",
                    "count": event.count or 1,
                    "first_seen": event.first_timestamp.isoformat() if event.first_timestamp else None,
                    "last_seen": event_time.isoformat() if event_time else None,
                    "source": event.source.component if event.source else None,
                    "scope": event_scope,
                })
            return sorted(result, key=lambda x: x.get("last_seen") or "", reverse=True)
        except Exception as e:
            # Opaque, correlatable message: an ApiException body carries the
            # ServiceAccount principal / namespace / RBAC denials (CWE-209).
            return [{"error": client_error("list Kubernetes events", e)}]

    def get_flink_pod_events(
        self,
        hours_back: int = 4,
        deployment_name=None,
        include_cross_deployment_warnings: bool = True,
    ) -> List[Dict]:
        # Thin wrapper: scope defaults (None → this deployment, NAMESPACE_WIDE
        # to widen) are resolved in get_events, so every caller inherits them.
        # The cross-deployment-Warning flag is threaded through so a caller
        # CAN turn namespace-wide Warning pass-through off where it is noise
        # (autoscaler events); the default keeps it on.
        return self.get_events(
            hours_back=hours_back,
            deployment_name=deployment_name,
            include_cross_deployment_warnings=include_cross_deployment_warnings,
        )

    def analyze_events(
        self,
        hours_back: int = 4,
        deployment_name=None,
        include_cross_deployment_warnings: bool = True,
    ) -> Dict:
        events = self.get_flink_pod_events(
            hours_back=hours_back,
            deployment_name=deployment_name,
            include_cross_deployment_warnings=include_cross_deployment_warnings,
        )
        if not events:
            return {"total_events": 0, "warnings": [], "errors": []}

        warnings = [e for e in events if e.get("type") == "Warning"]
        normal_events = [e for e in events if e.get("type") == "Normal"]
        error_keywords = ["error", "fail", "crash", "oom", "kill", "evict"]
        errors = [
            e for e in events
            if any(k in (e.get("message") or "").lower() for k in error_keywords)
        ]

        issues = []
        oom_events = [e for e in events if "OOM" in (e.get("reason") or "").upper() or "oom" in (e.get("message") or "").lower()]
        if oom_events:
            issues.append({
                "type": "oom_detected",
                "count": len(oom_events),
                "message": "OOM (Out of Memory) events detected",
                "severity": "critical",
            })

        restart_events = [e for e in events if e.get("reason") in ("BackOff", "Restarted")]
        if restart_events:
            issues.append({
                "type": "pod_restarts",
                "count": len(restart_events),
                "message": "Pod restart events detected",
                "severity": "warning",
            })

        # Generous caps favour agent fidelity over token cost; truncated:true flags a cut.
        WARN_CAP, ERR_CAP, NORMAL_CAP = 500, 500, 200
        return {
            "total_events": len(events),
            "warning_count": len(warnings),
            "error_count": len(errors),
            "warnings": warnings[:WARN_CAP],
            "errors": errors[:ERR_CAP],
            "normal_events": normal_events[:NORMAL_CAP],
            "issues": issues,
            "truncated": (
                len(warnings) > WARN_CAP
                or len(errors) > ERR_CAP
                or len(normal_events) > NORMAL_CAP
            ),
        }

    # ── Pods ─────────────────────────────────────────────────────────

    def get_pods(
        self,
        namespace: Optional[str] = None,
        label_selector=None,
    ) -> List[Dict]:
        """List pods, scoped to this deployment by default.

        `label_selector=None` (the default) lists `app=<deployment_name>`
        server-side; an explicit selector (e.g. the operator pod's) replaces
        it; only `NAMESPACE_WIDE` lists every pod in the namespace.
        """
        self._ensure_initialized()
        if not self._initialized:
            return []
        ns = namespace or self.namespace
        if label_selector is NAMESPACE_WIDE:
            label_selector = None
        elif not label_selector:
            label_selector = f"app={self.deployment_name}"
        try:
            kwargs = {"namespace": ns, "_request_timeout": K8S_REQUEST_TIMEOUT}
            if label_selector:
                kwargs["label_selector"] = label_selector
            pods = self.core_v1.list_namespaced_pod(**kwargs)
            return [
                {
                    "name": pod.metadata.name,
                    "namespace": pod.metadata.namespace,
                    "phase": pod.status.phase,
                    "node": pod.spec.node_name,
                    "containers": [
                        {
                            "name": cs.name,
                            "ready": cs.ready,
                            "restart_count": cs.restart_count,
                            "state": (
                                "running" if cs.state.running
                                else "waiting" if cs.state.waiting
                                else "terminated" if cs.state.terminated
                                else "unknown"
                            ),
                            "reason": (
                                cs.state.waiting.reason if cs.state and cs.state.waiting
                                else cs.state.terminated.reason if cs.state and cs.state.terminated
                                else None
                            ),
                        }
                        for cs in (pod.status.container_statuses or [])
                    ],
                    "start_time": pod.status.start_time.isoformat() if pod.status.start_time else None,
                }
                for pod in pods.items
            ]
        except Exception as e:
            return [{"error": client_error("list pods", e)}]

    def get_flink_pods(self) -> List[Dict]:
        return self.get_pods(label_selector=f"app={self.deployment_name}")

    def analyze_pod_health(self) -> Dict:
        # No namespace-wide fallback: get_pods() now defaults to this
        # deployment's selector, so the old `if not pods: get_pods()` was a
        # second identical list call that, before that default, reported every
        # neighbour pod's health whenever our own pods were briefly absent.
        pods = self.get_flink_pods()

        issues = []
        for pod in pods:
            if isinstance(pod, dict) and "error" not in pod:
                if pod.get("phase") not in ("Running", "Succeeded"):
                    issues.append({
                        "pod": pod["name"],
                        "type": "unhealthy_pod",
                        "message": f"Pod {pod['name']} is in {pod.get('phase')} state",
                        "severity": "warning",
                    })
                for container in pod.get("containers", []):
                    if container.get("restart_count", 0) > 3:
                        issues.append({
                            "pod": pod["name"],
                            "container": container["name"],
                            "type": "frequent_restarts",
                            "message": f"Container {container['name']} has {container['restart_count']} restarts",
                            "severity": "warning",
                        })
                    if not container.get("ready", True):
                        issues.append({
                            "pod": pod["name"],
                            "container": container["name"],
                            "type": "container_not_ready",
                            "message": f"Container {container['name']} is not ready: {container.get('reason', 'unknown')}",
                            "severity": "warning",
                        })

        return {"pods": pods, "issues": issues, "pod_count": len(pods)}

    # ── Logs ─────────────────────────────────────────────────────────

    def _read_pod_logs(
        self,
        pod_name: str,
        container: Optional[str] = None,
        tail_lines: int = 1000,
    ) -> "tuple[str, Optional[str]]":
        """Read one pod's log; returns (logs, error) with exactly one side set.

        get_pod_logs keeps its historical str-only contract for existing
        callers, but the composite readers below need to tell a failed read
        from an empty (or filtered-to-empty) one: an error string that flows
        into the deployment filter matches nothing and comes back as
        `logs: ""`, i.e. a read failure disguised as "no lines for you".
        """
        self._ensure_initialized()
        if not self._initialized:
            return "", "Kubernetes client not initialized"
        try:
            # Defensive clamp at the sink: an oversized (or malformed) value must
            # never reach read_namespaced_pod_log unbounded.
            try:
                tail_lines = int(tail_lines)
            except (TypeError, ValueError):
                tail_lines = 1000
            tail_lines = max(1, min(tail_lines, MAX_TAIL_LINES))
            kwargs = {
                "name": pod_name,
                "namespace": self.namespace,
                "tail_lines": tail_lines,
                "limit_bytes": LOG_LIMIT_BYTES,
                "_request_timeout": K8S_REQUEST_TIMEOUT,
            }
            if container:
                kwargs["container"] = container
            return self.core_v1.read_namespaced_pod_log(**kwargs), None
        except Exception as e:
            # Returned verbatim through /api/logs/* — must not carry the
            # API-server response body (CWE-209). Full detail is logged
            # server-side by client_error, retrievable by the ref id.
            return "", client_error("read pod logs", e)

    def get_pod_logs(
        self,
        pod_name: str,
        container: Optional[str] = None,
        tail_lines: int = 1000,
    ) -> str:
        logs, error = self._read_pod_logs(pod_name, container=container, tail_lines=tail_lines)
        return error if error is not None else logs

    @staticmethod
    def _list_error(pods: List[Dict]) -> Optional[str]:
        """The opaque error string a failed get_pods() call returned, if any."""
        if pods and isinstance(pods[0], dict) and "error" in pods[0]:
            return pods[0]["error"]
        return None

    def get_operator_logs(self, tail_lines: int = 5000, filter_deployment=None) -> Dict:
        # Least-privilege default (CWE-200): the operator's log covers EVERY
        # workload it reconciles, not just this deployment, so an unfiltered
        # read over-collects namespace data. Scope resolves like every other
        # read here: None/"" → this deployment, NAMESPACE_WIDE → whole log.
        # ("" is deliberately NOT an opt-out: an empty FLINK_DEPLOYMENT_NAME
        # or a forwarded blank must fail towards the scoped read.)
        filter_deployment = self._resolve_scope(filter_deployment)

        pods = self.get_pods(label_selector="app.kubernetes.io/name=flink-kubernetes-operator")
        if not pods:
            pods = self.get_pods(label_selector="app=flink-kubernetes-operator")
        list_error = self._list_error(pods)
        if list_error:
            return {"error": list_error, "logs": ""}
        if not pods:
            return {"error": "Could not find operator pod", "logs": ""}

        operator_pod = pods[0]["name"]
        raw_logs, read_error = self._read_pod_logs(
            operator_pod, container="flink-kubernetes-operator", tail_lines=tail_lines
        )
        if read_error is not None:
            # A failed read must surface AS a failure. Passing the error
            # string through the filter below would match nothing and return
            # `logs: ""` — indistinguishable from "no lines for this
            # deployment".
            return {"pod": operator_pod, "error": read_error, "logs": ""}

        if filter_deployment:
            # Same ownership predicate as get_events (_owned_name_regex), as a
            # delimited token: "<name>" and the operator-derived
            # "<name>-taskmanager-1-3" / "<name>-<rs>-<pod>" match; the
            # prefix-sharing neighbour "<name>-extra" does not. Note "\b"
            # alone is NOT enough — "-" is a non-word character, so
            # r"\bname\b" still matches "name-extra".
            pattern = re.compile(rf"(?<![\w-]){_owned_name_regex(filter_deployment).pattern}(?![\w-])")
            filtered = [
                line for line in raw_logs.splitlines()
                if pattern.search(line)
            ]
            logs = "\n".join(filtered)
            return {
                "pod": operator_pod,
                "filtered_for": filter_deployment,
                "logs": logs,
                "line_count": len(filtered),
                "total_lines_scanned": len(raw_logs.splitlines()),
            }

        return {"pod": operator_pod, "logs": raw_logs, "line_count": len(raw_logs.splitlines())}

    def get_flink_jobmanager_logs(self, tail_lines: int = 2000) -> Dict:
        # Only THIS deployment's pods are candidates (app=<deployment>
        # server-side). The old namespace-wide fallback (bare get_pods() then
        # pods[:1]) handed back a neighbour pod's log — HTTP-reachable via
        # /api/logs/jobmanager and fed to the root-cause tool — whenever our
        # pods were briefly absent (CWE-200).
        pods = self.get_flink_pods()
        list_error = self._list_error(pods)
        if list_error:
            return {"error": list_error, "logs": ""}
        # The operator names the JobManager pod "<deployment>-<rs>-<pod>",
        # not "*jobmanager*", so within the owned set "not a TaskManager" is
        # the JobManager. (The old `"job" in name` test matched every pod of
        # any deployment whose name contains "job".)
        names = [p.get("name", "") for p in pods]
        jm_pods = [n for n in names if "jobmanager" in n.lower()] or [n for n in names if "taskmanager" not in n.lower()]
        if not jm_pods:
            return {"error": "No JobManager pod found for this deployment", "logs": ""}

        pod_name = jm_pods[0]
        logs, read_error = self._read_pod_logs(pod_name, container="flink-main-container", tail_lines=tail_lines)
        if read_error is not None:
            return {"pod": pod_name, "error": read_error, "logs": ""}
        return {"pod": pod_name, "logs": logs, "line_count": len(logs.splitlines())}

    def get_flink_taskmanager_logs(self, tail_lines: int = 1000) -> Dict:
        # Scope the pod list to this deployment via the server-side label
        # selector (app=<deployment_name>) BEFORE the substring match: a bare
        # get_pods() lists every pod in the namespace, so any neighbour whose
        # name happened to contain "taskmanager" would have its logs read and
        # returned (CWE-200 / least privilege).
        pods = self.get_flink_pods()
        list_error = self._list_error(pods)
        if list_error:
            # A failed list is not "no pods": surface the (opaque) error.
            return {"error": list_error, "logs": {}}
        tm_pods = [p for p in pods if "taskmanager" in p.get("name", "").lower()]
        if not tm_pods:
            return {"error": "No TaskManager pods found for this deployment", "logs": {}}

        all_logs, errors = {}, {}
        for pod in tm_pods[:5]:  # Limit to 5 TMs
            pod_name = pod["name"]
            logs, read_error = self._read_pod_logs(pod_name, container="flink-main-container", tail_lines=tail_lines)
            if read_error is not None:
                errors[pod_name] = read_error
            else:
                all_logs[pod_name] = logs

        result = {"pods": [p["name"] for p in tm_pods[:5]], "logs": all_logs}
        if errors:
            result["errors"] = errors
        return result

    def analyze_logs_for_errors(self, logs: Dict) -> Dict:
        error_patterns = [
            (r"(?i)exception", "exception"),
            (r"(?i)error", "error"),
            (r"(?i)out\s*of\s*memory|oom", "oom"),
            (r"(?i)timeout", "timeout"),
            (r"(?i)connection\s*(refused|reset|closed)", "connection_issue"),
            (r"(?i)checkpoint.*fail", "checkpoint_failure"),
            (r"(?i)kill|killed", "killed"),
        ]

        findings = {
            "error_lines": [],
            "categories": {},
            "total_errors": 0,
        }

        raw_logs = logs.get("logs", "")
        if isinstance(raw_logs, dict):
            raw_logs = "\n".join(raw_logs.values())

        for line in raw_logs.splitlines():
            for pattern, category in error_patterns:
                if re.search(pattern, line):
                    findings["error_lines"].append({
                        "line": line.strip()[:300],
                        "category": category,
                    })
                    findings["categories"][category] = findings["categories"].get(category, 0) + 1
                    findings["total_errors"] += 1
                    break

        findings["error_lines"] = findings["error_lines"][-50:]
        return findings

    # ── Full Diagnostics ─────────────────────────────────────────────

    def get_full_diagnostics(self, hours_back: int = 24) -> Dict:
        # Scope events to this deployment: unscoped, this HTTP-reachable path
        # (/api/diagnostics/full, also metrics_collector) collected 24h of
        # events for every object in the namespace (CWE-200). Namespace-wide
        # Warnings stay visible by design (include_cross_deployment_warnings
        # defaults True) so neighbour-induced problems remain diagnosable —
        # see the get_events docstring / kb decision 2026-05-11.
        events = self.analyze_events(hours_back, deployment_name=self.deployment_name)
        pod_health = self.analyze_pod_health()
        return {
            "events": events,
            "pod_health": pod_health,
            "issues": events.get("issues", []) + pod_health.get("issues", []),
        }

    def get_logs_with_error_analysis(self, tail_lines: int = 1000) -> Dict:
        jm_logs = self.get_flink_jobmanager_logs(tail_lines=tail_lines)
        tm_logs = self.get_flink_taskmanager_logs(tail_lines=tail_lines)
        operator_logs = self.get_operator_logs(tail_lines=tail_lines)

        jm_errors = self.analyze_logs_for_errors(jm_logs)
        tm_errors = self.analyze_logs_for_errors(tm_logs)
        operator_errors = self.analyze_logs_for_errors(operator_logs)

        return {
            "jobmanager": {
                "logs": jm_logs,
                "errors": jm_errors,
            },
            "taskmanager": {
                "logs": tm_logs,
                "errors": tm_errors,
            },
            "operator": {
                "logs": operator_logs,
                "errors": operator_errors,
            },
        }

    # ── FlinkDeployment & Autoscaler ──────────────────────────────────

    def get_flink_deployment(self) -> Optional[Dict]:
        """Get the FlinkDeployment CRD object."""
        self._ensure_initialized()
        if not self._initialized:
            return None
        try:
            result = self.custom_api.get_namespaced_custom_object(
                group="flink.apache.org",
                version="v1beta1",
                namespace=self.namespace,
                plural="flinkdeployments",
                name=self.deployment_name,
                _request_timeout=K8S_REQUEST_TIMEOUT,
            )
            return result
        except Exception as e:
            logger.error("Failed to get FlinkDeployment: %s", e)
            return None

    def get_autoscaler_state(self, job_id: Optional[str] = None) -> Dict:
        """Get autoscaler state from FlinkDeployment CRD status."""
        deployment = self.get_flink_deployment()
        if not deployment:
            return {"error": "Could not fetch FlinkDeployment"}

        status = deployment.get("status", {})
        cluster_info = status.get("clusterInfo", {})
        job_status = status.get("jobStatus", {})

        return {
            "current_state": {
                "job_key": f"{self.namespace}/{self.deployment_name}",
                "job_id": job_status.get("jobName"),
                "job_state": job_status.get("state"),
                "lifecycle_state": status.get("lifecycleState"),
                "cluster_info": cluster_info,
                "last_update": status.get("reconciliationStatus", {}).get("reconciliationTimestamp"),
            },
            "message": "Autoscaler state read from Kubernetes CRD (operator autoscaler)",
        }

    def get_autoscaler_events(
        self,
        job_id: Optional[str] = None,
        hours: int = 24,
        event_types: Optional[List[str]] = None,
    ) -> List[Dict]:
        """Get autoscaler-related events from Kubernetes events."""
        # Scoped to this deployment with cross-deployment Warnings OFF: every
        # event here is stamped with OUR job_key below, so a neighbour's
        # IneffectiveScaling Warning would be mis-attributed to this job.
        # (Previously unscoped: 25h of every namespace object's events via
        # get_autoscaler_info.)
        events = self.get_flink_pod_events(
            hours_back=hours,
            deployment_name=self.deployment_name,
            include_cross_deployment_warnings=False,
        )

        # Filter for autoscaler-related events
        autoscaler_keywords = [
            "ScalingReport", "IneffectiveScaling", "Autoscaler",
            "Configuration recommendation", "Memory tuning"
        ]

        filtered_events = []
        for event in events:
            reason = event.get("reason", "")
            message = event.get("message", "")

            # Check if event is autoscaler-related
            is_autoscaler = any(
                keyword.lower() in reason.lower() or keyword.lower() in message.lower()
                for keyword in autoscaler_keywords
            )

            if is_autoscaler:
                # Map to autoscaler event format
                event_type = "ScalingReport" if "scaling" in reason.lower() else "Normal"
                if event.get("type") == "Warning":
                    event_type = "Warning"

                if not event_types or event_type in event_types:
                    filtered_events.append({
                        "event_key": f"{event.get('name', '')}",
                        "job_key": f"{self.namespace}/{self.deployment_name}",
                        "event_type": event_type,
                        "reason": reason,
                        "message": message,
                        "event_count": event.get("count", 1),
                        "create_time": event.get("first_timestamp", ""),
                        "update_time": event.get("last_timestamp", ""),
                    })

        return filtered_events

    def get_scaling_history(self, job_id: Optional[str] = None, hours: int = 5) -> List[Dict]:
        """Get scaling history from autoscaler events."""
        events = self.get_autoscaler_events(job_id, hours, event_types=["ScalingReport"])

        history = []
        for event in events:
            # Parse scaling information from message
            message = event.get("message", "")
            history.append({
                "job_key": event["job_key"],
                "timestamp": event["update_time"],
                "event_type": "scaling",
                "details": message,
            })

        return history

    def get_scaling_decisions(self, job_id: Optional[str] = None, hours: int = 5) -> List[Dict]:
        """Get scaling decisions from autoscaler events."""
        return self.get_scaling_history(job_id, hours)

    def get_autoscaler_errors(self, job_id: Optional[str] = None, hours: int = 24) -> List[Dict]:
        """Get autoscaler errors and warnings."""
        return self.get_autoscaler_events(
            job_id, hours, event_types=["Warning", "AutoscalerError"]
        )

    def analyze_autoscaler_events(self, job_id: Optional[str] = None, hours: int = 24) -> Dict:
        """Analyze autoscaler events and provide summary."""
        events = self.get_autoscaler_events(job_id, hours)

        if not events:
            return {
                "total_events": 0,
                "event_types": {},
                "reasons": {},
                "error_count": 0,
                "warning_count": 0,
                "recent_errors": [],
            }

        event_type_counts = {}
        reason_counts = {}
        errors = []
        warnings = []

        for event in events:
            et = event.get("event_type", "Unknown")
            event_type_counts[et] = event_type_counts.get(et, 0) + 1

            reason = event.get("reason", "Unknown")
            reason_counts[reason] = reason_counts.get(reason, 0) + 1

            if et in ["AutoscalerError", "Warning"]:
                if "error" in et.lower():
                    errors.append(event)
                else:
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

    def get_comprehensive_autoscaler_info(
        self, job_id: Optional[str] = None, hours: int = 5
    ) -> Dict:
        """Get comprehensive autoscaler information from Kubernetes."""
        return {
            "current_state": self.get_autoscaler_state(job_id),
            "state_history": self.get_scaling_history(job_id, hours),
            "scaling_decisions": self.get_scaling_decisions(job_id, hours),
            "all_events": self.get_autoscaler_events(job_id, hours * 5),
            "error_events": self.get_autoscaler_errors(job_id, hours * 5),
            "event_analysis": self.analyze_autoscaler_events(job_id, hours * 5),
            "metrics_history": [],  # Not available in CRD
            "config_changes": [],  # Not available in CRD
            "source": "kubernetes_crd",  # Indicate data source
        }

    def patch_flink_config(self, config_updates: Dict) -> Dict:
        """Patch flinkConfiguration in the FlinkDeployment CR."""
        self._ensure_initialized()
        if not self._initialized:
            return {"error": "Kubernetes client not initialized"}

        # Backstop allowlist enforcement (defence in depth): reject any key not
        # explicitly permitted, regardless of caller, before it reaches the CR patch.
        # Guards the actual write site even if a future caller skips the tool-boundary
        # check. Fail closed — reject the whole patch if any key is disallowed, and
        # do not echo rejected key names into the returned message.
        disallowed = [k for k in config_updates if k not in ALLOWED_FLINK_CONFIG_KEYS]
        if disallowed:
            logger.warning(
                "patch_flink_config: rejected %d disallowed config key(s)", len(disallowed),
            )
            return {"error": "Configuration key not permitted."}
        # Value schema (no line breaks / control characters, bounded length,
        # per-key shape and range). Values are never logged or echoed back.
        bad_values = flink_config_rejections(config_updates)
        if bad_values:
            logger.warning(
                "patch_flink_config: rejected %d config value(s) outside the schema", bad_values,
            )
            return {"error": "Configuration value not permitted."}

        try:
            patch_body = {
                "spec": {
                    "flinkConfiguration": config_updates,
                }
            }
            # Log KEYS only. app/langgraph_agent.py deliberately omits the config
            # value ("model output may carry a secret") and this logger reaches the
            # same durable audit sink — logging the dict here would undo that
            # caller-side redaction (CWE-532).
            logger.info(
                "Patching FlinkDeployment %s with config keys: %s",
                self.deployment_name, sorted(config_updates),
            )
            result = self.custom_api.patch_namespaced_custom_object(
                group="flink.apache.org",
                version="v1beta1",
                namespace=self.namespace,
                plural="flinkdeployments",
                name=self.deployment_name,
                body=patch_body,
                _request_timeout=K8S_REQUEST_TIMEOUT,
            )
            applied = result.get("spec", {}).get("flinkConfiguration", {})
            # Return only the keys we changed
            verified = {k: applied.get(k) for k in config_updates}
            logger.info("Patch applied successfully for keys: %s", sorted(verified))  # keys only (CWE-532)
            return {
                "success": True,
                "deployment": self.deployment_name,
                "applied": verified,
                "message": f"Updated {len(config_updates)} config key(s). "
                           "The Flink Operator will reconcile and restart the job.",
            }
        except Exception as e:
            return {"error": client_error("patch FlinkDeployment", e)}

    def restart_flink_job(self) -> Dict:
        """Restart the Flink job by rolling the Deployment (adds a restart annotation)."""
        self._ensure_initialized()
        if not self._initialized:
            return {"error": "Kubernetes client not initialized"}

        try:
            from datetime import datetime, timezone
            now = datetime.now(timezone.utc).isoformat()
            patch_body = {
                "spec": {
                    "template": {
                        "metadata": {
                            "annotations": {
                                "kubectl.kubernetes.io/restartedAt": now,
                            }
                        }
                    }
                }
            }
            logger.info("Restarting deployment %s", self.deployment_name)
            self.apps_v1.patch_namespaced_deployment(
                name=self.deployment_name,
                namespace=self.namespace,
                body=patch_body,
                _request_timeout=K8S_REQUEST_TIMEOUT,
            )
            logger.info("Restart triggered for %s", self.deployment_name)
            return {
                "success": True,
                "deployment": self.deployment_name,
                "restarted_at": now,
                "message": f"Rolling restart triggered for {self.deployment_name}. "
                           "The pod will be recreated with the latest configuration.",
            }
        except Exception as e:
            return {"error": client_error("restart deployment", e)}
