# Copyright Yahoo, Licensed under the terms of the Apache 2.0 license. See LICENSE for terms.

import os
import logging
import re
import ssl
from typing import Dict, List, Optional
from urllib.parse import urlparse, urlunparse

import aiohttp

from app.audit import has_secret_shape
from app.egress_policy import is_loopback, validate_destination
from app.kubernetes_client import ALLOWED_FLINK_CONFIG_KEYS
from app.safe_errors import client_error

logger = logging.getLogger(__name__)

# Optional CA bundle that signs the JobManager's REST certificate (set
# FLINK_SSL_CA_BUNDLE to the file your certificate issuer writes, e.g. a mounted
# workload-identity CA). Unset, or when the file is absent, the system trust
# store is used.
DEFAULT_FLINK_SSL_CA_BUNDLE = ""


# ── Cluster-config allowlist ───────────────────────────────────────────────
#
# /jobmanager/config returns the WHOLE-CLUSTER Flink configuration. Flink's
# own hideSensitiveValues masking is a substring denylist (password, secret,
# token, ...) that does NOT cover keys like fs.s3a.access.key, s3.access-key
# or env.java.opts* — so the app applies its own CLOSED allowlist behind it:
# only the diagnostic tuning keys the agent actually reasons about pass;
# everything else (TLS posture, storage URIs, identity labels, endpoints,
# unmasked credential-bearing keys) is dropped by default.
#
# The read set is DERIVED from the write allowlist (kubernetes_client.
# ALLOWED_FLINK_CONFIG_KEYS — every key the agent may set it must be able to
# read back, otherwise update_flink_config becomes write-only) plus a
# read-only extension of diagnostic keys the agent reasons about but never
# writes. Adding a key to the write allowlist therefore makes it readable
# automatically; the reverse is not true.
_CLUSTER_CONFIG_READ_ONLY_EXTRAS = frozenset({
    # Individual checkpointing tuning keys — deliberately NOT the bare
    # "execution.checkpointing." prefix, which would re-admit
    # execution.checkpointing.dir (the checkpoint bucket URI).
    "execution.checkpointing.mode",
    "execution.checkpointing.min-pause",
    "execution.checkpointing.max-concurrent-checkpoints",
    "execution.checkpointing.unaligned.enabled",
    # Exact keys — deliberately NOT a "state.backend." prefix, which would
    # re-admit the legacy state.backend.fs.checkpointdir (a storage URI).
    "state.backend",
    "state.backend.type",
    # Individual pipeline tuning keys — deliberately NOT a "pipeline."
    # prefix, which would re-admit pipeline.jars / pipeline.classpaths /
    # pipeline.cached-files (artifact URIs).
    "pipeline.max-parallelism",
    "pipeline.object-reuse",
    "pipeline.operator-chaining",
})
CLUSTER_CONFIG_READ_ALLOWLIST = ALLOWED_FLINK_CONFIG_KEYS | _CLUSTER_CONFIG_READ_ONLY_EXTRAS
_CLUSTER_CONFIG_ALLOWLIST_PREFIXES = (
    "taskmanager.memory.",
    "jobmanager.memory.",
    "restart-strategy",
    "job.autoscaler.",
)
# Value-level backstop: even an allowlisted key is dropped when its value
# looks like a location or credential. The credential/PII shapes come from
# audit._SECRET_PATTERNS via has_secret_shape() — one definition for the
# audit scrubber and this filter, so they cannot drift. The URI-scheme check
# is local because the audit scrubber deliberately keeps plain URLs (it only
# masks userinfo), whereas here a storage location itself is the leak.
_URI_SCHEME = re.compile(r"://")


def _looks_sensitive(value) -> bool:
    text = str(value)
    return bool(_URI_SCHEME.search(text)) or has_secret_shape(text)


def _filter_cluster_config(raw: Dict) -> Dict:
    """Closed allowlist over the whole-cluster config (defence in depth
    behind Flink's own hideSensitiveValues masking, not a replacement).
    Drop-by-default; a value-level backstop drops even allowlisted entries
    whose value looks like a URI or credential. Non-string keys (Flink
    would never emit them, but a proxy or fixture might) are dropped rather
    than raised on."""
    filtered = {}
    for key, value in raw.items():
        if not isinstance(key, str):
            continue
        if (
            key not in CLUSTER_CONFIG_READ_ALLOWLIST
            and not key.startswith(_CLUSTER_CONFIG_ALLOWLIST_PREFIXES)
        ):
            continue
        if _looks_sensitive(value):
            continue
        filtered[key] = value
    return filtered


class FlinkClient:
    def __init__(self):
        # Fail closed at construction: a Flink endpoint that is neither
        # loopback nor an allowed https host must stop the pod from starting,
        # not surface at first request.
        self.base_url = validate_destination(
            os.getenv("FLINK_JM_ENDPOINT", "http://127.0.0.1:8081"),
            name="FLINK_JM_ENDPOINT", require_https=True, allow_loopback=True,
        )
        self.timeout = aiohttp.ClientTimeout(total=30)
        # Certificate verification defaults ON (matches README.md and
        # ARCHITECTURE.md). Opting out is explicit and loud.
        self.ssl_verify = os.getenv("FLINK_SSL_VERIFY", "true").lower() != "false"
        if not self.ssl_verify:
            logger.warning(
                "FLINK_SSL_VERIFY=false: TLS certificate verification for the "
                "Flink REST endpoint is DISABLED — dev/test only"
            )
        self.ssl_ca_bundle = os.getenv("FLINK_SSL_CA_BUNDLE", DEFAULT_FLINK_SSL_CA_BUNDLE)
        # TLS name the server certificate is verified against (SNI + hostname
        # check). None = the URL host. Set by the 301 upgrade when Flink names
        # its rest.address in the Location while the connection itself stays
        # on the pod's loopback (see _should_honor_ssl_redirect).
        self.server_hostname: Optional[str] = None
        self._uses_https = urlparse(self.base_url).scheme == "https"
        self._ssl_param = self._build_ssl_param() if self._uses_https else False
        self._protocol_detected = self._uses_https
        logger.info("FlinkClient initialized: base_url=%s, ssl_verify=%s", self.base_url, self.ssl_verify)

    def _build_ssl_param(self):
        """aiohttp ``ssl=`` value for an https hop: False when verification is
        explicitly disabled, otherwise a verifying context trusting the configured CA
        bundle when it is present on disk and the system trust store otherwise."""
        if not self.ssl_verify:
            return False
        if self.ssl_ca_bundle and os.path.isfile(self.ssl_ca_bundle):
            logger.info("Flink REST TLS: trusting CA bundle %s", self.ssl_ca_bundle)
            return ssl.create_default_context(cafile=self.ssl_ca_bundle)
        return ssl.create_default_context()

    def _should_honor_ssl_redirect(self, location: str, path: str = "") -> bool:
        """Accept a 301 as an SSL-upgrade signal only when it asks for the
        SAME resource over https on the SAME port — i.e. Flink's own
        ``security.ssl.rest.enabled`` redirect. The redirect is unauthenticated
        input and must never steer this client (and its subsequent requests)
        to a different destination, port or path.

        The Location host is deliberately NOT required to be our loopback:
        Flink builds it from ``rest.address`` (the JobManager's service name,
        never 127.0.0.1), so a strict same-host rule would leave every REST
        call on the shipped production config stuck on ``HTTP 301``. Instead,
        a non-loopback Location host is treated as a scheme-only upgrade of
        the loopback base: the socket still goes to 127.0.0.1, the Location
        host becomes the TLS ``server_hostname`` (SNI + certificate name
        check) — exactly what the in-pod nginx proxy does for the same hop.
        """
        loc = urlparse(location)
        if loc.scheme != "https" or not loc.hostname:
            return False
        base = urlparse(self.base_url)
        # Flink redirects to the same REST port; anything else is not the
        # scheme upgrade we are looking for.
        if (loc.port or 443) != (base.port or 80):
            return False
        # Same resource only: a Location pointing elsewhere on the server is
        # not an upgrade signal.
        req = urlparse(path)
        if (loc.path or "/") != (req.path or "/"):
            return False
        if loc.query and loc.query != req.query:
            return False
        if is_loopback(loc.hostname) or loc.hostname == base.hostname:
            return True
        # Named host: acceptable ONLY as a TLS name on top of a loopback base
        # (the base is loopback by construction for any http:// FlinkClient —
        # validate_destination rejects plaintext off-box — but check anyway).
        return is_loopback(base.hostname or "")

    def _upgrade_to_https(self, location: str = ""):
        # Scheme-only rewrite of the already-validated base_url: host and port
        # are unchanged, so the egress policy verdict from construction still
        # holds and the TCP connection stays on the pod's own loopback. A
        # non-loopback Location host is used solely as the TLS name.
        old = self.base_url
        parsed = urlparse(self.base_url)
        self.base_url = urlunparse(parsed._replace(scheme="https"))
        loc_host = urlparse(location).hostname if location else None
        if loc_host and not is_loopback(loc_host) and loc_host != parsed.hostname:
            self.server_hostname = loc_host
        self._uses_https = True
        self._ssl_param = self._build_ssl_param()
        logger.info(
            "Flink REST SSL detected (301 redirect), switching: %s -> %s (tls name=%s)",
            old, self.base_url, self.server_hostname or parsed.hostname,
        )

    async def _request(self, method: str, path: str, **kwargs) -> Optional[Dict]:
        url = f"{self.base_url}{path}"
        tls_kwargs = {}
        if self._uses_https and self.server_hostname:
            tls_kwargs["server_hostname"] = self.server_hostname
        try:
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.request(
                    method, url, ssl=self._ssl_param,
                    allow_redirects=False, **tls_kwargs, **kwargs,
                ) as resp:
                    if resp.status == 200:
                        return await resp.json()
                    if (
                        resp.status == 301
                        and not self._protocol_detected
                    ):
                        location = resp.headers.get("Location", "")
                        if self._should_honor_ssl_redirect(location, path):
                            self._protocol_detected = True
                            self._upgrade_to_https(location)
                            return await self._request(method, path, **kwargs)
                    self._protocol_detected = True
                    logger.warning("Flink API %s %s returned %s", method, path, resp.status)
                    return {"error": f"HTTP {resp.status}", "path": path}
        except aiohttp.ClientError as e:
            # Opaque, correlatable message: connection errors embed endpoint
            # detail (CWE-209); full text stays server-side via client_error.
            return {"error": client_error("Flink REST request", e), "path": path}

    async def _get(self, path: str) -> Optional[Dict]:
        return await self._request("GET", path)

    async def _post(self, path: str, **kwargs) -> Optional[Dict]:
        return await self._request("POST", path, **kwargs)

    # ── Basic Info ───────────────────────────────────────────────────

    async def get_jobs(self) -> List[Dict]:
        result = await self._get("/jobs")
        if result and "jobs" in result:
            return result["jobs"]
        return []

    async def get_job_details(self, job_id: str) -> Dict:
        return await self._get(f"/jobs/{job_id}") or {}

    async def get_job_scoped_config(self, job_id: str) -> Dict:
        """The per-job /jobs/{id}/config payload. Single accessor for BOTH
        consumers (get_job_config for the agent tool, get_full_diagnostics for
        the HTTP bundle) so any future filtering of job-scoped config — e.g.
        user globalJobParameters, the known residual — is
        applied once, here, and reaches every sink."""
        return await self._get(f"/jobs/{job_id}/config") or {}

    async def get_job_config(self, job_id: str) -> Dict:
        job_config = await self.get_job_scoped_config(job_id)
        cluster_raw = await self._get("/jobmanager/config")
        result = {"job_config": job_config}
        # Cluster config comes as a list of {"key": ..., "value": ...} entries.
        # A non-200 / transport failure comes back as an error dict from
        # _request; surface that distinctly so an empty cluster_config is
        # never mistaken for "everything was filtered" (or vice versa).
        if isinstance(cluster_raw, list):
            cluster_dict = {}
            for entry in cluster_raw:
                if not isinstance(entry, dict):
                    continue
                key = entry.get("key")
                if isinstance(key, str) and key:
                    cluster_dict[key] = entry.get("value", "")
            # Every consumer of this method receives only allowlisted
            # cluster keys — the raw cluster dict never leaves this client.
            result["cluster_config"] = _filter_cluster_config(cluster_dict)
        else:
            error = (
                cluster_raw.get("error") if isinstance(cluster_raw, dict) else None
            ) or "unexpected /jobmanager/config response"
            result["cluster_config"] = {}
            result["cluster_config_error"] = str(error)
        return result

    async def get_job_exceptions(self, job_id: str) -> Dict:
        return await self._get(f"/jobs/{job_id}/exceptions") or {}

    async def get_running_job_id(self) -> Optional[str]:
        jobs = await self.get_jobs()
        for job in jobs:
            if job.get("status") == "RUNNING":
                return job["id"]
        if jobs:
            return jobs[0].get("id")
        return None

    # ── Checkpoints ──────────────────────────────────────────────────

    async def get_checkpoints(self, job_id: str) -> Dict:
        return await self._get(f"/jobs/{job_id}/checkpoints") or {}

    async def get_checkpoint_details(self, job_id: str, checkpoint_id: int) -> Dict:
        return await self._get(f"/jobs/{job_id}/checkpoints/details/{checkpoint_id}") or {}

    async def analyze_checkpoint_health(self, job_id: str) -> Dict:
        cp_data = await self.get_checkpoints(job_id)
        if not cp_data or "error" in cp_data:
            return {"status": "unknown", "error": cp_data.get("error", "No checkpoint data")}

        counts = cp_data.get("counts", {})
        latest = cp_data.get("latest", {})
        history = cp_data.get("history", [])

        completed = latest.get("completed")
        failed = latest.get("failed")

        analysis = {
            "total_checkpoints": counts.get("total", 0),
            "completed": counts.get("completed", 0),
            "failed": counts.get("failed", 0),
            "in_progress": counts.get("in_progress", 0),
            "issues": [],
        }

        if completed:
            duration = completed.get("duration", 0)
            size = completed.get("state_size", 0)
            analysis["latest_completed"] = {
                "id": completed.get("id"),
                "duration_ms": duration,
                "state_size_bytes": size,
                "trigger_timestamp": completed.get("trigger_timestamp"),
            }
            if duration > 60000:
                analysis["issues"].append({
                    "type": "slow_checkpoint",
                    "message": f"Last checkpoint took {duration}ms (>60s)",
                    "severity": "warning",
                })
            if duration > 180000:
                analysis["issues"][-1]["severity"] = "critical"

        if failed:
            analysis["latest_failed"] = {
                "id": failed.get("id"),
                "failure_timestamp": failed.get("failure_timestamp"),
                "failure_message": failed.get("failure_message"),
            }
            analysis["issues"].append({
                "type": "checkpoint_failure",
                "message": f"Recent checkpoint failure: {failed.get('failure_message', 'unknown')}",
                "severity": "critical",
            })

        if counts.get("failed", 0) > 0:
            fail_rate = counts["failed"] / max(counts.get("total", 1), 1)
            if fail_rate > 0.1:
                analysis["issues"].append({
                    "type": "high_failure_rate",
                    "message": f"Checkpoint failure rate: {fail_rate:.1%}",
                    "severity": "warning",
                })

        # Analyze recent history for duration trends
        if history:
            durations = [h.get("duration", 0) for h in history if h.get("status") == "COMPLETED"]
            if durations:
                analysis["duration_trend"] = {
                    "min_ms": min(durations),
                    "max_ms": max(durations),
                    "avg_ms": sum(durations) / len(durations),
                    "samples": len(durations),
                }

        analysis["status"] = "unhealthy" if analysis["issues"] else "healthy"
        return analysis

    # ── Metrics ──────────────────────────────────────────────────────

    async def get_comprehensive_metrics(self, job_id: str) -> Dict:
        details = await self.get_job_details(job_id)
        if not details or "error" in details:
            return {"error": "Could not get job details"}

        vertices = details.get("vertices", [])
        metrics = {}

        for vertex in vertices:
            vid = vertex["id"]
            name = vertex.get("name", vid)
            vertex_metrics = await self._get(
                f"/jobs/{job_id}/vertices/{vid}/metrics"
            )
            metric_names = []
            if vertex_metrics and isinstance(vertex_metrics, list):
                metric_names = [m["id"] for m in vertex_metrics]

            target_metrics = [
                m for m in metric_names
                if any(k in m for k in [
                    "numRecordsIn", "numRecordsOut", "numBytesIn", "numBytesOut",
                    "busyTimeMsPerSecond", "backPressuredTimeMsPerSecond",
                    "idleTimeMsPerSecond", "currentInputWatermark",
                ])
            ]

            if target_metrics:
                metric_values = await self._get(
                    f"/jobs/{job_id}/vertices/{vid}/metrics"
                    f"?get={','.join(target_metrics[:20])}"
                )
                metrics[name] = {
                    "vertex_id": vid,
                    "parallelism": vertex.get("parallelism", 0),
                    "status": vertex.get("status"),
                    "metrics": {
                        m["id"]: m.get("value", "0")
                        for m in (metric_values or [])
                        if isinstance(m, dict)
                    },
                }
            else:
                metrics[name] = {
                    "vertex_id": vid,
                    "parallelism": vertex.get("parallelism", 0),
                    "status": vertex.get("status"),
                    "metrics": {},
                }

        return metrics

    # ── Backpressure ─────────────────────────────────────────────────

    async def get_backpressure(self, job_id: str, vertex_id: str) -> Dict:
        return await self._get(f"/jobs/{job_id}/vertices/{vertex_id}/backpressure") or {}

    async def analyze_backpressure(self, job_id: str) -> Dict:
        details = await self.get_job_details(job_id)
        if not details or "error" in details:
            return {"error": "Could not get job details"}

        vertices = details.get("vertices", [])
        backpressure_info = {}
        issues = []

        for vertex in vertices:
            vid = vertex["id"]
            name = vertex.get("name", vid)
            bp = await self.get_backpressure(job_id, vid)

            status = bp.get("backpressure-level", bp.get("status", "unknown"))
            subtasks = bp.get("subtasks", [])

            bp_ratios = [
                st.get("backPressuredTimeMsPerSecond", st.get("ratio", 0))
                for st in subtasks
            ]

            backpressure_info[name] = {
                "vertex_id": vid,
                "status": status,
                "subtask_count": len(subtasks),
                "backpressure_ratios": bp_ratios,
            }

            if status in ("HIGH", "high"):
                issues.append({
                    "vertex": name,
                    "vertex_id": vid,
                    "level": status,
                    "message": f"High backpressure detected on '{name}'",
                    "severity": "critical",
                })
            elif status in ("OK", "ok", "LOW", "low"):
                pass
            elif bp_ratios and max(bp_ratios) > 500:
                issues.append({
                    "vertex": name,
                    "vertex_id": vid,
                    "level": "elevated",
                    "message": f"Elevated backpressure on '{name}'",
                    "severity": "warning",
                })

        return {
            "vertices": backpressure_info,
            "issues": issues,
            "has_backpressure": len(issues) > 0,
        }

    # ── Skewness ─────────────────────────────────────────────────────

    async def analyze_skewness(self, job_id: str) -> Dict:
        details = await self.get_job_details(job_id)
        if not details or "error" in details:
            return {"error": "Could not get job details"}

        vertices = details.get("vertices", [])
        skewness_info = {}
        issues = []

        for vertex in vertices:
            vid = vertex["id"]
            name = vertex.get("name", vid)
            parallelism = vertex.get("parallelism", 1)

            if parallelism <= 1:
                continue

            subtask_metrics = await self._get(
                f"/jobs/{job_id}/vertices/{vid}/subtasks/metrics"
                f"?get=numRecordsIn,numBytesIn,busyTimeMsPerSecond"
            )

            if not subtask_metrics or not isinstance(subtask_metrics, list):
                continue

            for metric_entry in subtask_metrics:
                metric_id = metric_entry.get("id", "")
                values = []
                for st in metric_entry.get("subtasks", metric_entry.get("values", [])):
                    if isinstance(st, dict):
                        values.append(float(st.get("value", 0)))
                    else:
                        values.append(float(st))

                if not values or max(values) == 0:
                    continue

                avg = sum(values) / len(values)
                if avg == 0:
                    continue
                max_val = max(values)
                min_val = min(values)
                skew_ratio = max_val / avg

                if metric_id not in skewness_info.get(name, {}):
                    if name not in skewness_info:
                        skewness_info[name] = {}
                    skewness_info[name][metric_id] = {
                        "min": min_val,
                        "max": max_val,
                        "avg": avg,
                        "skew_ratio": round(skew_ratio, 2),
                        "values": values,
                    }

                    if skew_ratio > 3.0:
                        issues.append({
                            "vertex": name,
                            "metric": metric_id,
                            "skew_ratio": round(skew_ratio, 2),
                            "message": f"Data skew on '{name}' for {metric_id}: max/avg = {skew_ratio:.1f}x",
                            "severity": "warning" if skew_ratio < 5.0 else "critical",
                        })

        return {
            "vertices": skewness_info,
            "issues": issues,
            "has_skewness": len(issues) > 0,
        }

    # ── TaskManagers ─────────────────────────────────────────────────

    async def get_taskmanagers(self) -> List[Dict]:
        result = await self._get("/taskmanagers")
        if result and "taskmanagers" in result:
            return result["taskmanagers"]
        return []

    async def get_jobmanager_thread_dump(self) -> Dict:
        return await self._get("/jobmanager/thread-dump") or {}

    async def get_taskmanager_thread_dump(self, tm_id: str) -> Dict:
        return await self._get(f"/taskmanagers/{tm_id}/thread-dump") or {}

    async def get_all_thread_dumps(self) -> Dict:
        tms = await self.get_taskmanagers()
        dumps = {}
        for tm in tms:
            tm_id = tm.get("id", "")
            if tm_id:
                dump = await self.get_taskmanager_thread_dump(tm_id)
                dumps[tm_id] = dump
        return dumps

    async def analyze_thread_dumps(self, component: str = "all") -> Dict:
        """Analyze thread dumps. component can be 'jobmanager', 'taskmanager', or 'all'."""
        analysis = {
            "component": component,
            "thread_states": {},
            "blocked_threads": [],
            "waiting_threads": [],
            "issues": [],
        }

        dumps = {}
        if component in ("jobmanager", "all"):
            jm_dump = await self.get_jobmanager_thread_dump()
            if jm_dump:
                dumps["jobmanager"] = jm_dump
        if component in ("taskmanager", "all"):
            tm_dumps = await self.get_all_thread_dumps()
            for tm_id, dump in tm_dumps.items():
                dumps[f"taskmanager-{tm_id}"] = dump

        analysis["component_count"] = len(dumps)

        for comp_id, dump in dumps.items():
            entries = dump.get("threadInfos", dump.get("threads", []))
            if not isinstance(entries, list):
                continue
            for thread in entries:
                thread_name = thread.get("threadName", thread.get("name", "unknown"))
                thread_state = thread.get("threadState", thread.get("state", "UNKNOWN"))
                stack = thread.get("stringifiedThreadInfo", thread.get("stackTrace", ""))

                analysis["thread_states"][thread_state] = (
                    analysis["thread_states"].get(thread_state, 0) + 1
                )

                if thread_state == "BLOCKED":
                    analysis["blocked_threads"].append({
                        "component": comp_id,
                        "thread": thread_name,
                        "stack_snippet": stack[:500] if isinstance(stack, str) else "",
                    })
                elif thread_state == "WAITING" or thread_state == "TIMED_WAITING":
                    if isinstance(stack, str) and any(
                        k in stack for k in ["java.net", "jdbc", "http", "socket"]
                    ):
                        analysis["waiting_threads"].append({
                            "component": comp_id,
                            "thread": thread_name,
                            "stack_snippet": stack[:500],
                        })

        if analysis["blocked_threads"]:
            analysis["issues"].append({
                "type": "blocked_threads",
                "count": len(analysis["blocked_threads"]),
                "message": f"{len(analysis['blocked_threads'])} blocked threads detected",
                "severity": "critical",
            })

        if analysis["waiting_threads"]:
            analysis["issues"].append({
                "type": "io_waiting_threads",
                "count": len(analysis["waiting_threads"]),
                "message": f"{len(analysis['waiting_threads'])} threads waiting on I/O",
                "severity": "warning",
            })

        return analysis

    # ── Resources ────────────────────────────────────────────────────

    async def analyze_resource_usage(self) -> Dict:
        tms = await self.get_taskmanagers()
        resources = {
            "taskmanager_count": len(tms),
            "taskmanagers": [],
            "issues": [],
        }

        for tm in tms:
            tm_id = tm.get("id", "")
            hw = tm.get("hardware", tm.get("resources", {}))
            mem_total = hw.get("freeMemory", 0) + hw.get("managedMemory", 0)
            mem_used = hw.get("managedMemory", 0)

            tm_info = {
                "id": tm_id,
                "slots_total": tm.get("slotsNumber", tm.get("freeSlots", 0)),
                "slots_available": tm.get("freeSlots", 0),
                "hardware": hw,
            }
            resources["taskmanagers"].append(tm_info)

            if tm.get("freeSlots", 1) == 0 and tm.get("slotsNumber", 0) > 0:
                resources["issues"].append({
                    "taskmanager": tm_id,
                    "type": "no_free_slots",
                    "message": "All slots occupied",
                    "severity": "info",
                })

        return resources

    # ── Savepoint ────────────────────────────────────────────────────

    async def trigger_savepoint(self, job_id: str, target_dir: str = "") -> Dict:
        body = {}
        if target_dir:
            body["target-directory"] = target_dir
        body["cancel-job"] = False
        return await self._post(f"/jobs/{job_id}/savepoints", json=body) or {}

    async def get_savepoint_status(self, job_id: str, trigger_id: str) -> Dict:
        return await self._get(f"/jobs/{job_id}/savepoints/{trigger_id}") or {}

    # ── Full Diagnostics ─────────────────────────────────────────────

    async def get_full_diagnostics(self, job_id: str) -> Dict:
        details = await self.get_job_details(job_id)
        # Job-scoped config only: the whole-cluster configuration must not
        # reach the HTTP diagnostics bundle. Nothing downstream consumes a
        # cluster_config key here (all_issues is built solely from
        # checkpoints/backpressure/skewness); the agent tool retains a
        # filtered cluster view via get_job_config(). Same accessor as
        # get_job_config so job-scoped filtering has one home.
        config = {"job_config": await self.get_job_scoped_config(job_id)}
        exceptions = await self.get_job_exceptions(job_id)
        checkpoints = await self.analyze_checkpoint_health(job_id)
        metrics = await self.get_comprehensive_metrics(job_id)
        backpressure = await self.analyze_backpressure(job_id)
        skewness = await self.analyze_skewness(job_id)
        resources = await self.analyze_resource_usage()

        all_issues = []
        for section in [checkpoints, backpressure, skewness]:
            if isinstance(section, dict):
                all_issues.extend(section.get("issues", []))

        return {
            "job_details": details,
            "job_config": config,
            "exceptions": exceptions,
            "checkpoints": checkpoints,
            "metrics": metrics,
            "backpressure": backpressure,
            "skewness": skewness,
            "resources": resources,
            "all_issues": all_issues,
            "issue_count": len(all_issues),
        }
