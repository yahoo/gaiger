# Copyright Yahoo, Licensed under the terms of the Apache 2.0 license. See LICENSE for terms.

import asyncio
import logging
from collections import deque
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from app.safe_errors import client_error

logger = logging.getLogger(__name__)

# 6 hours at 30-second intervals = 720 entries
MAX_HISTORY_SIZE = 720


class MetricsCollector:
    def __init__(self, flink_client):
        self.flink_client = flink_client
        self.metrics_history: deque = deque(maxlen=MAX_HISTORY_SIZE)
        self._task: Optional[asyncio.Task] = None
        self._running = False

    # ── Background Collection ────────────────────────────────────────────────

    async def start_background_collection(self):
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._collection_loop())
        logger.info("Background metrics collection started (every 30s)")

    async def stop_background_collection(self):
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
        logger.info("Background metrics collection stopped")

    async def _collection_loop(self):
        while self._running:
            try:
                await self._collect_snapshot()
            except Exception as e:
                logger.error("Error collecting metrics snapshot: %s", e)
            await asyncio.sleep(30)

    async def _collect_snapshot(self):
        job_id = await self.flink_client.get_running_job_id()
        if not job_id:
            return

        snapshot = {
            "timestamp": datetime.utcnow().isoformat(),
            "job_id": job_id,
        }

        try:
            details = await self.flink_client.get_job_details(job_id)
            snapshot["job_status"] = details.get("state", "UNKNOWN")
            snapshot["vertices"] = []
            for vertex in details.get("vertices", []):
                snapshot["vertices"].append({
                    "name": vertex.get("name", ""),
                    "parallelism": vertex.get("parallelism", 0),
                    "status": vertex.get("status", ""),
                })
        except Exception as e:
            # Snapshot entries are served to callers via /api/metrics/timeseries,
            # so error text must be opaque (CWE-209) — same rule for all three.
            snapshot["job_error"] = client_error("fetch job details", e)

        try:
            metrics = await self.flink_client.get_comprehensive_metrics(job_id)
            vertex_metrics = {}
            for name, data in metrics.items():
                if isinstance(data, dict) and "metrics" in data:
                    vertex_metrics[name] = data["metrics"]
            snapshot["metrics"] = vertex_metrics
        except Exception as e:
            snapshot["metrics_error"] = client_error("fetch job metrics", e)

        try:
            cp = await self.flink_client.get_checkpoints(job_id)
            counts = cp.get("counts", {})
            latest = cp.get("latest", {})
            completed = latest.get("completed", {})
            snapshot["checkpoints"] = {
                "completed_count": counts.get("completed", 0),
                "failed_count": counts.get("failed", 0),
                "latest_duration_ms": completed.get("duration", 0) if completed else 0,
                "latest_size_bytes": completed.get("state_size", 0) if completed else 0,
            }
        except Exception as e:
            snapshot["checkpoint_error"] = client_error("fetch checkpoint stats", e)

        self.metrics_history.append(snapshot)

    # ── Time Series ──────────────────────────────────────────────────────────

    def get_time_series(self, hours: int = 1) -> List[Dict]:
        if not self.metrics_history:
            return []
        cutoff = datetime.utcnow() - timedelta(hours=hours)
        cutoff_str = cutoff.isoformat()
        return [
            entry for entry in self.metrics_history
            if entry.get("timestamp", "") >= cutoff_str
        ]
