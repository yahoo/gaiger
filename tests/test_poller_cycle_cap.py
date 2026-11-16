# Copyright Yahoo, Licensed under the terms of the Apache 2.0 license. See LICENSE for terms.

"""Per-poll-cycle cap on alert analyses (CWE-770).

Each analysis is a paid agent run, and anyone who can create firing alerts
controls how many there are. Over GRAFANA_MAX_ANALYSES_PER_CYCLE the rest are
dropped from this cycle (and forgotten, so the next cycle retries them), and the
drop is audited.
"""
import asyncio
from unittest.mock import patch

import pytest

gp = pytest.importorskip("app.grafana_poller")


class _Resp:
    status = 200

    def __init__(self, alerts):
        self._alerts = alerts

    async def json(self):
        return self._alerts

    async def text(self):
        return ""

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False


class _Session:
    def __init__(self, alerts):
        self._alerts = alerts

    def get(self, *a, **k):
        return _Resp(self._alerts)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False


def _alerts(n):
    return [{"fingerprint": f"fp{i}", "startsAt": "t0",
             "labels": {"flink_deployment": "my-job", "alertname": f"a{i}"}}
            for i in range(n)]


def _run_cycle(monkeypatch, n_alerts, cap):
    monkeypatch.setenv("FLINK_DEPLOYMENT_NAME", "my-job")
    monkeypatch.setenv("GRAFANA_URL", "https://grafana.example.com")
    if cap is None:
        monkeypatch.delenv("GRAFANA_MAX_ANALYSES_PER_CYCLE", raising=False)
    else:
        monkeypatch.setenv("GRAFANA_MAX_ANALYSES_PER_CYCLE", cap)
    poller = gp.GrafanaAlertPoller(None, None)
    analyzed, events = [], []

    async def _analyze(alert):
        analyzed.append(alert["fingerprint"])

    monkeypatch.setattr(poller, "_analyze_alert", _analyze)
    monkeypatch.setattr(gp, "audit", lambda event, *a, **kw: events.append((event, kw)))
    with patch.object(gp.secret_provider, "get_grafana_sa_token", return_value="tok"), \
         patch.object(gp.aiohttp, "ClientSession", lambda *a, **k: _Session(_alerts(n_alerts))):
        asyncio.new_event_loop().run_until_complete(poller._poll_once())
    return poller, analyzed, events


def test_ten_alerts_cap_three(monkeypatch):
    poller, analyzed, events = _run_cycle(monkeypatch, 10, "3")
    assert len(analyzed) == 3
    dropped = [kw for ev, kw in events if ev == "alert_analysis_dropped"]
    assert dropped == [{"count": 7, "reason": "per_cycle_cap"}]
    # Dropped alerts are forgotten so the next cycle retries them.
    assert len(poller._seen) == 3


def test_default_cap_is_three(monkeypatch):
    _, analyzed, _ = _run_cycle(monkeypatch, 5, None)
    assert len(analyzed) == 3


def test_under_the_cap_nothing_is_dropped(monkeypatch):
    _, analyzed, events = _run_cycle(monkeypatch, 2, "3")
    assert len(analyzed) == 2
    assert not [e for e, _ in events if e == "alert_analysis_dropped"]
