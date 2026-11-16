"""Shared test setup.

Starlette's TestClient sends ``Host: testserver``. The app's inbound Host
allowlist (INBOUND_ALLOWED_HOSTS, loopback by default) would refuse that, so
the test host name is added before app.main is imported or reloaded.
"""
import os

os.environ.setdefault("INBOUND_ALLOWED_HOSTS", "testserver")
# The rolling PR cap is process-wide; tests that exercise it set their own value.
os.environ.setdefault("GITHUB_PR_MAX_PER_DAY", "100")
