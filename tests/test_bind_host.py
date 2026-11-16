"""Bind-host resolution tests (loopback bind hardening).

The loopback bind on :8765 is the standing cross-pod control for the
debugger API, which performs no authorization of its own. resolve_bind_host() must
make undoing that control a two-variable, loudly-logged act:

  - default bind is 127.0.0.1;
  - HOST alone is IGNORED (the old one-variable escape hatch is gone);
  - HOST is honored only when ALLOW_NON_LOOPBACK_BIND=true (stripped,
    case-insensitive) is also set, and a warning is logged;
  - a non-loopback HOST WITHOUT the opt-in logs a warning that it had no effect and
    why, then binds loopback as before.

Imports the FastAPI app module, so it requires the app dependencies; in a bare
local shell without those deps it skips cleanly via importorskip (same pattern as
test_cors.py).
"""
import logging

import pytest

pytest.importorskip("fastapi")


@pytest.fixture()
def main_module(monkeypatch):
    monkeypatch.setenv("SECRET_PROVIDER", "env")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "dummy")
    import app.main as main
    return main


def test_default_is_loopback(monkeypatch, main_module):
    monkeypatch.delenv("HOST", raising=False)
    monkeypatch.delenv("ALLOW_NON_LOOPBACK_BIND", raising=False)
    assert main_module.resolve_bind_host() == "127.0.0.1"


def test_host_alone_is_ignored(monkeypatch, main_module):
    """The pre-fix one-variable escape hatch must be dead: HOST alone changes nothing."""
    monkeypatch.setenv("HOST", "0.0.0.0")
    monkeypatch.delenv("ALLOW_NON_LOOPBACK_BIND", raising=False)
    assert main_module.resolve_bind_host() == "127.0.0.1"


@pytest.mark.parametrize("flag", [None, "", "false", "0", "yes"])
def test_host_alone_warns_that_it_had_no_effect(monkeypatch, main_module, caplog, flag):
    """A non-loopback HOST without the opt-in is a no-op, and the log must say so and why,
    naming the variable that would make it effective. Still binds loopback."""
    monkeypatch.setenv("HOST", "0.0.0.0")
    if flag is None:
        monkeypatch.delenv("ALLOW_NON_LOOPBACK_BIND", raising=False)
    else:
        monkeypatch.setenv("ALLOW_NON_LOOPBACK_BIND", flag)
    with caplog.at_level(logging.WARNING, logger="app.main"):
        assert main_module.resolve_bind_host() == "127.0.0.1"
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING and r.name == "app.main"]
    assert len(warnings) == 1, [r.getMessage() for r in caplog.records]
    msg = warnings[0].getMessage()
    assert "HOST=0.0.0.0" in msg and "had no effect" in msg, msg
    assert "ALLOW_NON_LOOPBACK_BIND=true" in msg, "the warning must name what would make HOST effective"
    assert "no authorization" in msg, "the warning must say why the bind stays on loopback"
    assert "127.0.0.1" in msg, "the warning must say what was bound instead"


@pytest.mark.parametrize("host", ["127.0.0.1", "localhost", "::1", "", "  "])
def test_loopback_or_empty_host_without_optin_is_silent(monkeypatch, main_module, caplog, host):
    """Nothing to warn about: the requested value is already loopback (or unset/blank)."""
    monkeypatch.setenv("HOST", host)
    monkeypatch.delenv("ALLOW_NON_LOOPBACK_BIND", raising=False)
    with caplog.at_level(logging.WARNING, logger="app.main"):
        assert main_module.resolve_bind_host() == "127.0.0.1"
    assert not [r for r in caplog.records if r.name == "app.main" and r.levelno >= logging.WARNING]


def test_unset_host_without_optin_is_silent(monkeypatch, main_module, caplog):
    monkeypatch.delenv("HOST", raising=False)
    monkeypatch.delenv("ALLOW_NON_LOOPBACK_BIND", raising=False)
    with caplog.at_level(logging.WARNING, logger="app.main"):
        assert main_module.resolve_bind_host() == "127.0.0.1"
    assert not [r for r in caplog.records if r.name == "app.main" and r.levelno >= logging.WARNING]


def test_optin_honors_host_and_warns(monkeypatch, main_module, caplog):
    monkeypatch.setenv("HOST", "0.0.0.0")
    monkeypatch.setenv("ALLOW_NON_LOOPBACK_BIND", "true")
    with caplog.at_level(logging.WARNING, logger="app.main"):
        assert main_module.resolve_bind_host() == "0.0.0.0"
    assert any(
        "ALLOW_NON_LOOPBACK_BIND" in rec.getMessage()
        and "no authorization" in rec.getMessage()
        for rec in caplog.records
    ), "opting out of the loopback bind must produce an explicit warning"


def test_optin_is_stripped_and_case_insensitive(monkeypatch, main_module):
    monkeypatch.setenv("HOST", "0.0.0.0")
    monkeypatch.setenv("ALLOW_NON_LOOPBACK_BIND", "  TRUE  ")
    assert main_module.resolve_bind_host() == "0.0.0.0"


@pytest.mark.parametrize("flag", ["", "false", "0", "1", "yes", "garbage", "TRUE!"])
def test_non_true_optin_values_are_ignored(monkeypatch, main_module, flag):
    monkeypatch.setenv("HOST", "0.0.0.0")
    monkeypatch.setenv("ALLOW_NON_LOOPBACK_BIND", flag)
    assert main_module.resolve_bind_host() == "127.0.0.1"


def test_optin_without_host_stays_loopback(monkeypatch, main_module):
    monkeypatch.delenv("HOST", raising=False)
    monkeypatch.setenv("ALLOW_NON_LOOPBACK_BIND", "true")
    assert main_module.resolve_bind_host() == "127.0.0.1"
