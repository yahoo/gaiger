# Copyright Yahoo, Licensed under the terms of the Apache 2.0 license. See LICENSE for terms.

import logging

import pytest

from app import write_authz


def _evaluate(monkeypatch, enable, deploy_env, allow_without_env=None):
    if enable is None:
        monkeypatch.delenv("ENABLE_WRITE_TOOLS", raising=False)
    else:
        monkeypatch.setenv("ENABLE_WRITE_TOOLS", enable)
    if deploy_env is None:
        monkeypatch.delenv("DEPLOY_ENV", raising=False)
    else:
        monkeypatch.setenv("DEPLOY_ENV", deploy_env)
    if allow_without_env is None:
        monkeypatch.delenv("ALLOW_WRITE_TOOLS_WITHOUT_ENV", raising=False)
    else:
        monkeypatch.setenv("ALLOW_WRITE_TOOLS_WITHOUT_ENV", allow_without_env)
    return write_authz.write_tools_enabled()


@pytest.mark.parametrize(
    "enable,deploy_env,expected",
    [
        ("true", "nonprod", True),    # opted in on nonprod -> enabled
        ("true", "prod", False),      # prod hard-stop overrides the flag
        ("false", "nonprod", False),  # not opted in
        (None, "nonprod", False),     # default off
        ("true", None, False),                  # missing domain -> unknown -> FAIL CLOSED
        ("true", "", False),                    # blank domain -> unknown -> FAIL CLOSED
        ("true", "corp", False),                # neither prod nor nonprod -> FAIL CLOSED
        ("true", "prod-test", False),           # names both -> prod wins (restrictive)
        ("true", "test.prod", False),           # ... regardless of separator/order
        ("true", "preprod", False),   # no exact segment match -> FAIL CLOSED
        ("TRUE", "nonprod", True),    # flag case-insensitive
        ("true", "PRODUCTION", False),      # domain case-insensitive
        ("true", "prod-us-east-1", False),      # any prod domain blocked
        ("true", "prd", False),       # prd is production
        ("true", "dev", True),        # dev segment -> nonprod
        ("true", "staging", True),    # staging segment -> nonprod
    ],
)
def test_write_tools_gate(monkeypatch, enable, deploy_env, expected):
    assert _evaluate(monkeypatch, enable, deploy_env) is expected


@pytest.mark.parametrize(
    "deploy_env,allow,expected",
    [
        (None, "true", True),                # local dev: unknown env + explicit hatch
        ("", "true", True),                  # blank domain + hatch
        ("corp", "true", False),        # set but unrecognised: the hatch does not apply
        ("prd", "true", False),         # prd is production
        ("prod", "true", False),   # hatch NEVER overrides prod
        ("PRODUCTION", "TRUE", False),   # ... regardless of case
        (None, "false", False),              # hatch present but not truthy
        (None, None, False),                 # hatch absent -> unknown fails closed
    ],
)
def test_local_dev_escape_hatch(monkeypatch, deploy_env, allow, expected):
    assert _evaluate(monkeypatch, "true", deploy_env, allow) is expected


def test_denial_logs_unknown_environment(monkeypatch, caplog):
    """The decisive negative test: flag on + blank domain must deny and log it."""
    with caplog.at_level(logging.WARNING, logger="app.write_authz"):
        assert _evaluate(monkeypatch, "true", "") is False
    assert any("environment=unknown" in r.getMessage() for r in caplog.records)


def test_denial_logs_prod_environment(monkeypatch, caplog):
    with caplog.at_level(logging.WARNING, logger="app.write_authz"):
        assert _evaluate(monkeypatch, "true", "prod") is False
    assert any("environment=prod" in r.getMessage() for r in caplog.records)


def test_escape_hatch_denial_still_logged_on_prod(monkeypatch, caplog):
    """Even with the hatch set, prod denies and the denial is logged."""
    with caplog.at_level(logging.WARNING, logger="app.write_authz"):
        assert _evaluate(monkeypatch, "true", "prod", "true") is False
    assert any("environment=prod" in r.getMessage() for r in caplog.records)
