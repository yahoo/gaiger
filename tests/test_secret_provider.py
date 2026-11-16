# Copyright Yahoo, Licensed under the terms of the Apache 2.0 license. See LICENSE for terms.

"""Unit tests for app.secret_provider — the built-in env-var secret backend."""

import importlib

import pytest

_SECRET_VARS = (
    "ANTHROPIC_API_KEY",
    "SLACK_BOT_TOKEN",
    "GITHUB_TOKEN",
    "POSTGRES_PASSWORD",
    "GRAFANA_SA_TOKEN",
)


@pytest.fixture()
def sp(monkeypatch):
    """Reload the module so each test starts with empty in-memory state and a clean env."""
    for var in _SECRET_VARS + ("SECRET_PROVIDER",):
        monkeypatch.delenv(var, raising=False)
    from app import secret_provider

    importlib.reload(secret_provider)
    return secret_provider


# --- Anthropic (required) ---------------------------------------------------------

def test_fetch_key_reads_from_env(monkeypatch, sp):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "  sk-ant-test  ")
    sp.fetch_key()
    assert sp.get_api_key() == "sk-ant-test"


def test_fetch_key_missing_raises(sp):
    with pytest.raises(RuntimeError, match="ANTHROPIC_API_KEY"):
        sp.fetch_key()


def test_fetch_key_blank_raises(monkeypatch, sp):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "   ")
    with pytest.raises(RuntimeError, match="ANTHROPIC_API_KEY"):
        sp.fetch_key()


def test_get_api_key_before_fetch_raises(sp):
    with pytest.raises(RuntimeError, match="fetch_key"):
        sp.get_api_key()


# --- Slack (optional) -------------------------------------------------------------

def test_fetch_slack_token_present(monkeypatch, sp):
    monkeypatch.setenv("SLACK_BOT_TOKEN", "xoxb-test")
    assert sp.fetch_slack_token() == "xoxb-test"


@pytest.mark.parametrize("value", [None, "", "   "])
def test_fetch_slack_token_missing_or_blank_is_none(monkeypatch, sp, value):
    if value is not None:
        monkeypatch.setenv("SLACK_BOT_TOKEN", value)
    assert sp.fetch_slack_token() is None


# --- GitHub (optional) ------------------------------------------------------------

def test_fetch_github_token_present(monkeypatch, sp):
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_test")
    assert sp.fetch_github_token() == "ghp_test"


@pytest.mark.parametrize("value", [None, "", "   "])
def test_fetch_github_token_missing_or_blank_is_none(monkeypatch, sp, value):
    if value is not None:
        monkeypatch.setenv("GITHUB_TOKEN", value)
    assert sp.fetch_github_token() is None


# --- Postgres (required when called) ---------------------------------------------

def test_fetch_postgres_password_reads_from_env(monkeypatch, sp):
    monkeypatch.setenv("POSTGRES_PASSWORD", "hunter2")
    sp.fetch_postgres_password()
    assert sp.get_postgres_password() == "hunter2"


@pytest.mark.parametrize("value", [None, "   "])
def test_fetch_postgres_password_missing_or_blank_raises(monkeypatch, sp, value):
    if value is not None:
        monkeypatch.setenv("POSTGRES_PASSWORD", value)
    with pytest.raises(RuntimeError, match="POSTGRES_PASSWORD"):
        sp.fetch_postgres_password()


def test_get_postgres_password_before_fetch_raises(sp):
    with pytest.raises(RuntimeError, match="fetch_postgres_password"):
        sp.get_postgres_password()


# --- Grafana (optional) -----------------------------------------------------------

def test_fetch_grafana_sa_token_present(monkeypatch, sp):
    monkeypatch.setenv("GRAFANA_SA_TOKEN", "glsa_test")
    assert sp.fetch_grafana_sa_token() == "glsa_test"
    assert sp.get_grafana_sa_token() == "glsa_test"


@pytest.mark.parametrize("value", [None, "", "   "])
def test_fetch_grafana_sa_token_missing_or_blank_is_none(monkeypatch, sp, value):
    if value is not None:
        monkeypatch.setenv("GRAFANA_SA_TOKEN", value)
    assert sp.fetch_grafana_sa_token() is None
    assert sp.get_grafana_sa_token() is None


# --- provider selection -----------------------------------------------------------

def test_default_provider_is_env(monkeypatch, sp):
    assert "SECRET_PROVIDER" not in __import__("os").environ
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    sp.fetch_key()
    assert sp.get_api_key() == "sk-ant-test"


def test_explicit_env_provider_accepted(monkeypatch, sp):
    monkeypatch.setenv("SECRET_PROVIDER", "env")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    sp.fetch_key()
    assert sp.get_api_key() == "sk-ant-test"


@pytest.mark.parametrize("provider", ["vault", "kms", "ENV2"])
def test_unknown_provider_raises_even_when_env_var_present(monkeypatch, sp, provider):
    """Misconfigured provider must fail closed, not silently fall back to env."""
    monkeypatch.setenv("SECRET_PROVIDER", provider)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    monkeypatch.setenv("SLACK_BOT_TOKEN", "xoxb-test")
    with pytest.raises(RuntimeError, match="Unknown SECRET_PROVIDER"):
        sp.fetch_key()
    with pytest.raises(RuntimeError, match="Unknown SECRET_PROVIDER"):
        sp.fetch_slack_token()
