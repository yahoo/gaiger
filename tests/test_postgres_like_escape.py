# Copyright Yahoo, Licensed under the terms of the Apache 2.0 license. See LICENSE for terms.

"""Deterministic tests for LIKE-metacharacter escaping in the Postgres client.

Pure stdlib — exercises the `_like_contains` helper and the shape of the SQL
literals in app.postgres_client without a database or event loop.

The weakness class (CWE-943): a job_id interpolated raw into a `%…%` LIKE
value lets `%` / `_` act as wildcards and broaden the match across the
autoscaler tables. The fix escapes the metacharacters and states the escape
character explicitly with `LIKE $1 ESCAPE '\\'` in every query.
"""
import inspect
import types
from pathlib import Path

from app.postgres_client import LIKE_ESCAPE, PostgresStateReader, _like_contains

MODULE_SOURCE = Path(
    inspect.getsourcefile(PostgresStateReader)
).read_text(encoding="utf-8")

# The exact number of LIKE sites in the module. If a query is added or
# removed, update this deliberately — every LIKE site must use the helper
# and carry the ESCAPE clause.
EXPECTED_LIKE_SITES = 7


# ── Helper semantics ────────────────────────────────────────────────────────

def test_metacharacters_are_escaped():
    assert _like_contains("ab%c_d") == r"%ab\%c\_d%"


def test_backslash_is_doubled_before_metacharacter_escaping():
    # The escape character itself must be escaped first; if the order were
    # wrong, the backslash introduced for % / _ would itself get doubled.
    assert _like_contains("a\\b") == r"%a\\b%"
    assert _like_contains("\\%") == r"%\\\%%"


def test_normal_flink_job_id_is_unchanged():
    # Regression guard: a real Flink JobID (32 lowercase hex chars) contains
    # no metacharacters and must pass through untouched apart from the
    # surrounding contains-anchors.
    job_id = "00112233445566778899aabbccddeeff"
    assert _like_contains(job_id) == f"%{job_id}%"


def test_lone_percent_matches_literally_not_all_rows():
    # Before the fix, job_id="%" produced the pattern "%%%" (matches every
    # row). After, the % is escaped and only a literal percent sign matches.
    assert _like_contains("%") == r"%\%%"


def test_lone_underscore_is_escaped():
    assert _like_contains("_") == r"%\_%"


def test_empty_value_yields_bare_contains_anchors():
    assert _like_contains("") == "%%"


def test_escape_character_is_backslash():
    assert LIKE_ESCAPE == "\\"


# ── Structural checks on the module ────────────────────────────────────────

def test_no_raw_job_id_interpolation_remains():
    assert 'f"%{job_id}%"' not in MODULE_SOURCE


def test_every_like_site_uses_the_helper():
    assert MODULE_SOURCE.count("_like_contains(job_id)") == EXPECTED_LIKE_SITES


def test_every_like_site_declares_the_escape_clause():
    # Match the full clause, not the bare word ESCAPE — the helper introduces
    # additional uses of the LIKE_ESCAPE constant elsewhere in the module.
    assert MODULE_SOURCE.count("LIKE $1 ESCAPE") == EXPECTED_LIKE_SITES


def _string_constants(code):
    """Yield every string constant reachable from a code object."""
    for const in code.co_consts:
        if isinstance(const, str):
            yield const
        elif isinstance(const, types.CodeType):
            yield from _string_constants(const)


def test_runtime_sql_carries_single_backslash_escape_clause():
    # The SQL lives in non-raw triple-quoted literals, where a sloppy edit
    # (ESCAPE '\' instead of ESCAPE '\\') would silently emit ESCAPE ''.
    # Inspect the actual runtime string constants, not the source text.
    like_sql = []
    for member in vars(PostgresStateReader).values():
        if isinstance(member, types.FunctionType):
            like_sql.extend(
                s for s in _string_constants(member.__code__) if "LIKE $1" in s
            )
    assert len(like_sql) == EXPECTED_LIKE_SITES
    for sql in like_sql:
        assert "LIKE $1 ESCAPE '\\'" in sql, sql
        assert "ESCAPE '\\\\'" not in sql, sql
