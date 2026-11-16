# Copyright Yahoo, Licensed under the terms of the Apache 2.0 license. See LICENSE for terms.

import pytest
from app.langgraph_agent import SYSTEM_PROMPT, is_leakage_attempt


def _first_prompt_line() -> str:
    return [l.strip() for l in SYSTEM_PROMPT.splitlines() if l.strip()][0]


def test_leakage_patterns_match_system_prompt_opening():
    assert is_leakage_attempt(_first_prompt_line())


def test_leakage_patterns_case_insensitive():
    assert is_leakage_attempt(_first_prompt_line().upper())


def test_leakage_patterns_no_false_positive():
    assert not is_leakage_attempt("The job is failing due to backpressure")
    assert not is_leakage_attempt("Checkpoint interval is too short")
