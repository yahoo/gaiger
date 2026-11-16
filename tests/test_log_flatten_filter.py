# Copyright Yahoo, Licensed under the terms of the Apache 2.0 license. See LICENSE for terms.

"""The plaintext log stream must be newline-safe and bounded (CWE-117).

app/main.py attaches _FlattenFilter to the ROOT handlers, so remote- and
model-controlled content interpolated into plaintext log lines (Grafana API
bodies, alert names, user question text) cannot forge whole log entries via
embedded CR/LF or flood the stream with an unbounded body. The structured JSON
audit channel ("app.audit", propagate=False, own handler) must NOT be touched.

Imports the FastAPI app, so it needs the app dependencies; in a bare local
shell without them it skips cleanly via importorskip — same pattern as the
other endpoint tests.
"""
import importlib
import json
import logging

import pytest

pytest.importorskip("fastapi")


@pytest.fixture
def main_module(monkeypatch):
    monkeypatch.setenv("SECRET_PROVIDER", "env")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "dummy")
    import app.main as main
    importlib.reload(main)
    return main


_FORGERY = "evil\n2026-08-20 00:00:00 [INFO] app.main: forged clean-shutdown entry"


def test_newline_payload_stays_one_line(main_module):
    f = main_module._FlattenFilter()
    rec = logging.LogRecord(
        "app.grafana_poller", logging.INFO, __file__, 1,
        "Processing polled alert: %s", (_FORGERY,), None,
    )
    assert f.filter(rec) is True              # never drops a record
    msg = rec.getMessage()
    assert "\n" not in msg and "\r" not in msg
    assert "\\n" in msg                       # newline neutralized to a literal
    assert "forged clean-shutdown entry" in msg
    assert rec.args == ()                     # no second %-interpolation possible


def test_other_control_characters_are_escaped(main_module):
    # Beyond CR/LF: ESC (terminal control sequences), NUL and backspace must not
    # reach the stream raw; tab is deliberately kept for readability.
    f = main_module._FlattenFilter()
    rec = logging.LogRecord(
        "app.grafana_poller", logging.INFO, __file__, 1,
        "body: \x1b[2Jcleared\x00\x08 and\ttab", None, None,
    )
    f.filter(rec)
    msg = rec.getMessage()
    assert "\x1b" not in msg and "\x00" not in msg and "\x08" not in msg
    assert "\\x1b" in msg
    assert "\t" in msg                        # tab kept


def test_unbounded_remote_body_is_truncated(main_module):
    f = main_module._FlattenFilter()
    rec = logging.LogRecord(
        "app.grafana_poller", logging.INFO, __file__, 1, "X" * 50000, None, None,
    )
    f.filter(rec)
    msg = rec.getMessage()
    assert len(msg) <= main_module._MAX_LOG_MSG + 64   # bound + truncation marker
    assert "[truncated" in msg


def test_no_double_interpolation_on_percent_payload(main_module):
    # record.args must be cleared after getMessage(): otherwise the formatter
    # would %-interpolate a second time against the substituted message and raise.
    f = main_module._FlattenFilter()
    rec = logging.LogRecord(
        "x", logging.INFO, __file__, 1, "%s", ("payload with %s and \n newline",), None,
    )
    f.filter(rec)
    out = logging.Formatter("%(message)s").format(rec)
    assert "payload with %s" in out           # literal, not re-interpolated
    assert "\n" not in out


def test_filter_attached_to_root_handlers(main_module):
    root = logging.getLogger()
    assert root.handlers, "root logger must have handlers (basicConfig)"
    for h in root.handlers:
        current = [x for x in h.filters if isinstance(x, main_module._FlattenFilter)]
        assert len(current) == 1              # attached, and not duplicated per import


def test_audit_channel_is_not_filtered(main_module):
    # The JSON audit channel must keep its byte-for-byte shape: it does not
    # propagate to root and its own handler carries no flatten filter.
    from app import audit as audit_mod

    audit_logger = logging.getLogger("app.audit")
    assert audit_logger.propagate is False

    # Assert over the handler app/audit.py owns, not every handler on the logger.
    # pytest's logging plugin attaches its capture handlers to non-propagating
    # loggers as well as to root, so the SAME handler object appears in both
    # lists; main.py's root-handler loop then filters it, and a naive sweep of
    # audit_logger.handlers reads that as "the audit channel is filtered".
    # Identity against root is what separates the injected handlers from ours.
    root_handler_ids = {id(h) for h in logging.getLogger().handlers}
    own = [h for h in audit_logger.handlers if id(h) not in root_handler_ids]
    assert own, "app/audit.py must configure its own handler"
    for h in own:
        assert not any(isinstance(x, main_module._FlattenFilter) for x in h.filters)

    # End-to-end: an audit record with an embedded newline is still exactly one
    # parseable JSON line (JSON-escaped, not flattened by this filter).
    records = []

    class _H(logging.Handler):
        def emit(self, record):
            records.append(record.getMessage())

    h = _H()
    audit_logger.addHandler(h)
    try:
        audit_mod.audit("ai_query", None, question="line1\nline2")
    finally:
        audit_logger.removeHandler(h)
    assert len(records) == 1
    assert "\n" not in records[0]
    json.loads(records[0])                    # still one parseable JSON object


@pytest.mark.parametrize("text,secret", [
    ("Authorization: Bearer abc.def.ghi-jkl", "abc.def.ghi-jkl"),
    ("connecting with password=hunter2 to db", "hunter2"),
    ("url https://user:s3cr3tpw@db.example/x", "s3cr3tpw"),
])
def test_credentials_are_masked_in_the_plain_stream(main_module, text, secret):
    f = main_module._FlattenFilter()
    rec = logging.LogRecord("app.grafana_poller", logging.INFO, __file__, 1, "%s", (text,), None)
    f.filter(rec)
    assert secret not in rec.getMessage()


def test_masking_stops_at_a_real_line_break(main_module):
    f = main_module._FlattenFilter()
    rec = logging.LogRecord("app.grafana_poller", logging.INFO, __file__, 1,
                            "Authorization: Bearer\nparallelism.default=4", None, None)
    f.filter(rec)
    assert rec.getMessage().endswith("\\nparallelism.default=4")


def test_root_handler_masks_a_logged_bearer_token(main_module, capsys):
    handler = logging.StreamHandler()
    handler.addFilter(main_module._FlattenFilter())
    log = logging.getLogger("app.test_masking")
    log.addHandler(handler)
    log.propagate = False
    try:
        log.warning("Authorization: Bearer abc.def.ghi")
    finally:
        log.removeHandler(handler)
    assert "abc.def.ghi" not in capsys.readouterr().err


def test_audit_records_are_left_untouched(main_module):
    f = main_module._FlattenFilter()
    rec = logging.LogRecord("app.audit", logging.INFO, __file__, 1,
                            '{"question":"Authorization: Bearer\\nx"}', None, None)
    f.filter(rec)
    assert rec.getMessage() == '{"question":"Authorization: Bearer\\nx"}'


def test_plain_lines_carry_the_correlation_id_in_utc(main_module):
    import time
    from app.audit import new_correlation_id
    root = logging.getLogger()
    handler = next(h for h in root.handlers
                   if any(isinstance(f, main_module._FlattenFilter) for f in h.filters))
    cid = new_correlation_id()
    rec = logging.LogRecord("app.x", logging.INFO, __file__, 1, "hello", None, None)
    for f in handler.filters:
        f.filter(rec)
    assert rec.correlation_id == cid
    fmt = logging.Formatter("%(asctime)sZ [cid=%(correlation_id)s]: %(message)s")
    fmt.converter = time.gmtime
    line = fmt.format(rec)
    assert f"[cid={cid}]" in line
    assert line.startswith(time.strftime("%Y-%m-%d %H", time.gmtime(rec.created)))


def test_traceback_is_credential_masked(main_module):
    f = main_module._FlattenFilter()
    try:
        raise RuntimeError("connect failed: password=hunter2")
    except RuntimeError:
        import sys
        exc_info = sys.exc_info()
    rec = logging.LogRecord("app.safe_errors", logging.ERROR, __file__, 1,
                            "job_status failed", None, exc_info)
    f.filter(rec)
    out = logging.Formatter("%(message)s").format(rec)
    assert "hunter2" not in out
    assert "Traceback" in out and "RuntimeError" in out
    assert "\n" in out                        # traceback keeps its line breaks


def test_client_error_traceback_is_masked_in_the_log_stream(main_module):
    import io
    from app.safe_errors import client_error

    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.addFilter(main_module._FlattenFilter())
    lg = logging.getLogger("app.safe_errors")
    lg.addHandler(handler)
    try:
        try:
            raise ValueError("bad url https://user:hunter2@db.example.com/x")
        except ValueError as e:
            client_error("db read", e)
    finally:
        lg.removeHandler(handler)
    assert "hunter2" not in stream.getvalue()
    assert "Traceback" in stream.getvalue()
