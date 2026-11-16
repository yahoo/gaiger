"""Static guard: every innerHTML assignment in the chat UI that interpolates a
value must route it through escapeHtml() or renderMarkdown() (which escapes
first), and the page must ship a Content-Security-Policy. Fails on any new raw
`${...}` reaching innerHTML, so a third unescaped sink cannot appear."""
import re
from pathlib import Path

UI_INDEX = Path(__file__).resolve().parent.parent / "app" / "ui" / "index.html"
_ASSIGN = re.compile(r"\.innerHTML\s*\+?=\s*(.+?);\s*(?://.*)?$", re.M)
_INTERP = re.compile(r"\$\{([^}]*)\}")
_SAFE_WRAPPERS = ("escapeHtml(", "renderMarkdown(")


def _sinks():
    src = UI_INDEX.read_text(encoding="utf-8")
    # Multi-line template literals: join continuation lines until the closing backtick.
    lines = src.splitlines()
    out = []
    for i, line in enumerate(lines, 1):
        if ".innerHTML" in line and "=" in line:
            buf = line
            j = i
            while buf.count("`") % 2 == 1 and j < len(lines):
                buf += "\n" + lines[j]
                j += 1
            out.append((i, buf))
    return out


def test_every_innerhtml_interpolation_is_escaped():
    offenders = []
    for lineno, stmt in _sinks():
        for m in _INTERP.finditer(stmt):
            expr = m.group(1).strip()
            if not any(expr.startswith(w) for w in _SAFE_WRAPPERS):
                offenders.append((lineno, expr))
    assert not offenders, f"raw interpolation into innerHTML: {offenders}"


def test_innerhtml_sinks_are_the_known_set():
    # Allowlist-based, per the ticket: adding a sink is a deliberate act.
    assert len(_sinks()) <= 5, [l for l, _ in _sinks()]


def test_csp_meta_present_and_strict_where_it_can_be():
    src = UI_INDEX.read_text(encoding="utf-8")
    m = re.search(r'<meta http-equiv="Content-Security-Policy"\s+content="([^"]+)"', src)
    assert m, "CSP meta missing from app/ui/index.html"
    # Parse into {directive: [source tokens]} and compare exact tokens, not substrings.
    policy = {}
    for part in m.group(1).split(";"):
        tokens = part.split()
        if tokens:
            policy[tokens[0]] = tokens[1:]
    assert policy["default-src"] == ["'self'"]
    assert policy["object-src"] == ["'none'"]
    assert policy["frame-ancestors"] == ["'none'"]
    assert policy["base-uri"] == ["'self'"]
    assert policy["style-src"] == ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"]
    assert policy["font-src"] == ["https://fonts.gstatic.com"]
    assert policy["connect-src"] == ["'self'"]
