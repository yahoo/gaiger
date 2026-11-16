"""Agent-side egress governance: create_github_pr argument validation, the
GitHub read-tool egress flag, outbound secret redaction at the
truncate_for_model chokepoint, and source-level invariants on
app/langgraph_agent.py that keep those properties enforced.

The behavior tests import app.egress_governance (langchain-free) so they run
in a bare environment; the invariants inspect the agent source as TEXT, so no
langgraph import is needed either."""

import ast
import json
import re
from pathlib import Path

import pytest

from app.egress_governance import (
    git_ref_allowed,
    github_tools_enabled,
    passthrough_for_edit,
    pr_branch_allowed,
    pr_path_allowed,
    repo_path_filter_allowed,
    truncate_for_model,
)

AGENT_SRC = (Path(__file__).resolve().parent.parent / "app" / "langgraph_agent.py").read_text(
    encoding="utf-8"
)


# ── branch validation (create_github_pr) ────────────────────────────────────────

@pytest.mark.parametrize("branch,base,expected", [
    ("ai-debugger/skew-celebrity-key", "main", True),
    ("ai-debugger/a1", "main", True),
    ("ai-debugger/fix_v1.2-x", "main", True),
    ("main", "main", False),                        # base branch itself
    ("ai-debugger/x", "ai-debugger/x", False),      # equals base branch
    ("fix/skew-celebrity-key", "main", False),      # outside the namespace
    ("ai-debugger/", "main", False),                # empty slug
    ("ai-debugger/Fix", "main", False),             # uppercase not allowed
    ("ai-debugger/-x", "main", False),              # must start alphanumeric
    ("ai-debugger/" + "a" * 41, "main", False),     # too long
    ("", "main", False),
])
def test_pr_branch_allowed(branch, base, expected):
    assert pr_branch_allowed(branch, base) is expected


# ── path validation — includes the plan review's bypass shapes ──────────────────

@pytest.mark.parametrize("path,expected", [
    ("src/main/java/Job.java", True),
    ("src/main/resources/app.conf", True),
    ("pom.xml", True),
    ("build.gradle", True),
    ("README.md", True),
    (".github/workflows/x.yml", False),
    ("./.github/workflows/x.yml", False),   # alias via '.' segment
    ("/etc/passwd", False),                 # absolute
    ("a/../.github/x", False),              # traversal
    ("..", False),
    ("a//b", False),                        # empty segment
    ("src/./x.java", False),                # non-canonical
    (".GITHUB/workflows/x.yml", False),     # case-insensitive
    ("k8s/x.yaml", False),
    ("apps/prod/k8s/rbac.yaml", False),     # protected DIRECTORY at any depth
    ("helm/values.yaml", False),
    ("modules/helm/values.yaml", False),    # nested helm/
    ("charts/app/values.yaml", False),
    ("deploy/main.tf", False),
    ("apps/prod/deploy/deployment.yaml", False),  # nested deploy/
    ("pkg/.github/workflows/x.yml", False),       # nested .github/
    (".circleci/config.yml", False),
    (".buildkite/pipeline.yml", False),
    (".gitlab-ci.yml", False),
    ("cloudbuild.yaml", False),
    ("azure-pipelines.yml", False),
    ("bitbucket-pipelines.yml", False),
    ("screwdriver.yaml", False),
    ("screwdriver.yml", False),             # .yml variant
    ("ci/screwdriver.yaml", False),         # protected segment anywhere
    ("Jenkinsfile", False),
    ("ci/Jenkinsfile", False),              # nested CI file
    ("Makefile", False),
    ("Dockerfile", False),
    ("docker/Dockerfile", False),           # nested Dockerfile
    ("dockerfile.dev", False),
    (".env", False),                        # secret material (read symmetry)
    ("config/.env.prod", False),
    ("certs/server.pem", False),
    ("src/main/resources/keystore.jks", False),
    ("id_rsa", False),
    ("a\\b", False),                        # backslash separator
    ("", False),
])
def test_pr_path_allowed(path, expected):
    assert pr_path_allowed(path) is expected


# ── model-supplied git refs (base_branch / ref) ─────────────────────────────────

@pytest.mark.parametrize("ref,expected", [
    ("main", True),
    ("release/2.0", True),
    ("deadbeefcafe", True),
    ("", False),
    ("-evil", False),                       # must start alphanumeric
    ("a..b", False),                        # no '..'
    ("refs/heads/x;rm -rf", False),         # charset
    ("a" * 120, False),                     # length bound
])
def test_git_ref_allowed(ref, expected):
    assert git_ref_allowed(ref) is expected


def test_pr_branch_allowed_rejects_bad_base_branch():
    assert pr_branch_allowed("ai-debugger/x", "a..b") is False


# ── GitHub read-tool egress flag ────────────────────────────────────────────────

@pytest.mark.parametrize("write_enabled,github_configured,expected", [
    (True, True, True),
    (True, False, False),
    (False, True, False),   # read tools never register without the write tool
    (False, False, False),
])
def test_github_tools_single_predicate(write_enabled, github_configured, expected):
    assert github_tools_enabled(write_enabled, github_configured) is expected


def test_passthrough_for_edit_does_not_redact_or_truncate():
    """read_github_file output is written back verbatim by create_github_pr, so
    it must not carry redaction placeholders or a size cut."""
    content = "kafka.sasl.password = ${KAFKA_PASSWORD}\nemail = ops@example.com\n" + ("x" * 5000)
    out = passthrough_for_edit({"success": True, "content": content, "sha": "abc"})
    assert "<REDACTED" not in out
    assert "[truncated]" not in out
    assert json.loads(out)["content"] == content


def test_passthrough_for_edit_refuses_oversize_instead_of_truncating():
    out = json.loads(passthrough_for_edit({"success": True, "content": "y" * 500}, limit=100))
    assert out["success"] is False
    assert "too large" in out["error"]


def test_read_github_file_shares_the_path_envelope():
    """read_github_file must apply the same path policy as create_github_pr —
    an injected instruction must not pull CI/deploy config into model context."""
    read_idx = AGENT_SRC.find("async def read_github_file")
    assert read_idx != -1
    body = AGENT_SRC[read_idx:AGENT_SRC.find("async def create_github_pr")]
    assert "pr_path_allowed(file_path)" in body
    assert "github_read_rejected" in body


def test_list_github_files_filters_denied_paths():
    """list_github_files must not enumerate even the NAMES of denied files —
    the returned listing is filtered through the same path envelope."""
    list_idx = AGENT_SRC.find("async def list_github_files")
    assert list_idx != -1
    body = AGENT_SRC[list_idx:AGENT_SRC.find("async def read_github_file")]
    # The predicate is handed to the client so it is applied BEFORE the size
    # cap — a post-cap filter under-reported count/truncated.
    assert "path_allowed=pr_path_allowed" in body
    assert "fit_listing_for_model(result)" in body
    assert "git_ref_allowed(ref)" in body


def test_github_tools_register_together_under_the_write_gate():
    """list_github_files, read_github_file and create_github_pr register in ONE
    statement under ONE predicate, inside the write_tools_enabled() branch."""
    reg = AGENT_SRC.find("tools.extend([list_github_files, read_github_file, create_github_pr])")
    assert reg != -1, "GitHub tools must register as one unit"
    gate = AGENT_SRC.find("if github_tools_enabled(write_enabled, github_configured):")
    # The write branch opens with the alert-flow gate on the
    # cluster-mutating tools; the GitHub predicate still sits inside it.
    write_gate = AGENT_SRC.find("if write_enabled:\n            write_tool_names = []")
    mutating = AGENT_SRC.find("tools.extend([update_flink_config, restart_flink_job, apply_remediation])")
    assert -1 < write_gate < mutating < gate < reg
    assert "tools.append(list_github_files)" not in AGENT_SRC
    assert "tools.append(read_github_file)" not in AGENT_SRC
    assert "tools.append(create_github_pr)" not in AGENT_SRC


def test_read_github_file_returns_via_passthrough_not_truncate():
    read_idx = AGENT_SRC.find("async def read_github_file")
    body = AGENT_SRC[read_idx:AGENT_SRC.find("async def create_github_pr")]
    assert "return _passthrough_for_edit(result)" in body
    assert "return _truncate(result)" not in body


# ── outbound redaction at the truncate_for_model chokepoint ─────────────────────

def test_truncate_redacts_secrets():
    out = truncate_for_model({
        "cfg": "password=hunter2",
        "url": "https://svc:s3cr3tpw@internal.host/db",
        "token": "xoxb-1234567890-abcdef",
    })
    assert "hunter2" not in out
    assert "s3cr3tpw" not in out
    assert "xoxb-1234567890-abcdef" not in out
    assert "<REDACTED" in out


def test_truncate_keeps_rpc_addresses_and_emails_for_the_model():
    """The model path masks credentials only: RPC addresses and emails are
    operational data (the audit sink still masks them)."""
    out = json.loads(truncate_for_model({
        "rpc": "akka.tcp://flink@flink-jobmanager.flink-ns.svc:6123/user/rpc/dispatcher",
        "owner": "ops-team@example.com",
        "cfg": "password=hunter2",
    }))
    assert out["rpc"] == "akka.tcp://flink@flink-jobmanager.flink-ns.svc:6123/user/rpc/dispatcher"
    assert out["owner"] == "ops-team@example.com"
    assert "hunter2" not in out["cfg"]


def test_truncate_still_bounds_size():
    out = truncate_for_model({"blob": "x" * 50000}, limit=1000)
    assert len(out) < 1100
    assert out.endswith("[truncated]")


def test_truncate_preserves_epoch_millis_and_stays_valid_json():
    """Regression: redaction must run per STRING LEAF, never over the serialized
    blob. _SECRET_PATTERNS' credit-card rule matches any 13-19 digit run, so
    masking the JSON text rewrote every Flink epoch-millis timestamp into
    <REDACTED:cc> — the agent could no longer compute checkpoint duration or
    recency, and the emitted document no longer parsed as JSON."""
    payload = {
        "latest": {
            "completed": {
                "id": 4212,
                "trigger_timestamp": 1788458246653,
                "latest_ack_timestamp": 1788458247891,
                "state_size": 1073741824,
            }
        }
    }
    out = truncate_for_model(payload)

    # 1. still parses — the mask token is not valid JSON in a value position
    parsed = json.loads(out)

    # 2. the numbers survive intact and are still NUMBERS, so the model can
    #    subtract them to get a checkpoint duration
    completed = parsed["latest"]["completed"]
    assert completed["trigger_timestamp"] == 1788458246653
    assert completed["latest_ack_timestamp"] == 1788458247891
    assert completed["state_size"] == 1073741824
    assert isinstance(completed["trigger_timestamp"], int)
    assert "REDACTED" not in out


def test_truncate_redacts_secrets_inside_nested_strings():
    """Per-leaf redaction must still reach secrets nested in lists/dicts — the
    fix must not trade correctness for coverage."""
    out = truncate_for_model({
        "pods": [
            {"name": "jm-0", "log": "connecting with password=hunter2", "restarts": 4},
            {"name": "tm-1", "log": "retry with Bearer abcdef0123456789", "restarts": 0},
        ],
        "epoch": 1788458246653,
    })
    parsed = json.loads(out)
    assert "hunter2" not in out
    assert "abcdef0123456789" not in out
    assert parsed["epoch"] == 1788458246653          # number untouched
    assert parsed["pods"][0]["restarts"] == 4        # nested number untouched
    assert "<REDACTED:secret>" in parsed["pods"][0]["log"]


def test_truncate_output_of_a_realistic_log_payload_parses():
    """A pod-log tool result carries long digit runs (offsets, byte counts, PIDs)
    in free text. Those may legitimately be masked inside the string, but the
    envelope must remain parseable JSON."""
    out = truncate_for_model({
        "lines": [
            "offset=1788458246653001 committed for partition 3",
            "GC pause 1234567890123456 ns",
        ],
        "count": 2,
    })
    parsed = json.loads(out)
    assert parsed["count"] == 2
    assert len(parsed["lines"]) == 2


# ── source-level invariants on the agent module ─────────────────────────────────

def test_send_to_slack_has_no_channel_parameter():
    m = re.search(r"async def send_to_slack\((.*?)\)", AGENT_SRC, re.S)
    assert m, "send_to_slack not found"
    assert "channel" not in m.group(1), \
        "send_to_slack must not expose a model-chosen destination"


# Names of module-level mappings whose VALUES are all literal constants, so a
# subscript of them is as static as a literal. Verified structurally by
# test_static_error_maps_really_are_constant below — this is not a free pass.
_STATIC_STRING_MAPS = {"SAFE_ERROR_MESSAGES"}


def _module_level_constant_maps(tree: ast.Module) -> dict:
    """Module-level `NAME = {...}` assignments whose keys and values are all
    ast.Constant."""
    found = {}
    for node in tree.body:
        if not isinstance(node, ast.Assign) or not isinstance(node.value, ast.Dict):
            continue
        all_const = all(
            isinstance(k, ast.Constant) for k in node.value.keys
        ) and all(isinstance(v, ast.Constant) for v in node.value.values)
        if not all_const:
            continue
        for target in node.targets:
            if isinstance(target, ast.Name):
                found[target.id] = node.value
    return found


def _is_static_value(node: ast.AST) -> bool:
    """A dict value is static iff it is a literal constant, or a subscript of a
    module-level all-constant mapping (SAFE_ERROR_MESSAGES[...] — the result can
    only ever be one of that map's literal strings, whatever the index is)."""
    if isinstance(node, ast.Constant):
        return True
    if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name):
        return node.value.id in _STATIC_STRING_MAPS
    return False


def test_static_error_maps_really_are_constant():
    """The AST invariant below trusts _STATIC_STRING_MAPS. That trust is only
    honest while those maps are genuinely literal — assert it, so a future edit
    that puts a dynamic value in SAFE_ERROR_MESSAGES fails here rather than
    silently widening the chokepoint invariant."""
    const_maps = _module_level_constant_maps(ast.parse(AGENT_SRC))
    for name in _STATIC_STRING_MAPS:
        assert name in const_maps, (
            f"{name} is no longer a module-level all-constant dict literal, so it "
            f"can no longer be treated as static by the json.dumps invariant"
        )


def test_tools_never_json_dumps_dynamic_data():
    """Every json.dumps in the agent module must take a dict literal whose VALUES
    are all static — anything dynamic must return via _truncate (size bound +
    secret redaction). This is what makes the outbound chokepoint non-bypassable
    by a future tool.

    A real AST walk, not a text match: the previous regex form only checked that
    the character after `json.dumps(` was `{`, so a future
    `json.dumps({"logs": pod_logs})` passed it while bypassing redaction
    entirely."""
    violations = []
    for node in ast.walk(ast.parse(AGENT_SRC)):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        is_json_dumps = (
            isinstance(func, ast.Attribute)
            and func.attr == "dumps"
            and isinstance(func.value, ast.Name)
            and func.value.id == "json"
        )
        if not is_json_dumps:
            continue
        arg = node.args[0] if node.args else None
        if not isinstance(arg, ast.Dict):
            violations.append(
                f"line {node.lineno}: json.dumps() argument is "
                f"{type(arg).__name__}, not a dict literal"
            )
            continue
        for key, value in zip(arg.keys, arg.values):
            if key is None:  # `**spread` inside the literal — contents unknowable
                violations.append(f"line {node.lineno}: dict literal uses ** unpacking")
            elif not _is_static_value(value):
                key_repr = key.value if isinstance(key, ast.Constant) else "<dynamic key>"
                violations.append(
                    f"line {node.lineno}: value for {key_repr!r} is "
                    f"{type(value).__name__}, not a static constant"
                )
    assert not violations, (
        "json.dumps site(s) bypass the _truncate egress chokepoint:\n  "
        + "\n  ".join(violations)
    )
    assert "_truncate(" in AGENT_SRC


def _dynamic_json_dumps_violations(source: str) -> list:
    """The same walk as the invariant above, factored out so it can be run
    against a synthetic source string in the negative control."""
    found = []
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if not (
            isinstance(func, ast.Attribute)
            and func.attr == "dumps"
            and isinstance(func.value, ast.Name)
            and func.value.id == "json"
        ):
            continue
        arg = node.args[0] if node.args else None
        if not isinstance(arg, ast.Dict):
            found.append(node.lineno)
            continue
        for key, value in zip(arg.keys, arg.values):
            if key is None or not _is_static_value(value):
                found.append(node.lineno)
    return found


@pytest.mark.parametrize("snippet,should_flag", [
    # The exact shape the old regex `json\.dumps\((?!\{)` let through: first
    # character IS '{', so it passed, while the VALUE bypasses redaction.
    ('return json.dumps({"logs": pod_logs})', True),
    ('return json.dumps({"error": f"bad {x}"})', True),
    ('return json.dumps({"files": [p for p in paths]})', True),
    ('return json.dumps({**base, "ok": True})', True),
    ('return json.dumps(result)', True),
    # Legitimately static forms that must NOT be flagged.
    ('return json.dumps({"error": "Tool execution failed."})', False),
    ('return json.dumps({"success": False, "error": SAFE_ERROR_MESSAGES["x"]})', False),
    ('return _truncate({"logs": pod_logs})', False),
])
def test_ast_invariant_actually_catches_dynamic_values(snippet, should_flag):
    """Negative control. The invariant is only worth having if it fails on the
    cases it claims to cover — the regex it replaced did not."""
    assert bool(_dynamic_json_dumps_violations(snippet)) is should_flag


# ── CWE-117: control characters in model-supplied repo paths (log forging) ──────

@pytest.mark.parametrize("path", [
    'src/a.java\n{"event":"forged"}',   # the reported forging shape
    "src/a.java\r\nfoo",
    "src/a.java\tb",
    "src/ a.java",                       # bare space
    "src/a.java ",                       # trailing space
    " src/a.java",
    "src/a\x00.java",                    # NUL
    "src/a\x1b[31m.java",                # ANSI escape
    "src/a b.java",                 # unicode line separator
    "src/a\x7f.java",                    # DEL
])
def test_repo_path_rejects_control_and_whitespace_characters(path):
    """A model-supplied path lands on the same stdout stream as the single-line
    JSON audit events, so an embedded newline can forge an audit-shaped line."""
    assert pr_path_allowed(path) is False


def test_repo_path_still_accepts_ordinary_source_paths():
    """The control-character rejection must not narrow the legitimate envelope."""
    for ok in ("src/main/java/com/x/Job.java", "pom.xml", "README.md", "a-b_c.1.txt"):
        assert pr_path_allowed(ok) is True


@pytest.mark.parametrize("value,expected", [
    (None, True),                        # no filter
    ("", True),
    ("src/main/java", True),
    ("src/main/java/", True),            # trailing slash tolerated on a prefix
    ('src\n{"event":"forged"}', False),  # log forging via path_filter
    ("src/main java", False),
    (".github", False),                  # protected surface
    ("k8s", False),
    ("../etc", False),
    ("/abs", False),
    (123, False),                        # non-string
])
def test_repo_path_filter_allowed(value, expected):
    """list_github_files' path_filter was entirely unvalidated and logged raw."""
    assert repo_path_filter_allowed(value) is expected


def test_github_read_tools_validate_before_logging():
    """CWE-117 ordering invariant: no model-controlled value may reach a logger
    call before it has been validated."""
    read_idx = AGENT_SRC.find("async def read_github_file")
    read_body = AGENT_SRC[read_idx:AGENT_SRC.find("async def create_github_pr")]
    validate_at = read_body.find("if not pr_path_allowed(file_path):")
    log_at = read_body.find('logger.info(\n                "read_github_file:')
    assert validate_at != -1 and log_at != -1
    assert validate_at < log_at, \
        "read_github_file logs the model-supplied path before validating it"

    list_idx = AGENT_SRC.find("async def list_github_files")
    list_body = AGENT_SRC[list_idx:read_idx]
    filter_validate_at = list_body.find("if not repo_path_filter_allowed(path_filter):")
    list_log_at = list_body.find('logger.info("list_github_files:')
    assert filter_validate_at != -1, "path_filter is not validated"
    assert filter_validate_at < list_log_at, \
        "list_github_files logs the model-supplied path_filter before validating it"


# ── single Slack sink ───────────────────────────────────────────────────────────

def test_no_second_ungoverned_slack_sink():
    """slack_client.py's module comment claims every Slack send passes through one
    sink. app/slack_client_webhook.py defined its own send_message posting to
    SLACK_WEBHOOK_URL with no channel allowlist and no mrkdwn escaping, which
    falsified that claim; it had zero importers and was removed."""
    app_dir = Path(__file__).resolve().parent.parent / "app"
    assert not (app_dir / "slack_client_webhook.py").exists(), \
        "the ungoverned webhook Slack sink is back"
    senders = [
        f.name for f in app_dir.glob("*.py")
        if "def send_message" in f.read_text(encoding="utf-8")
    ]
    assert senders == ["slack_client.py"], \
        f"more than one Slack send sink: {senders}"


# ── static prompt must not instruct unregistered tools ──────────────────────────

def test_static_prompt_does_not_unconditionally_instruct_github_read_tools():
    """ENABLE_GITHUB_READ_TOOLS defaults false (the deployment does not set it), so
    the read tools are usually NOT registered. The static prompt must not issue
    them as unconditional imperatives — the dynamic capabilities block was updated
    but the static prompt was not."""
    poller_src = (
        Path(__file__).resolve().parent.parent / "app" / "grafana_poller.py"
    ).read_text(encoding="utf-8")

    # The exact unconditional phrasings this fix removed. Each issued the read
    # tools as a flat imperative with no "if it is registered" guard.
    banned_in_agent = [
        "\u2192 first list_github_files to discover the exact path",
        "(also call this before any PR so you reason about the actual source",
        "never ask the operator for the repo name. If you don't know the exact "
        "file path, FIRST call `list_github_files`",
    ]
    banned_in_poller = [
        "(call read_github_file first to fetch the actual job source",
    ]
    for phrase in banned_in_agent:
        assert phrase not in AGENT_SRC, \
            f"unconditional instruction still in SYSTEM_PROMPT: {phrase!r}"
    for phrase in banned_in_poller:
        assert phrase not in poller_src, \
            f"unconditional instruction still in poller prompt: {phrase!r}"

    # Every mention of a gated tool must sit in a prompt that establishes the
    # tools are conditional, and states what to do when they are absent.
    for name, src in (("SYSTEM_PROMPT", AGENT_SRC), ("grafana_poller", poller_src)):
        assert "in your toolset" in src, f"{name} lacks the conditional framing"
        assert "NOT in your toolset" in src or "not, " in src, \
            f"{name} does not say what to do when the tools are absent"


def test_truncate_alias_is_the_governed_chokepoint():
    """_truncate is the OFFLOADED form of the redacting chokepoint
    (the redaction pass measured 178-881 ms on the event loop), and every call
    site awaits it — a bare `_truncate(` would return a coroutine to the model."""
    assert "truncate_for_model_offloaded as _truncate" in AGENT_SRC, \
        "_truncate must be the offloaded redacting chokepoint from app.egress_governance"
    bare = re.findall(r"(?<!await )(?<!as )\b_truncate\(", AGENT_SRC)
    assert not bare, f"{len(bare)} _truncate call(s) not awaited"
    assert AGENT_SRC.count("await _truncate(") >= 20


def test_offloaded_truncate_runs_off_the_event_loop():
    import asyncio
    import inspect
    from app import egress_governance as eg

    assert inspect.iscoroutinefunction(eg.truncate_for_model_offloaded)
    assert "asyncio.to_thread(truncate_for_model" in inspect.getsource(eg.truncate_for_model_offloaded)
    out = asyncio.new_event_loop().run_until_complete(
        eg.truncate_for_model_offloaded({"cfg": "password=hunter2", "n": 1788458246653})
    )
    parsed = json.loads(out)
    assert "hunter2" not in out and parsed["n"] == 1788458246653


# ── key-blind redaction ────────────────────────────────────────────

def test_truncate_masks_values_under_credential_named_keys():
    """`kafka.sasl.password: hunter2` has no secret-shaped VALUE, so the text
    patterns let it through; the key names it. Numeric ids / timestamps are
    untouched and the structure stays parseable."""
    out = json.loads(truncate_for_model({
        "kafka.sasl.password": "hunter2",
        "s3.secret-key": "wJalrXUtnFEMI/K7MDENG",
        "accessToken": "abc",
        "Authorization": "Basic Zm9vOmJhcg==",
        "security.ssl.keystore-password": "changeit",
        "secretName": "flink-kafka-creds",         # names a secret, does not carry one
        "tokenizer": "whitespace",
        "token_count": "12",
        "checkpoint.timeout": 600000,
        "1788458246653": "epoch-keyed entry",
    }))
    for k in ("kafka.sasl.password", "s3.secret-key", "accessToken", "Authorization",
              "security.ssl.keystore-password"):
        assert out[k] == "<REDACTED:secret>", k
    assert out["secretName"] == "flink-kafka-creds"
    assert out["tokenizer"] == "whitespace"
    assert out["token_count"] == "12"
    assert out["checkpoint.timeout"] == 600000
    assert out["1788458246653"] == "epoch-keyed entry"


@pytest.mark.parametrize("key,expected", [
    ("password", True), ("PASSWORD", True), ("kafka.sasl.password", True),
    ("db_passwd", True), ("api_key", True), ("apiKey", True), ("x-api-key", True),
    ("aws.access-key", True), ("private_key", True), ("refreshToken", True),
    ("credentials", True), ("passphrase", True),
    # round-2: auth + plurals
    ("auth", True), ("credential", True), ("secrets", True), ("tokens", True),
    ("passwords", True), ("api_keys", True), ("apiKeys", True), ("passwd", True),
    ("secretName", False), ("secretKeyRef", False), ("tokenFile", False),
    ("tokenizer", False), ("token_count", False), ("passwordEnabled", False),
    ("authType", False), ("auth.enabled", False), ("oauth", False),
    ("key", False), ("keys", False), ("parallelism.default", False),
    ("", False), (1788458246653, False), (None, False),
])
def test_is_sensitive_key(key, expected):
    from app.audit import is_sensitive_key
    assert is_sensitive_key(key) is expected


# ── round-2 review: `\b` boundary skipped underscore-joined key names ───────────

@pytest.mark.parametrize("text,value", [
    ("DB_PASSWORD=hunter2", "hunter2"),
    ("AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG", "wJalrXUtnFEMI/K7MDENG"),
    ("GITHUB_TOKEN=ghp_notlongenoughforthetokenshape", "ghp_notlongenoughforthetokenshape"),
    ("client_secret=s3cr3t-v4lue", "s3cr3t-v4lue"),
    ("export SPRING_DATASOURCE_PASSWORD=\"pg-pass\"; run", "pg-pass"),
    ("my.app.api_key: k-1234", "k-1234"),
    ("SECRET_KEY_BASE=abc", "abc"),
    ('{"password": "hunter2"}', "hunter2"),            # serialized JSON inside a log line
    ("kafka.sasl.password: hunter2", "hunter2"),        # dotted form still masked
])
def test_redact_credentials_masks_prefixed_and_suffixed_key_names(text, value):
    """`\\b(password|...)\\b` never matched `DB_PASSWORD=` because `_` is a word
    character. The reviewer reproduced all four env-style names passing through
    unchanged on the model and audit paths."""
    from app.audit import redact_credentials, redact_secrets
    for fn in (redact_credentials, redact_secrets):
        out = fn(text)
        assert value not in out, (fn.__name__, out)
        assert "<REDACTED:secret>" in out, (fn.__name__, out)


@pytest.mark.parametrize("text", [
    "passwordless_login=true",          # keyword is a prefix of a longer word, not a segment
    "token_count=12",                   # reference tail: counts a token, does not carry one
    "token_count: 5",
    "password_file=/run/secrets/db",    # points at a secret, is not one
    "secret_name=flink-kafka-creds",
    "tokenizer=whitespace",
    "authorization_type=basic",
    "2024-01-01 12:00:00 INFO checkpoint 42 completed",   # time/colon forms are not key=value secrets
    "parallelism.default=10",
])
def test_redact_credentials_leaves_benign_key_names_alone(text):
    from app.audit import redact_credentials, redact_secrets
    assert redact_credentials(text) == text
    assert redact_secrets(text) == text


def test_redact_credentials_prefilter_still_covers_prefixed_names():
    """Every string the new boundary can match must trip the trigger prefilter,
    otherwise the fast path would skip exactly the names this fixes."""
    from app.audit import _CREDENTIAL_TRIGGER_RE
    for s in ("DB_PASSWORD=x", "AWS_SECRET_ACCESS_KEY=x", "GITHUB_TOKEN=x", "client_secret=x"):
        assert _CREDENTIAL_TRIGGER_RE.search(s), s


# ── round-2 review: mask the whole subtree under a credential-named key ─────────

def test_truncate_masks_containers_and_scalars_under_credential_named_keys():
    """`{"credentials": {"db": "hunter2"}, "password": ["hunter2"]}` reached the
    model verbatim because only STRING values under a sensitive key were masked.
    The whole value is now replaced, whatever its type."""
    out = json.loads(truncate_for_model({
        "credentials": {"db": "hunter2", "nested": {"deeper": "hunter2"}},
        "password": ["hunter2", "hunter3"],
        "auth": {"user": "svc", "pass": "hunter2"},
        "secrets": [{"name": "kafka", "value": "hunter2"}],
        "tokens": ("t1", "t2"),
        "api_keys": {"primary": "k1"},
        "pin_token": 123456,
        "password_enabled": True,                  # reference tail: kept
        "secretName": "flink-kafka-creds",         # names a secret: kept
        "password_unset": None,
        "state.checkpoints.num-retained": 3,
        "jobs": [{"id": "abc", "kafka.sasl.password": "hunter2"}],
    }))
    for k in ("credentials", "password", "auth", "secrets", "tokens", "api_keys", "pin_token"):
        assert out[k] == "<REDACTED:secret>", k
    assert out["password_enabled"] is True
    assert out["secretName"] == "flink-kafka-creds"
    assert out["password_unset"] is None                   # nothing to leak; stays visible as unset
    assert out["state.checkpoints.num-retained"] == 3
    assert out["jobs"][0]["id"] == "abc"
    assert out["jobs"][0]["kafka.sasl.password"] == "<REDACTED:secret>"
    assert "hunter" not in json.dumps(out)


def test_mask_whole_value_keeps_unset_credentials_visible():
    """None / "" under a credential key have nothing to leak; keeping them shows
    the field was unset (useful when diagnosing a missing-credential failure)."""
    from app.audit import mask_whole_value
    assert mask_whole_value("password", None) is False
    assert mask_whole_value("password", "") is False
    assert mask_whole_value("password", 0) is True
    assert mask_whole_value("password", False) is True
    assert mask_whole_value("password", []) is True
    assert mask_whole_value("password", {}) is True
    assert mask_whole_value("parallelism", "10") is False
    out = json.loads(truncate_for_model({"password": None, "token": ""}))
    assert out == {"password": None, "token": ""}


def test_redact_credentials_prefilter_is_transparent():
    """The trigger prefilter only skips work; it must never change a result."""
    from app.audit import _SECRET_ONLY_COUNT, _SECRET_PATTERNS, redact_credentials

    def _slow(text):
        for pattern, repl in _SECRET_PATTERNS[:_SECRET_ONLY_COUNT]:
            text = pattern.sub(repl, text)
        return text

    samples = [
        "plain operational text 1788458246653 flink@jm.svc",
        "password=hunter2", "PASSWORD: x", "https://u:p@h/", "Bearer abcdefgh12345678",
        "AKIAABCDEFGHIJKLMNOP", "ghp_" + "a" * 36, "xoxb-12345678-abc",
        "eyJ" + "a" * 12 + "." + "b" * 12 + "." + "c" * 10, "sk-" + "z" * 20,
        "token: t0k3n", "api-key=k", "apikey=k", "Authorization: Basic x",
    ]
    for s in samples:
        assert redact_credentials(s) == _slow(s), s


# ── review: passthrough_for_edit measured the wrong thing ───────────────────────

def test_passthrough_measures_content_chars_not_escaped_envelope():
    """A 120k-char non-ASCII file serialized (ensure_ascii) to ~480k chars and
    was refused at '480135 chars'. The bound is on the file's own characters."""
    content = "é" * 120_000
    out = passthrough_for_edit({"success": True, "content": content, "sha": "abc"})
    parsed = json.loads(out)
    assert parsed["success"] is True
    assert parsed["content"] == content
    assert len(out) < 130_000                   # non-ASCII kept as-is, not \\u-escaped


def test_passthrough_refuses_on_content_chars():
    out = json.loads(passthrough_for_edit({"success": True, "content": "y" * 101}, limit=100))
    assert out["success"] is False and "101 chars" in out["error"]


def test_passthrough_routes_error_envelopes_through_redaction():
    """A GitHub error message can echo a token; error dicts are not the edit
    payload and must go through the chokepoint like every other tool result."""
    out = passthrough_for_edit({
        "success": False,
        "error": "GitHub API error (401): bad token ghp_" + "a" * 36 + " password=hunter2",
    })
    assert "hunter2" not in out and "ghp_" + "a" * 36 not in out
    assert "<REDACTED" in out
    assert json.loads(out)["success"] is False


# ── listing fit ─────────────────────────────────────────────────────

def test_fit_listing_drops_whole_entries_and_recomputes_count_and_truncated():
    from app.egress_governance import fit_listing_for_model
    files = [f"src/main/java/com/example/flink/pipeline/stage{i:03d}/SomeLongOperatorName{i:03d}.java"
             for i in range(500)]
    result = {"success": True, "repo": "o/r", "ref": "main", "path_filter": None,
              "count": 500, "truncated": False, "files": files}
    assert len(json.dumps(result)) > 30000       # the reproduced shape: 500 paths > 30k
    fitted = fit_listing_for_model(result, limit=30000)
    out = truncate_for_model(fitted)
    assert not out.endswith("[truncated]")       # never byte-cut afterwards
    parsed = json.loads(out)                     # whole document parses
    assert parsed["truncated"] is True
    assert parsed["count"] == len(parsed["files"]) < 500
    assert parsed["files"] == files[:parsed["count"]]
    assert result["files"] == files and result["count"] == 500   # input not mutated


def test_fit_listing_is_identity_when_it_fits():
    from app.egress_governance import fit_listing_for_model
    result = {"success": True, "count": 2, "truncated": False, "files": ["a.java", "b.java"]}
    assert fit_listing_for_model(result) == result
    assert fit_listing_for_model({"success": False, "error": "x"}) == {"success": False, "error": "x"}


def test_fit_listing_preserves_upstream_truncated_flag():
    from app.egress_governance import fit_listing_for_model
    fitted = fit_listing_for_model({"success": True, "count": 1, "truncated": True, "files": ["a"]})
    assert fitted["truncated"] is True


# ── denylist gaps and credential material on the read path ─────────

@pytest.mark.parametrize("path", [
    ".netrc", "home/.netrc", "_netrc", ".npmrc", "packages/x/.npmrc", ".pypirc",
    ".git-credentials", ".pgpass", ".htpasswd", ".boto", ".s3cfg", ".dockercfg",
    "certs/apns.p8", "keys/release.gpg", "keys/release.asc", "putty/host.ppk",
    "terraform/main.tf", "infra/terraform/vars.tfvars", "modules/vpc/main.tf",
    "env/prod.tfvars", "state/terraform.tfstate", ".terraform/plugins/x",
    "id_ecdsa", "id_dsa",
])
def test_denylist_covers_review_44_shapes(path):
    assert pr_path_allowed(path) is False


def test_denylist_additions_keep_source_paths_open():
    for ok in ("src/main/java/Tf.java", "docs/terraforming.md", "src/gpg/Sign.java",
               "config/application.properties"):
        assert pr_path_allowed(ok) is True, ok


@pytest.mark.parametrize("text,expected", [
    ("-----BEGIN RSA PRIVATE KEY-----\nMIIE...", True),
    ("-----BEGIN PRIVATE KEY-----", True),
    ("-----BEGIN OPENSSH PRIVATE KEY-----", True),
    ("aws.key=AKIAABCDEFGHIJKLMNOP", True),
    ("token = \"ghp_" + "a" * 36 + "\"", True),
    ("slack: xoxb-12345678-abcdef", True),
    ("jwt = eyJ" + "a" * 12 + "." + "b" * 12 + "." + "c" * 10, True),
    ('String pw = config.get("password");', False),   # ordinary source must stay readable
    ("password = ${KAFKA_PASSWORD}", False),
    ("-----BEGIN CERTIFICATE-----", False),           # public material
    ("", False),
])
def test_contains_hard_credential(text, expected):
    from app.egress_governance import contains_hard_credential
    assert contains_hard_credential(text) is expected


def test_read_github_file_refuses_credential_material_before_passthrough():
    read_idx = AGENT_SRC.find("async def read_github_file")
    body = AGENT_SRC[read_idx:AGENT_SRC.find("async def create_github_pr")]
    check = body.find("contains_hard_credential(")
    passthrough = body.find("return _passthrough_for_edit(result)")
    assert -1 < check < passthrough
    assert 'reason="credential_material"' in body


# ── round-3 review item 1: HTTP auth scheme values ──────────────────────────────

_BEARER = "opaque0123456789abcdef"
_BASIC = "ZGVtbzpzM2NyM3Q="


@pytest.mark.parametrize("text,token", [
    (f"Authorization: Bearer {_BEARER}", _BEARER),           # header form
    (f"authorization=Bearer {_BEARER}", _BEARER),            # env / properties form
    (json.dumps({"Authorization": f"Bearer {_BEARER}"}), _BEARER),   # serialized JSON form
    (f"Authorization: Basic {_BASIC}", _BASIC),              # Basic scheme
    (f"Proxy-Authorization: Bearer {_BEARER}", _BEARER),
    (f"-H 'Authorization: Basic {_BASIC}'", _BASIC),         # pasted curl fragment
    (f"Basic {_BASIC}", _BASIC),                             # scheme + credential, no header name
    ("Bearer " + "x" * 40, "x" * 40),
])
def test_auth_scheme_values_are_masked_whole(text, token):
    """The key=value rule ran first and its value stopped at whitespace, so
    `Authorization: Bearer <token>` became `Authorization: <REDACTED:secret>
    <token>` — the scheme word was masked and the token itself survived, on the
    model path and the audit path alike (reviewer reproduced all four shapes)."""
    from app.audit import redact_credentials, redact_secrets
    for fn in (redact_credentials, redact_secrets):
        out = fn(text)
        assert token not in out, (fn.__name__, out)
        assert "<REDACTED:" in out, (fn.__name__, out)
    # and through the model-bound chokepoint as a leaf
    out = truncate_for_model({"headers": text})
    assert token not in out


def test_auth_scheme_prose_is_not_rewritten():
    """The standalone Basic rule must not eat ordinary log prose."""
    from app.audit import redact_credentials
    for text in ("Basic Authentication failed for user svc",
                 "basic auth is enabled",
                 "Bearer token expired"):
        assert redact_credentials(text) == text, text


# ── round-4 review: single-quoted values, -D properties, jaas, newline scheme ────

_ROUND4_SINGLE_QUOTED = [
    # Kafka JAAS string (the reviewer's reproduction on every path)
    "PlainLoginModule required username='alice' password='hunter2';",
    "export DB_PASSWORD='hunter2'",          # shell export
    "-Dpassword='hunter2'",                  # JVM system property
    "-Dpassword=hunter2",                    # ... was failing unquoted too: `D` defeated the key boundary
    '-Dkafka.sasl.password="hunter2"',
    "{'password': 'hunter2', 'user': 'alice'}",   # Python repr of a dict
    "sasl.jaas.config=org.apache.kafka.common.security.plain.PlainLoginModule "
    "required username='alice' password='hunter2';",
]


@pytest.mark.parametrize("text", _ROUND4_SINGLE_QUOTED)
def test_single_quoted_and_dash_d_values_are_masked(text):
    """Round-4 review: the key=value rule accepted only `"` as the quote and
    the value class excludes `'`, so a single-quoted value never matched;
    `-Dpassword=...` never matched because `D` is alphanumeric. Both paths."""
    from app.audit import redact_credentials, redact_secrets
    for fn in (redact_credentials, redact_secrets):
        out = fn(text)
        assert "hunter2" not in out, (fn.__name__, out)
        assert "<REDACTED:secret>" in out, (fn.__name__, out)
    out = truncate_for_model({"cmd": text})       # model-bound chokepoint, as a leaf
    assert "hunter2" not in out
    if "alice" in text:
        assert "alice" in out                     # only the credential is masked, not the username


def test_single_quote_fix_preserves_surrounding_syntax():
    """The quotes and the JAAS terminator survive, so the masked text still
    reads as what it was (and the repr / shell forms stay parseable)."""
    from app.audit import redact_credentials
    assert redact_credentials("PlainLoginModule required username='alice' password='hunter2';") == \
        "PlainLoginModule required username='alice' password='<REDACTED:secret>';"
    assert redact_credentials("export DB_PASSWORD='hunter2'") == "export DB_PASSWORD='<REDACTED:secret>'"
    assert redact_credentials("-Dpassword='hunter2'") == "-Dpassword='<REDACTED:secret>'"
    assert redact_credentials("{'password': 'hunter2'}") == "{'password': '<REDACTED:secret>'}"


@pytest.mark.parametrize("prose", [
    "it's a password' reset",                # apostrophes around a keyword, no separator
    "the token's value is cached",
    "reset your password' and retry",
    "password_file=/run/x token_count=12 passwordless_login=true",   # reference tails, still open
])
def test_single_quote_fix_does_not_mangle_prose(prose):
    from app.audit import redact_credentials, redact_secrets
    assert redact_credentials(prose) == prose
    assert redact_secrets(prose) == prose


def test_jaas_is_a_sensitive_key():
    """`sasl.jaas.config` carries username AND password inline; the key-based
    walkers mask its whole value, and the text rule knows the keyword."""
    from app.audit import is_sensitive_key, redact_credentials
    assert is_sensitive_key("sasl.jaas.config") is True
    assert is_sensitive_key("jaasConfig") is True
    assert is_sensitive_key("jaas_config_file") is False       # a path reference, not the credential
    leaf = truncate_for_model({"kafka": {"sasl.jaas.config": "PlainLoginModule required username='a' password='hunter2';"}})
    assert "hunter2" not in leaf and "PlainLoginModule" not in leaf
    assert "PlainLoginModule" not in redact_credentials("jaas=org.apache.PlainLoginModule")


@pytest.mark.parametrize("text,next_line", [
    ("Authorization: Bearer\nnext_key=value", "next_key=value"),
    ("authorization=Basic\nparallelism.default=4", "parallelism.default=4"),
    ("Bearer\nabcdefghijklmnop", "abcdefghijklmnop"),                # standalone bearer rule
    ("Basic\nZGVtbzpzM2NyM3Q=", "ZGVtbzpzM2NyM3Q="),                # standalone basic rule
])
def test_auth_scheme_does_not_consume_the_next_line(text, next_line):
    """Round-4 minor: `(?:bearer|basic)\\s+` crossed a newline, so a bare
    scheme word at end of line swallowed the first token of the next line.
    The separator is `[ \\t]+` now, on the key=value rule and the standalone
    scheme rules alike."""
    from app.audit import redact_credentials, redact_secrets
    for fn in (redact_credentials, redact_secrets):
        out = fn(text)
        assert next_line in out, (fn.__name__, out)
        assert out.endswith("\n" + next_line), (fn.__name__, out)


# ── round-3 review item 2: the key=value prefix was quadratic ───────────────────

def _separator_dense(chars: int) -> str:
    # separator-dense text with no credential keyword; "://" passes the prefilter
    return ("ab_" * (chars // 3)) + " http://x"


@pytest.mark.parametrize("chars", [9_000, 18_000, 36_000])
def test_redact_credentials_is_linear_on_separator_dense_text(chars):
    """Reviewer's measurements on 4ff914e: 9 KB 554 ms, 18 KB 2.3 s, 36 KB
    8.9 s per leaf (the model path had no length cap). The prefix / suffix
    segment repeats are now bounded; the whole 36 KB leaf must scrub in well
    under 100 ms."""
    import time
    from app.audit import redact_credentials
    text = _separator_dense(chars)
    start = time.perf_counter()
    redact_credentials(text)
    elapsed_ms = (time.perf_counter() - start) * 1000
    assert elapsed_ms < 100, f"{chars} chars took {elapsed_ms:.0f} ms"


def test_truncate_for_model_bounds_cost_on_oversize_leaf():
    """A single 400 KB log leaf is capped to the model-bound limit BEFORE the
    regex passes run, so cost is bounded by the limit, not by the leaf."""
    import time
    from app.egress_governance import _LEAF_CUT_MARKER
    payload = {"log": _separator_dense(400_000), "n": 1}
    start = time.perf_counter()
    out = truncate_for_model(payload, limit=30_000)
    elapsed_ms = (time.perf_counter() - start) * 1000
    assert elapsed_ms < 200, f"{elapsed_ms:.0f} ms"
    assert out.endswith("\n... [truncated]")
    assert len(out) <= 30_000 + len("\n... [truncated]")
    # a leaf that fits is untouched by the cap
    small = json.loads(truncate_for_model({"log": "x" * 100}, limit=30_000))
    assert small == {"log": "x" * 100}
    assert _LEAF_CUT_MARKER not in json.dumps(small)


def test_bounded_prefix_keeps_deep_key_names_masked():
    """Bounding the prefix to 8 segments loses nothing: the match may start at
    any segment boundary, so a longer key is still caught from a later one."""
    from app.audit import redact_credentials
    deep = "_".join(f"s{i}" for i in range(14)) + "_PASSWORD=hunter2"
    assert "hunter2" not in redact_credentials(deep)
    dotted = "spring.datasource.hikari.replica.primary.password=hunter2"
    assert "hunter2" not in redact_credentials(dotted)


# ── round-3 minor: depth-guard fallback must not stringify the structure ───────

def test_depth_guard_returns_placeholder_not_flattened_text():
    """`str(value)` at the depth guard flattened keys into text, and key-based
    masking does not apply to text, so `{"password": "hunter2"}` 30 levels
    down leaked through the fallback."""
    from app.egress_governance import _DEPTH_EXCEEDED, _MAX_REDACT_DEPTH
    inner = {"password": "hunter2", "kafka.sasl.password": "hunter3"}
    value = inner
    for _ in range(_MAX_REDACT_DEPTH + 5):
        value = {"n": value}
    out = truncate_for_model(value)
    assert "hunter2" not in out and "hunter3" not in out
    assert _DEPTH_EXCEEDED in out


# ── round-3 minor: denylist over-matched source ─────────────────────────────────

@pytest.mark.parametrize("path", [
    "src/main/java/com/example/flink/deploy/JobDeployer.java",   # `deploy` as a Java package
    "src/main/scala/com/example/charts/Renderer.scala",          # `charts` as a package
    "src/main/java/com/example/docker/DockerfileParser.java",    # name begins with Dockerfile
    "src/main/kotlin/k8s/Client.kt",
    "cmd/deploy/main.go",
    "pkg/terraform/parser.go",
    "src/main/resources/i18n/messages.key",                    # .key that is not key material
    "src/keys/KeyGroupRange.java",
])
def test_denylist_keeps_source_under_generic_infra_names_open(path):
    assert pr_path_allowed(path) is True, path


@pytest.mark.parametrize("path", [
    "deploy/deployment.yaml", "apps/prod/deploy/deployment.yaml",
    "deploy/release.py", "deploy/run.sh",                       # scripts under deploy/ stay refused
    "charts/app/values.yaml", "charts/app/templates/_helpers.tpl",
    "helm/values.yaml", "k8s/rbac.yaml", "terraform/main.tf", "terraform/README.md",
    "Dockerfile", "docker/Dockerfile", "Dockerfile.dev", "build/app.dockerfile",
    ".github/workflows/x.yml", ".github/CODEOWNERS", "pkg/.github/x.java",   # dot-CI dirs: any leaf
    "certs/server.key", "config/tls/tls.key", "pki/ca.key", "secrets/app.key",
    ".ssh/id_rsa", ".ssh/config",
])
def test_denylist_still_refuses_intended_shapes(path):
    assert pr_path_allowed(path) is False, path


@pytest.mark.parametrize("text", [
    "-----BEGIN PGP PRIVATE KEY BLOCK-----\nlQ...",
    "PuTTY-User-Key-File-3: ssh-ed25519",
    "-----BEGIN EC PRIVATE KEY-----",
])
def test_key_material_content_is_refused_on_read(text):
    """A `.key` file is now refused by CONTENT (contains_hard_credential) rather
    than by extension, so the content rule must cover the key-block formats."""
    from app.egress_governance import contains_hard_credential
    assert contains_hard_credential(text) is True
