"""DEBUG_FLINK_CONNECTION.sh shell-hygiene regressions.

The script is a developer-workstation artefact (it does not ship in the image:
the Dockerfile copies only requirements files and app/), but it must meet the
the repo's shell standard: strict mode, quoted
expansions, a written justification for every ``curl -k``, and no stale
pod-instance / container-name literals. Two failure modes are pinned here:

* Silent failure: without ``set -euo pipefail`` every kubectl call could fail
  (both the hardcoded pod name and the container name were stale) while the
  script still printed all five section headings and exited 0 -- misleading an
  incident responder with output indistinguishable from a clean result.
* Latent argument injection (CWE-88): the fourteen unquoted ``$NAMESPACE`` /
  ``$POD_NAME`` expansions were safe only while both stayed hardcoded literals
  (which is also why ShellCheck was silent). Now that the script is
  parameterised, quoting is what keeps a whitespace-bearing value ONE kubectl
  argument instead of extra flags/words.

Static text assertions plus behavioural runs against a fake ``kubectl`` shim
on PATH: no cluster, no docker, no network.
"""

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = REPO_ROOT / "DEBUG_FLINK_CONNECTION.sh"
CONTENT = SCRIPT.read_text()
README = (REPO_ROOT / "README.md").read_text()
# Any FlinkDeployment name works for the shim; the script has NO default.
DEP = "some-flink-deployment"
# The pod name the shims resolve to; any value works, the script has no default.
SHIM_POD = "resolved-jm-pod-7c9f-0"
# A value that must never reach the terminal (stdout or the DEBUG=1 trace).
SENTINEL = "s3ntinel-hunter2-do-not-print"

BASH = shutil.which("bash")
needs_bash = pytest.mark.skipif(BASH is None, reason="bash not available")

# shellcheck: the system binary, or the one `pip install shellcheck-py` drops
# next to the running interpreter. Skip-safe when neither is present.
SHELLCHECK = shutil.which("shellcheck") or shutil.which(
    "shellcheck", path=str(Path(sys.executable).parent)
)
needs_shellcheck = pytest.mark.skipif(
    SHELLCHECK is None, reason="shellcheck not available"
)

HEADINGS = [
    "=== Checking AI Debugger Environment ===",
    "=== Checking if Flink container is running ===",
    "=== Testing connection from sidecar to Flink ===",
    "=== Checking Flink REST API ===",
    "=== Checking AI Debugger logs for errors ===",
]


def _without_comments(content):
    """Drop comment lines so rationale comments naming a banned literal don't
    false-positive (e.g. the comment explaining the WRONG container name)."""
    return "\n".join(
        l for l in content.splitlines() if not l.lstrip().startswith("#")
    )


# ---------------------------------------------------------------------------
# Static: the repo's shell standard
# ---------------------------------------------------------------------------

def test_shebang_and_strict_mode():
    lines = CONTENT.splitlines()
    assert lines[0] == "#!/usr/bin/env bash", "match the repo's shell standard shebang"
    assert CONTENT.count("set -euo pipefail") == 1, (
        "exactly one `set -euo pipefail` (the ticket's acceptance check)"
    )
    strict_line = next(
        i for i, l in enumerate(lines) if "set -euo pipefail" in l
    )
    first_kubectl_line = next(
        i
        for i, l in enumerate(lines)
        if "kubectl" in l and not l.lstrip().startswith("#")
    )
    assert strict_line < first_kubectl_line, (
        "strict mode must be enabled before the first kubectl call"
    )


def test_no_bare_unbraced_expansions():
    """Every use of the script's variables must be the braced `${VAR}` form
    (the quoted-ness itself is proven behaviourally below)."""
    code = _without_comments(CONTENT)
    bare = re.findall(r"\$(?:NAMESPACE|POD_NAME|CONTAINER|DEPLOYMENT)\b", code)
    assert not bare, f"bare unbraced expansions reintroduced: {bare}"


def test_stale_pod_instance_literal_removed():
    # A ReplicaSet-style pod instance name (<name>-<hash>-<suffix>) hardcoded
    # anywhere in the script would go stale on the next reschedule.
    assert not re.search(r"\b[a-z0-9-]+-[0-9a-f]{8,10}-[a-z0-9]{5}\b", CONTENT), (
        "a hardcoded pod INSTANCE goes stale on the next reschedule; resolve by "
        "label selector instead"
    )


def test_container_and_deployment_names_match_manifest():
    code = _without_comments(CONTENT)
    assert "flink-ai-debugger-sidecar" not in code, (
        "the manifest defines no container named flink-ai-debugger-sidecar; "
        "every kubectl exec using it fails"
    )
    assert 'CONTAINER="ai-debugger-sidecar"' in CONTENT
    # No default FlinkDeployment: positional, then env, then fail closed.
    assert 'DEPLOYMENT="${1:-${FLINK_DEPLOYMENT_NAME:-}}"' in CONTENT


def test_env_name_is_the_sidecars_own_variable():
    """The sidecar reads FLINK_DEPLOYMENT_NAME (app/kubernetes_client.py); the
    script accepts exactly that spelling so a sidecar env block can be sourced
    as-is, and no second spelling exists anywhere in the script or README."""
    for text, where in ((CONTENT, "script"), (README, "README")):
        assert "FLINK_DEPLOYMENT_NAME" in text, where
        assert not re.search(r"FLINK_DEPLOYMENT\b(?!_NAME)", text), (
            f"{where}: a second spelling of the deployment env var crept in"
        )


def test_no_reference_to_a_committed_manifest():
    """The script inspects a live FlinkDeployment, not a committed example
    manifest, so it must not point operators at any k8s/ file or 'test
    fixture'."""
    assert "k8s/" not in CONTENT
    assert ".yaml" not in CONTENT and ".yml" not in CONTENT
    assert "test fixture" not in CONTENT


def test_curl_k_sites_are_justified_in_writing():
    code_lines = [
        l for l in _without_comments(CONTENT).splitlines()
        if "curl" in l and re.search(r"\s-k\s", l)
    ]
    assert len(code_lines) == 2, (
        f"expected exactly the 2 known in-pod `curl -k` sites, found "
        f"{len(code_lines)} -- any new -k site needs its own written justification"
    )
    # The required content of the justification (ticket validation items).
    assert "DO NOT copy -k" in CONTENT
    assert "localhost:8081" in CONTENT
    assert "security.ssl.rest.enabled" in CONTENT
    assert "service identity" in CONTENT


def test_every_curl_probe_is_time_bounded():
    """Each in-pod curl carries --connect-timeout 5 --max-time 20 (via the one
    CURL_TIMEOUTS array), so a JM that accepts TCP and hangs cannot hang the
    diagnosis; proven at the argv level in the behavioural test below."""
    assert 'CURL_TIMEOUTS=(--connect-timeout 5 --max-time 20)' in CONTENT
    curl_lines = [
        l for l in _without_comments(CONTENT).splitlines()
        if re.search(r"\bcurl\s", l)
    ]
    assert len(curl_lines) == 3, curl_lines
    for line in curl_lines:
        assert '"${CURL_TIMEOUTS[@]}"' in line, f"curl without timeouts: {line!r}"


def test_rest_probe_does_not_pipe_into_head():
    """`... | head -20 || echo` made head's early close fail the pipeline under
    pipefail on a >20-line response (false 'probe failed'); the response is
    captured first and truncated afterwards."""
    code = _without_comments(CONTENT)
    assert not re.search(r"\|\s*head\b", code), "curl piped into head reintroduced"
    assert 'head -20 <<< "${OVERVIEW}"' in CONTENT


def test_env_and_log_captures_run_untraced():
    """Static half of the DEBUG=1 secret-leak fix: both sensitive captures sit
    between trace_off and trace_on (behavioural proof below with a sentinel)."""
    lines = [l for l in _without_comments(CONTENT).splitlines() if l.strip()]
    for var in ("ENV_OUT=", "LOG_OUT="):
        idx = next(i for i, l in enumerate(lines) if l.startswith(var))
        before = [l.strip() for l in lines[:idx]]
        after = [l.strip() for l in lines[idx:]]
        assert before[-1] == "trace_off", f"{var} is not immediately preceded by trace_off"
        assert "trace_on" in after, f"{var} capture is never followed by trace_on"
        # The redaction sed covers the credential-looking names.
        assert "PASSWORD|SECRET|TOKEN|KEY|CREDENTIAL" in CONTENT


def test_curl_k_is_scoped_to_the_in_pod_loopback_only():
    """The written justification holds only for the pod's own loopback: every
    `-k` must sit on a line whose URL is https://localhost:8081..., inside a
    `kubectl exec`-continued command (never a curl run from the workstation)."""
    lines = _without_comments(CONTENT).splitlines()
    for i, line in enumerate(lines):
        if "curl" not in line or not re.search(r"\s-k\s", line):
            continue
        urls = re.findall(r"https?://\S+", line)
        assert urls, f"-k line has no URL to scope it: {line!r}"
        assert all(u.startswith("https://localhost:8081") for u in urls), (
            f"curl -k must only target the in-pod loopback: {line!r}"
        )
        prev = lines[i - 1]
        assert "kubectl exec" in prev and prev.rstrip().endswith("\\"), (
            f"curl -k must be the argv of a kubectl exec, not a local curl: {prev!r}"
        )


def test_no_unbraced_positional_or_test_brackets():
    """The repo's shell standard: `[[ ]]` not `[ ]`, no bare `$1`/`$2`
    outside the `${N:-default}` assignments, no `read` without -r."""
    code = _without_comments(CONTENT)
    assert not re.search(r"(^|\s)\[\s", code, re.M), "use [[ ]] not [ ]"
    # Single-quoted strings are not shell expansions (the awk program's $1/$2).
    shell_only = re.sub(r"'[^']*'", "''", code)
    assert not re.search(r"\$[12](?![0-9])", shell_only), "positional used unbraced"
    assert not re.search(r"\bread\b(?!.*\s-r\b)", code), "read without -r"


@needs_shellcheck
def test_shellcheck_style_clean():
    proc = subprocess.run(
        [SHELLCHECK, "-S", "style", str(SCRIPT)],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


# ---------------------------------------------------------------------------
# Behavioural: fake kubectl shim on PATH
# ---------------------------------------------------------------------------

FAKE_KUBECTL_OK = """#!/usr/bin/env bash
{
  printf 'ARGV_BEGIN\\n'
  for a in "$@"; do printf '%s\\n' "$a"; done
  printf 'ARGV_END\\n'
} >> "${KUBECTL_LOG}"
cmd="${1:-}"
if [[ "${cmd}" == "exec" ]]; then
  after=0
  target=""
  for a in "$@"; do
    if [[ "${after}" -eq 1 ]]; then target="$a"; break; fi
    if [[ "$a" == "--" ]]; then after=1; fi
  done
  if [[ "${target}" == "env" ]]; then
    # A realistic sidecar environment: the one FLINK var the section is for,
    # a credential-looking FLINK/SSL var, and a non-FLINK secret. Only the
    # first may print verbatim; the sentinel must reach neither stdout nor
    # the DEBUG=1 trace.
    echo "FLINK_JM_ENDPOINT=http://localhost:8081"
    echo "FLINK_SSL_KEYSTORE_PASSWORD=__SENTINEL__"
    echo "GITHUB_APP_PRIVATE_KEY=__SENTINEL__"
    echo "DATABASE_URL=postgres://u:__SENTINEL__@db/x"
  else
    echo "HTTP: 200"
  fi
elif [[ "${cmd}" == "get" ]]; then
  joined="$*"
  if [[ "${joined}" == *"range .items"* ]]; then
    # "<name> <Ready status>" per pod, as the script's jsonpath renders it.
    echo "__SHIM_POD__ True"
  elif [[ "${joined}" == *"containerStatuses"* ]]; then
    echo "flink-main-container identity-agent ai-debugger-sidecar"
  fi
elif [[ "${cmd}" == "logs" ]]; then
  echo "startup complete"
  echo "token=__SENTINEL__ accepted"
fi
exit 0
""".replace("__SHIM_POD__", SHIM_POD).replace("__SENTINEL__", SENTINEL)

FAKE_KUBECTL_FAIL = """#!/usr/bin/env bash
echo "Error from server (NotFound): pods not found" >&2
exit 1
"""


FAKE_KUBECTL_EMPTY_SELECTOR = """#!/usr/bin/env bash
# `kubectl get -l ... -o jsonpath` on zero matches prints nothing and exits 0.
exit 0
"""

# Healthy pod, but every in-pod curl fails (connection refused) and the sidecar
# log carries an error line: the script must REPORT and keep going -- a failing
# probe is the diagnosis, not a reason to stop diagnosing.
FAKE_KUBECTL_PROBES_FAIL = """#!/usr/bin/env bash
cmd="${1:-}"
if [[ "${cmd}" == "exec" ]]; then
  for a in "$@"; do
    if [[ "$a" == "curl" ]]; then
      echo "curl: (7) Failed to connect to localhost port 8081" >&2
      exit 7
    fi
  done
  echo "FLINK_JM_ENDPOINT=http://localhost:8081"
elif [[ "${cmd}" == "get" ]]; then
  echo "flink-main-container identity-agent ai-debugger-sidecar"
elif [[ "${cmd}" == "logs" ]]; then
  echo "ERROR: connection refused"
fi
exit 0
"""

# Healthy kubectl, but the container env has no FLINK/SSL vars and the log has
# no 'error' lines: both greps return 1 and must NOT abort under pipefail.
FAKE_KUBECTL_NO_MATCHES = """#!/usr/bin/env bash
cmd="${1:-}"
if [[ "${cmd}" == "exec" ]]; then
  for a in "$@"; do
    if [[ "$a" == "env" ]]; then echo "PATH=/usr/bin"; exit 0; fi
  done
  echo "HTTP: 200"
elif [[ "${cmd}" == "get" ]]; then
  echo "flink-main-container identity-agent ai-debugger-sidecar"
elif [[ "${cmd}" == "logs" ]]; then
  echo "startup complete"
fi
exit 0
"""


def _run_script(tmp_path, shim_body, args, *, path=None, env_extra=None):
    """Run the script with a fake kubectl shim prepended to PATH.

    ``path`` overrides PATH entirely (used to simulate a missing kubectl);
    ``shim_body=None`` installs no shim; ``env_extra`` adds/overrides env vars
    (FLINK_DEPLOYMENT, POD_NAME, DEBUG).
    """
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    if shim_body is not None:
        shim = bindir / "kubectl"
        shim.write_text(shim_body)
        shim.chmod(0o755)
    log = tmp_path / "kubectl.log"
    log.write_text("")
    env = dict(os.environ)
    env["PATH"] = path if path is not None else f"{bindir}{os.pathsep}{env['PATH']}"
    env["KUBECTL_LOG"] = str(log)
    # The developer's own shell must not leak a target into the tests.
    env.pop("FLINK_DEPLOYMENT_NAME", None)
    env.pop("POD_NAME", None)
    env.pop("DEBUG", None)
    if env_extra:
        env.update(env_extra)
    proc = subprocess.run(
        [BASH, str(SCRIPT), *args],
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
    )
    return proc, log.read_text()


def _argv_calls(log):
    """The recorded kubectl invocations as lists of argv strings."""
    calls, current, inside = [], [], False
    for line in log.splitlines():
        if line == "ARGV_BEGIN":
            current, inside = [], True
        elif line == "ARGV_END":
            calls.append(current)
            inside = False
        elif inside:
            current.append(line)
    return calls


@needs_bash
def test_bash_syntax_is_valid():
    proc = subprocess.run(
        [BASH, "-n", str(SCRIPT)], capture_output=True, text=True, timeout=30
    )
    assert proc.returncode == 0, proc.stderr


@needs_bash
def test_pod_name_with_whitespace_stays_one_kubectl_argument(tmp_path):
    """The executable form of the latent CWE-88: a whitespace-bearing POD_NAME
    must arrive at kubectl as ONE argv element. On the old unquoted script it
    word-split into extra kubectl arguments (= injectable flags/words)."""
    proc, log = _run_script(
        tmp_path, FAKE_KUBECTL_OK, ["dep with spaces", "test-ns"],
        env_extra={"POD_NAME": "pod with spaces"},
    )
    assert proc.returncode == 0, proc.stderr
    calls = [c for c in _argv_calls(log) if c and c[0] in ("exec", "get", "logs")]
    assert calls, "kubectl was never invoked"
    for argv in calls:
        assert "pod with spaces" in argv, (
            f"pod name word-split into multiple kubectl arguments: {argv}"
        )
        assert "with" not in argv and "spaces" not in argv, (
            f"word-split fragments reached kubectl: {argv}"
        )
    # And the deployment name reaches the label selector as one `-l` value.
    proc, log = _run_script(tmp_path, FAKE_KUBECTL_OK, ["dep with spaces", "test-ns"])
    assert proc.returncode == 0, proc.stderr
    sel = [c for c in _argv_calls(log) if c and c[0] == "get" and "-l" in c]
    assert sel and sel[0][sel[0].index("-l") + 1] == "app=dep with spaces,component=jobmanager"


@needs_bash
def test_kubectl_failure_aborts_loudly_not_silently(tmp_path):
    """The ticket's negative test: against a broken/stale reference the script
    must exit non-zero at the first failing command -- not print five confident
    section headings over output that never ran (old behaviour: exit 0)."""
    proc, _ = _run_script(
        tmp_path, FAKE_KUBECTL_FAIL, [DEP, "test-ns"],
        env_extra={"POD_NAME": "no-such-pod"},
    )
    assert proc.returncode != 0, "script must fail when kubectl fails"
    assert HEADINGS[0] in proc.stdout, "should reach the first section"
    for heading in HEADINGS[1:]:
        assert heading not in proc.stdout, (
            f"section {heading!r} printed after kubectl already failed -- "
            "silent-failure regression"
        )
    # When the failure is in pod RESOLUTION itself, nothing runs at all.
    proc, _ = _run_script(tmp_path, FAKE_KUBECTL_FAIL, [DEP, "test-ns"])
    assert proc.returncode != 0
    assert "NotFound" in proc.stderr
    for heading in HEADINGS:
        assert heading not in proc.stdout


@needs_bash
def test_positive_control_all_sections_and_no_error_message(tmp_path):
    """With a healthy kubectl every section runs, and grep finding no 'error'
    log lines must NOT abort under pipefail -- it must report explicitly (so
    'no errors' is distinguishable from 'the command never ran')."""
    proc, _ = _run_script(tmp_path, FAKE_KUBECTL_OK, [DEP, "test-ns"])
    assert proc.returncode == 0, proc.stderr + proc.stdout
    for heading in HEADINGS:
        assert heading in proc.stdout, f"missing section: {heading}"
    assert "No 'error' lines" in proc.stdout
    assert "No FLINK/SSL environment variables set." not in proc.stdout


@needs_bash
def test_default_pod_resolution_uses_label_selector(tmp_path):
    """With no arguments the pod is resolved by label selector (the fix for the
    stale-pod-instance class), and the resolved name is what kubectl exec gets."""
    proc, log = _run_script(tmp_path, FAKE_KUBECTL_OK, [DEP])
    assert proc.returncode == 0, proc.stderr + proc.stdout
    calls = _argv_calls(log)
    get_calls = [c for c in calls if c and c[0] == "get" and "-l" in c]
    assert get_calls, "expected a label-selector pod lookup"
    assert f"app={DEP},component=jobmanager" in get_calls[0]
    assert get_calls[0][get_calls[0].index("-n") + 1] == "default"
    exec_calls = [c for c in calls if c and c[0] == "exec"]
    assert exec_calls
    for argv in exec_calls:
        assert SHIM_POD in argv


@needs_bash
def test_leading_dash_arguments_are_rejected(tmp_path):
    """Arguments are kubectl VALUES; anything that could parse as a kubectl
    flag is refused before kubectl is ever invoked."""
    proc, log = _run_script(tmp_path, FAKE_KUBECTL_OK, ["--all"])
    assert proc.returncode == 2
    assert "must not start with '-'" in proc.stderr
    assert "ARGV_BEGIN" not in log, "kubectl must not be invoked at all"


@needs_bash
def test_env_provided_values_get_the_same_flag_check(tmp_path):
    """FLINK_DEPLOYMENT_NAME and POD_NAME reach kubectl exactly like the
    positionals do, so a flag-shaped value from the environment is refused the
    same way: exit 2, usage, kubectl never invoked."""
    cases = [
        ([], {"FLINK_DEPLOYMENT_NAME": "--all-namespaces"}, "FLINK_DEPLOYMENT_NAME"),
        ([DEP], {"POD_NAME": "--all"}, "POD_NAME"),
        ([DEP, "ns"], {"POD_NAME": "-oyaml"}, "POD_NAME"),
    ]
    for args, extra, what in cases:
        proc, log = _run_script(tmp_path, FAKE_KUBECTL_OK, args, env_extra=extra)
        assert proc.returncode == 2, (args, extra, proc.stderr)
        assert f"{what} must not start with '-'" in proc.stderr
        assert "Usage:" in proc.stderr
        assert "ARGV_BEGIN" not in log, "kubectl must not be invoked at all"
        assert HEADINGS[0] not in proc.stdout


@needs_bash
def test_namespace_with_whitespace_stays_one_kubectl_argument(tmp_path):
    """Same CWE-88 proof for the second positional: NAMESPACE arrives as the
    single value of `-n`, on every kubectl call."""
    proc, log = _run_script(tmp_path, FAKE_KUBECTL_OK, [DEP, "ns with spaces"])
    assert proc.returncode == 0, proc.stderr
    calls = [c for c in _argv_calls(log) if c and c[0] in ("exec", "get", "logs")]
    assert calls
    for argv in calls:
        assert argv[argv.index("-n") + 1] == "ns with spaces", argv
        assert "with" not in argv and "spaces" not in argv, argv


@needs_bash
def test_too_many_arguments_are_rejected(tmp_path):
    """A third positional would otherwise be silently dropped -- a typo'd
    namespace would debug the wrong cluster without saying so."""
    proc, log = _run_script(tmp_path, FAKE_KUBECTL_OK, [DEP, "ns", "extra"])
    assert proc.returncode == 2
    assert "too many arguments" in proc.stderr
    assert "Usage:" in proc.stderr
    assert "ARGV_BEGIN" not in log, "kubectl must not be invoked at all"


@needs_bash
def test_missing_kubectl_fails_with_a_named_precondition(tmp_path):
    """Fail closed with a diagnosis, not bash's bare 'command not found'.

    PATH is an EMPTY directory: `/usr/bin:/bin` is not kubectl-free on every
    runner (ubuntu-latest ships kubectl in /usr/bin, so the real binary ran and
    exited 1 on CI). The script is invoked via the absolute bash path and uses
    only builtins before its kubectl check, so an empty PATH is sufficient."""
    empty = tmp_path / "empty-path"
    empty.mkdir()
    proc, _ = _run_script(tmp_path, None, [DEP, "ns"], path=str(empty))
    assert proc.returncode == 127
    assert "kubectl not found on PATH" in proc.stderr
    assert "command not found" not in proc.stderr
    assert HEADINGS[0] not in proc.stdout, "must fail before any section runs"


@needs_bash
def test_empty_pod_resolution_fails_with_a_clear_message(tmp_path):
    """Requirement 7: when the label selector matches no pod, kubectl prints
    nothing and exits 0 -- the script must not go on to exec into pod ''."""
    proc, log = _run_script(tmp_path, FAKE_KUBECTL_EMPTY_SELECTOR, [DEP])
    assert proc.returncode == 1
    assert f"no Ready JobManager pod found for app={DEP}" in proc.stderr
    assert "namespace default" in proc.stderr
    assert HEADINGS[0] not in proc.stdout
    # Same path with the deployment from the environment and a namespace arg
    # (an explicit empty POD_NAME env must not bypass resolution either).
    proc, _ = _run_script(
        tmp_path, FAKE_KUBECTL_EMPTY_SELECTOR, [DEP, "other-ns"],
        env_extra={"POD_NAME": ""},
    )
    assert proc.returncode == 1
    assert "namespace other-ns" in proc.stderr


@needs_bash
def test_failing_connectivity_probes_report_and_continue(tmp_path):
    """Requirement 3, second half: a failing in-pod curl is the diagnosis. All
    three probe sites must print their fallback, every section must still run,
    and the script must exit 0 (no kubectl itself failed)."""
    proc, _ = _run_script(
        tmp_path, FAKE_KUBECTL_PROBES_FAIL, [DEP, "ns"], env_extra={"POD_NAME": "good-pod"}
    )
    assert proc.returncode == 0, proc.stderr + proc.stdout
    for heading in HEADINGS:
        assert heading in proc.stdout, f"missing section: {heading}"
    assert "HTTP probe failed" in proc.stdout
    assert "HTTPS probe failed" in proc.stdout
    assert "HTTPS REST API probe failed" in proc.stdout
    # The captured REST probe site: curl's stderr (2>&1) still surfaces.
    assert proc.stdout.count("curl: (7)") == 3
    # An error line in the sidecar log is shown, not swallowed.
    assert "ERROR: connection refused" in proc.stdout
    assert "No 'error' lines" not in proc.stdout


@needs_bash
def test_no_matching_env_or_log_lines_is_reported_not_fatal(tmp_path):
    """Requirement 6: 'no FLINK/SSL vars' and 'no error lines' are explicit
    messages, distinguishable from 'the command never ran', and grep's exit 1
    does not trip `set -e`/pipefail."""
    proc, _ = _run_script(
        tmp_path, FAKE_KUBECTL_NO_MATCHES, [DEP, "ns"], env_extra={"POD_NAME": "good-pod"}
    )
    assert proc.returncode == 0, proc.stderr + proc.stdout
    for heading in HEADINGS:
        assert heading in proc.stdout, f"missing section: {heading}"
    assert "No FLINK/SSL environment variables set." in proc.stdout
    assert "No 'error' lines in the last 30 log lines." in proc.stdout


# Two JobManager pods (HA): the first listed is NotReady (terminating), the
# second is Ready. Logs the argv like FAKE_KUBECTL_OK so the exec target and
# the selector can be asserted.
FAKE_KUBECTL_HA = """#!/usr/bin/env bash
{
  printf 'ARGV_BEGIN\\n'
  for a in "$@"; do printf '%s\\n' "$a"; done
  printf 'ARGV_END\\n'
} >> "${KUBECTL_LOG}"
cmd="${1:-}"
joined="$*"
if [[ "${cmd}" == "get" && "${joined}" == *"range .items"* ]]; then
  echo "jm-old-terminating False"
  echo "jm-new-ready True"
elif [[ "${cmd}" == "get" ]]; then
  echo "flink-main-container identity-agent ai-debugger-sidecar"
elif [[ "${cmd}" == "exec" ]]; then
  echo "FLINK_JM_ENDPOINT=http://localhost:8081"
elif [[ "${cmd}" == "logs" ]]; then
  echo "startup complete"
fi
exit 0
"""

FAKE_KUBECTL_NONE_READY = """#!/usr/bin/env bash
if [[ "${1:-}" == "get" ]]; then
  echo "jm-a False"
  echo "jm-b "
fi
exit 0
"""


@needs_bash
def test_default_pod_resolution_picks_the_first_ready_jobmanager(tmp_path):
    """JobManager HA: two pods match the selector; the NotReady one listed
    first must be skipped and every exec must target the Ready pod."""
    proc, log = _run_script(tmp_path, FAKE_KUBECTL_HA, [DEP])
    assert proc.returncode == 0, proc.stderr + proc.stdout
    assert "Debugging pod 'jm-new-ready'" in proc.stdout
    exec_calls = [c for c in _argv_calls(log) if c and c[0] == "exec"]
    assert exec_calls
    for argv in exec_calls:
        assert "jm-new-ready" in argv and "jm-old-terminating" not in argv, argv


@needs_bash
def test_no_ready_jobmanager_is_a_clear_failure(tmp_path):
    proc, _ = _run_script(tmp_path, FAKE_KUBECTL_NONE_READY, [DEP])
    assert proc.returncode == 1
    assert "no Ready JobManager pod found" in proc.stderr
    assert HEADINGS[0] not in proc.stdout


@needs_bash
def test_flink_deployment_env_selects_the_deployment(tmp_path):
    """With no positional, FLINK_DEPLOYMENT_NAME names the FlinkDeployment in the
    label selector; a positional takes precedence over the env var."""
    proc, log = _run_script(
        tmp_path, FAKE_KUBECTL_HA, [], env_extra={"FLINK_DEPLOYMENT_NAME": "from-env"}
    )
    assert proc.returncode == 0, proc.stderr + proc.stdout
    get_calls = [c for c in _argv_calls(log) if c and c[0] == "get" and "-l" in c]
    assert get_calls and "app=from-env,component=jobmanager" in get_calls[0]

    proc, log = _run_script(
        tmp_path, FAKE_KUBECTL_HA, ["from-arg"], env_extra={"FLINK_DEPLOYMENT_NAME": "from-env"}
    )
    assert proc.returncode == 0, proc.stderr + proc.stdout
    get_calls = [c for c in _argv_calls(log) if c and c[0] == "get" and "-l" in c]
    assert get_calls and "app=from-arg,component=jobmanager" in get_calls[0]


@needs_bash
def test_no_deployment_given_prints_usage_and_exits_2(tmp_path):
    """Fail closed, no guessing: with neither the positional nor
    FLINK_DEPLOYMENT_NAME set there is no target, so usage + exit 2 and kubectl is
    never invoked. Same for an empty positional / empty env var."""
    for args, extra in ([], None), ([""], None), ([], {"FLINK_DEPLOYMENT_NAME": ""}):
        proc, log = _run_script(tmp_path, FAKE_KUBECTL_OK, args, env_extra=extra)
        assert proc.returncode == 2, (args, extra, proc.stderr)
        assert "no FlinkDeployment given" in proc.stderr
        assert "Usage:" in proc.stderr and "<DEPLOYMENT>" in proc.stderr
        assert "ARGV_BEGIN" not in log, "kubectl must not be invoked at all"
        assert HEADINGS[0] not in proc.stdout


@needs_bash
def test_debug_env_enables_tracing(tmp_path):
    proc, _ = _run_script(
        tmp_path, FAKE_KUBECTL_OK, [DEP, "ns"], env_extra={"POD_NAME": "good-pod"}
    )
    assert "+ kubectl" not in proc.stderr
    proc, _ = _run_script(
        tmp_path, FAKE_KUBECTL_OK, [DEP, "ns"],
        env_extra={"POD_NAME": "good-pod", "DEBUG": "1"},
    )
    assert proc.returncode == 0, proc.stderr
    # Tracing is on for the ordinary commands...
    assert "+ kubectl get pod -n ns good-pod -o" in proc.stderr
    assert "+ kubectl exec -n ns good-pod -c ai-debugger-sidecar -- curl" in proc.stderr
    # ...and resumes after the untraced env capture: the very next section's
    # heading is traced (the trace_on call itself runs while tracing is off).
    assert "+ echo '=== Checking if Flink container is running ==='" in proc.stderr


@needs_bash
def test_debug_trace_never_contains_an_env_or_log_secret(tmp_path):
    """The reviewer-reproduced leak: `set -x` traces `ENV_OUT="$(...)"` WITH
    its value, i.e. the sidecar's whole environment. The shim injects a
    sentinel as a credential-looking FLINK var, a non-FLINK secret, a URL
    password and a log line; with DEBUG=1 the sentinel must appear nowhere
    (not in the trace, not in stdout), while the section still works."""
    proc, _ = _run_script(
        tmp_path, FAKE_KUBECTL_OK, [DEP, "ns"],
        env_extra={"POD_NAME": "good-pod", "DEBUG": "1"},
    )
    assert proc.returncode == 0, proc.stderr
    assert "+ kubectl" in proc.stderr, "tracing was not actually on"
    assert SENTINEL not in proc.stderr, "sentinel leaked into the DEBUG trace"
    assert SENTINEL not in proc.stdout, "sentinel leaked into the report"
    # The untraced captures must not even show the command that fetched them.
    assert "-- env" not in proc.stderr
    assert "+ kubectl logs" not in proc.stderr
    for heading in HEADINGS:
        assert heading in proc.stdout, f"missing section: {heading}"
    # The section still reports the non-secret FLINK var, redacts the
    # credential-looking FLINK var by name, and omits everything else.
    assert "FLINK_JM_ENDPOINT=http://localhost:8081" in proc.stdout
    assert "FLINK_SSL_KEYSTORE_PASSWORD=<redacted>" in proc.stdout
    assert "GITHUB_APP_PRIVATE_KEY" not in proc.stdout
    assert "DATABASE_URL" not in proc.stdout
    # The log section still surfaces nothing it should not (no 'error' lines).
    assert "No 'error' lines" in proc.stdout


@needs_bash
def test_env_section_prints_only_flink_ssl_names_with_redaction(tmp_path):
    """Same filter without DEBUG: stdout carries only FLINK/SSL-named vars,
    credential-looking ones redacted -- the environment dump is not a report."""
    proc, _ = _run_script(
        tmp_path, FAKE_KUBECTL_OK, [DEP, "ns"], env_extra={"POD_NAME": "good-pod"}
    )
    assert proc.returncode == 0, proc.stderr
    assert SENTINEL not in proc.stdout and SENTINEL not in proc.stderr
    assert "FLINK_JM_ENDPOINT=http://localhost:8081" in proc.stdout
    assert "FLINK_SSL_KEYSTORE_PASSWORD=<redacted>" in proc.stdout
    assert "GITHUB_APP_PRIVATE_KEY" not in proc.stdout
    assert "DATABASE_URL" not in proc.stdout


# Healthy pod whose /v1/overview response is 25 lines (a pretty-printed JSON
# body): the old `| head -20 || echo` printed a false "probe failed" here,
# because head closing the pipe early failed the pipeline under pipefail.
FAKE_KUBECTL_LONG_OVERVIEW = """#!/usr/bin/env bash
{
  printf 'ARGV_BEGIN\\n'
  for a in "$@"; do printf '%s\\n' "$a"; done
  printf 'ARGV_END\\n'
} >> "${KUBECTL_LOG}"
cmd="${1:-}"
if [[ "${cmd}" == "exec" ]]; then
  joined="$*"
  if [[ "${joined}" == *"/v1/overview"* ]]; then
    for i in $(seq 1 25); do echo "overview-line-${i}"; done
  elif [[ "${joined}" == *"curl"* ]]; then
    echo "HTTP: 200"
  else
    echo "FLINK_JM_ENDPOINT=http://localhost:8081"
  fi
elif [[ "${cmd}" == "get" ]]; then
  echo "flink-main-container identity-agent ai-debugger-sidecar"
elif [[ "${cmd}" == "logs" ]]; then
  echo "startup complete"
fi
exit 0
"""


@needs_bash
def test_long_rest_response_is_truncated_not_reported_as_failure(tmp_path):
    proc, _ = _run_script(
        tmp_path, FAKE_KUBECTL_LONG_OVERVIEW, [DEP, "ns"], env_extra={"POD_NAME": "good-pod"}
    )
    assert proc.returncode == 0, proc.stderr + proc.stdout
    assert "probe failed" not in proc.stdout, "false probe failure on a long response"
    assert "overview-line-1\n" in proc.stdout and "overview-line-20" in proc.stdout
    assert "overview-line-21" not in proc.stdout, "response not truncated to 20 lines"


@needs_bash
def test_every_curl_probe_carries_timeouts_at_the_argv_level(tmp_path):
    proc, log = _run_script(
        tmp_path, FAKE_KUBECTL_LONG_OVERVIEW, [DEP, "ns"], env_extra={"POD_NAME": "good-pod"}
    )
    assert proc.returncode == 0, proc.stderr
    curl_calls = [c for c in _argv_calls(log) if "curl" in c]
    assert len(curl_calls) == 3, curl_calls
    for argv in curl_calls:
        tail = argv[argv.index("curl"):]
        assert tail[tail.index("--connect-timeout") + 1] == "5", argv
        assert tail[tail.index("--max-time") + 1] == "20", argv
