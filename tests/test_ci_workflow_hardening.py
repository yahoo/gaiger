# Copyright Yahoo, Licensed under the terms of the Apache 2.0 license. See LICENSE for terms.

"""CI workflow hardening invariants.

Every workflow under .github/workflows must:
  * pin every `uses:` to a full 40-hex commit SHA (tags and branches are mutable);
  * declare a top-level `permissions: {}` (no workflow-wide token grant);
  * grant each job at most `contents: read` (internal-only workflows,
    which publish-tree.sh keeps out of the public tree, are exempt);
  * check out with `persist-credentials: false` (no token left in .git/config).

And the CI workflow's image build must be gated on the test suite, the secret
scan, the dependency review and the config scan.
"""
import os
import pathlib
import re
import subprocess

import pytest

yaml = pytest.importorskip("yaml")

ROOT = pathlib.Path(__file__).resolve().parent.parent
WORKFLOW_DIR = ROOT / ".github" / "workflows"
WORKFLOWS = sorted(WORKFLOW_DIR.glob("*.yml")) + sorted(WORKFLOW_DIR.glob("*.yaml"))
SHA_PIN = re.compile(r"^[^@\s]+@[0-9a-f]{40}$")
# Read-only scopes a job may hold; any write grant (or write-all) is rejected.
ALLOWED_JOB_PERMISSIONS = {"contents": "read"}
# Never published; scripts/publish-tree.sh removes these from the release tree.
INTERNAL_ONLY = {"internal-container-scan.yml", "security-workflow.yml"}
INTERNAL_WORKFLOW = WORKFLOW_DIR / "internal-container-scan.yml"


def _load(path):
    return yaml.safe_load(path.read_text())


def _steps(workflow):
    for job_id, job in (workflow.get("jobs") or {}).items():
        for step in job.get("steps") or []:
            yield job_id, step


def test_workflows_exist():
    assert WORKFLOWS, "no workflows found; the hardening checks would be vacuous"


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_every_action_is_pinned_to_a_full_sha(path):
    wf = _load(path)
    uses = [(job_id, step["uses"]) for job_id, step in _steps(wf) if "uses" in step]
    # Reusable-workflow calls sit at job level.
    uses += [(job_id, job["uses"]) for job_id, job in (wf.get("jobs") or {}).items() if "uses" in job]
    for job_id, ref in uses:
        if ref.startswith("./"):
            continue  # local action/workflow: versioned with this repo
        assert SHA_PIN.match(ref), f"{path.name}:{job_id}: {ref!r} is not pinned to a commit SHA"


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_top_level_permissions_are_empty(path):
    wf = _load(path)
    assert "permissions" in wf, f"{path.name}: missing top-level permissions"
    assert wf["permissions"] == {}, f"{path.name}: top-level permissions must be {{}}, got {wf['permissions']!r}"


@pytest.mark.parametrize("path", [w for w in WORKFLOWS if w.name not in INTERNAL_ONLY], ids=lambda p: p.name)
def test_jobs_hold_at_most_contents_read(path):
    wf = _load(path)
    for job_id, job in (wf.get("jobs") or {}).items():
        perms = job.get("permissions", {})
        assert isinstance(perms, dict), f"{path.name}:{job_id}: permissions {perms!r} (use a scoped mapping)"
        for scope, level in perms.items():
            assert ALLOWED_JOB_PERMISSIONS.get(scope) == level or level == "none", (
                f"{path.name}:{job_id}: {scope}: {level} exceeds contents: read"
            )


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_checkout_does_not_persist_credentials(path):
    wf = _load(path)
    checkouts = [(job_id, step) for job_id, step in _steps(wf)
                 if str(step.get("uses", "")).startswith("actions/checkout@")]
    for job_id, step in checkouts:
        assert (step.get("with") or {}).get("persist-credentials") is False, (
            f"{path.name}:{job_id}: actions/checkout without persist-credentials: false"
        )


def test_docker_build_is_gated_on_all_checks():
    wf = _load(WORKFLOW_DIR / "ci.yml")
    jobs = wf["jobs"]
    needs = jobs["docker-build"]["needs"]
    needs = [needs] if isinstance(needs, str) else needs
    for required in ("test", "secret-scan", "dependency-review", "config-scan"):
        assert required in jobs, f"ci.yml: job {required!r} missing"
        assert required in needs, f"ci.yml: docker-build does not need {required!r}"
    # dependency-review is skipped on push, so docker-build carries an explicit
    # condition; it must still refuse to run when any needed job failed.
    cond = str(jobs["docker-build"].get("if", ""))
    assert "failure" in cond and "needs" in cond, f"docker-build if: {cond!r} does not block on failed needs"
    assert "always()" not in cond, "always() would run the build even after a failed check"


def test_security_checks_are_configured_to_fail():
    jobs = _load(WORKFLOW_DIR / "ci.yml")["jobs"]

    def _with(job, prefix):
        steps = [s for s in jobs[job]["steps"] if str(s.get("uses", "")).startswith(prefix)]
        assert len(steps) == 1, f"{job}: expected one {prefix} step"
        return steps[0].get("with") or {}

    dr = _with("dependency-review", "actions/dependency-review-action@")
    assert dr.get("fail-on-severity") == "high"
    trivy = _with("config-scan", "aquasecurity/trivy-action@")
    assert trivy.get("scan-type") == "config"
    assert str(trivy.get("exit-code")) == "1"
    assert set(str(trivy.get("severity")).split(",")) >= {"HIGH", "CRITICAL"}


def test_dco_job_requires_sign_off_on_pull_requests():
    jobs = _load(WORKFLOW_DIR / "ci.yml")["jobs"]
    assert "dco" in jobs, "ci.yml: DCO job missing (CONTRIBUTING.md requires sign-off)"
    dco = jobs["dco"]
    assert dco.get("name") == "DCO"
    assert "pull_request" in str(dco.get("if", ""))
    assert dco.get("permissions") == {"contents": "read"}
    steps = dco["steps"]
    checkout = [s for s in steps if str(s.get("uses", "")).startswith("actions/checkout@")]
    assert len(checkout) == 1
    assert SHA_PIN.match(checkout[0]["uses"])
    assert checkout[0]["with"].get("persist-credentials") is False
    assert checkout[0]["with"].get("fetch-depth") == 0       # full history for rev-list
    run = [s for s in steps if "run" in s]
    assert len(run) == 1
    script = run[0]["run"]
    assert "Signed-off-by: " in script and 'exit "$fail"' in script
    # Event values reach the script through env, never interpolated into it.
    assert "${{" not in script
    assert set(run[0]["env"]) == {"BASE", "HEAD"}


def test_dependabot_keeps_the_opentelemetry_cap():
    cfg = _load(ROOT / ".github" / "dependabot.yml")
    pip = next(u for u in cfg["updates"] if u["package-ecosystem"] == "pip")
    ignored = {i["dependency-name"]: i["versions"] for i in pip.get("ignore", [])}
    assert ignored.get("opentelemetry-sdk") == [">=1.41.0"]
    assert ignored.get("opentelemetry-exporter-otlp-proto-grpc") == [">=1.41.0"]
    assert ignored.get("opentelemetry-instrumentation*") == [">=0.62b0"]


def test_image_is_built_from_hashed_lock_and_digest_pinned_base():
    dockerfile = (ROOT / "Dockerfile").read_text()
    assert re.search(r"^FROM python:3\.12-slim@sha256:[0-9a-f]{64}$", dockerfile, re.M)
    assert "--require-hashes -r requirements.lock" in dockerfile
    assert "requirements.txt" not in re.sub(r"#.*", "", dockerfile)
    lock = (ROOT / "requirements.lock").read_text()
    pins = re.findall(r"^([A-Za-z0-9_.\-]+)==\S+ \\$", lock, re.M)
    assert pins and lock.count("--hash=sha256:") >= len(pins)
    # The OpenTelemetry cap from requirements.txt carries into the lock.
    for name, ceiling in (("opentelemetry-sdk", (1, 41)), ("opentelemetry-instrumentation", (0, 62))):
        version = re.search(rf"^{name}==(\d+)\.(\d+)", lock, re.M)
        assert version and tuple(map(int, version.groups())) < ceiling


def test_ci_scans_the_built_image_and_bounds_runs():
    wf = _load(WORKFLOW_DIR / "ci.yml")
    assert wf["concurrency"]["group"] == "ci-${{ github.ref }}"
    for job_id, job in wf["jobs"].items():
        assert job.get("timeout-minutes") == 20, job_id
    steps = wf["jobs"]["docker-build"]["steps"]
    scans = [s for s in steps if str(s.get("uses", "")).startswith("aquasecurity/trivy-action@")]
    assert len(scans) == 1
    w = scans[0]["with"]
    assert w["scan-type"] == "image" and w["image-ref"] == "gaiger:ci"
    assert str(w["exit-code"]) == "1" and set(w["severity"].split(",")) >= {"HIGH", "CRITICAL"}
    install = next(s for s in wf["jobs"]["test"]["steps"] if s.get("name") == "Install")["run"]
    assert "--require-hashes -r requirements.lock" in install and "requirements-dev.txt" in install


def test_one_python_version_everywhere():
    wf = _load(WORKFLOW_DIR / "ci.yml")
    setup = next(s for s in wf["jobs"]["test"]["steps"] if str(s.get("uses", "")).startswith("actions/setup-python@"))
    assert setup["with"]["python-version"] == "3.12"
    assert "python:3.11" not in (ROOT / "Dockerfile").read_text()


def test_lock_satisfies_every_requirement():
    # A requirements.txt bump without a regenerated lock changes nothing in the image.
    from packaging.requirements import Requirement
    from packaging.utils import canonicalize_name

    lock = (ROOT / "requirements.lock").read_text()
    pins = {canonicalize_name(n): v for n, v in re.findall(r"^([A-Za-z0-9_.\-]+)==(\S+) \\$", lock, re.M)}
    stale = []
    for line in (ROOT / "requirements.txt").read_text().splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        req = Requirement(line)
        pinned = pins.get(canonicalize_name(req.name))
        if pinned is None or not req.specifier.contains(pinned, prereleases=True):
            stale.append(f"{req} (lock: {pinned})")
    assert not stale, "regenerate requirements.lock (scripts/compile-requirements.sh): " + ", ".join(stale)


def test_internal_scan_workflow_only_runs_in_the_internal_repository():
    if not INTERNAL_WORKFLOW.exists():
        pytest.skip("internal-only workflow is not part of the public tree")
    jobs = _load(INTERNAL_WORKFLOW)["jobs"]
    for job_id, job in jobs.items():
        assert "github.repository ==" in str(job.get("if", "")), job_id
        for step in job.get("steps") or []:
            if "uses" in step:
                assert (step.get("with") or {}).get("push-in-pr") is False, job_id


def test_publish_tree_leaves_out_the_internal_workflow(tmp_path):
    def git(*args, cwd=tmp_path):
        return subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True).stdout.strip()

    git("init", "-q")
    internal = (".github/workflows/internal-container-scan.yml", ".github/workflows/security-workflow.yml")
    for name in (".github/workflows/ci.yml", *internal, "scripts/publish-tree.sh"):
        target = tmp_path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text((ROOT / "scripts/publish-tree.sh").read_text() if name.endswith(".sh") else name)
    git("add", "-A")
    git("-c", "user.name=t", "-c", "user.email=t@example.com", "commit", "-qm", "base")
    env_cmd = ["bash", str(tmp_path / "scripts/publish-tree.sh"), "HEAD", "release"]
    out = subprocess.run(env_cmd, cwd=tmp_path, check=True, capture_output=True, text=True,
                         env={**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.com",
                              "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.com"}).stdout.strip()
    files = git("ls-tree", "-r", "--name-only", out).splitlines()
    assert ".github/workflows/ci.yml" in files
    assert not set(internal) & set(files)
    assert git("rev-list", "--count", out) == "1"
    assert git("status", "--porcelain") == ""
