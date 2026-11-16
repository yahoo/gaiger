# AI Incident Response — Gaiger

Operational runbook for stopping, containing, and investigating the Gaiger
sidecar. Written for a responder who has never seen this service before.
Every command works as written; if one does not, that is a runbook defect —
file it against this document.

## Ownership & escalation

| Role | Who |
|---|---|
| Service owner (primary) | `<owning team / primary contact>` |
| Escalation | `<platform on-call rotation / channel>` |
| Security engagement contact | `<security team contact>` (see also `SECURITY.md`) |

> Owner confirmation: fill in and keep this table current. If the owner above
> is stale, the platform on-call is the authoritative escalation path.

## What this system does autonomously

The sidecar (`ai-debugger-sidecar` container in each Flink JobManager pod) runs
an autonomous loop with **no human in the loop**:

1. Polls Grafana for firing alerts matching `FLINK_DEPLOYMENT_NAME` (every
   `GRAFANA_POLL_INTERVAL`, default 60s; re-analysis every 900s while firing).
2. Invokes the Anthropic model on the alert.
3. Posts analysis to Slack (`GRAFANA_ALERT_SLACK_CHANNEL` / `SLACK_DEFAULT_CHANNEL`)
   and, when GitHub integration is configured, write tools are enabled and
   `ENABLE_ALERT_FLOW_PRS=true`, may propose a PR against `TARGET_REPO`. The PR
   is opened only when a person approves it in the UI.

Cluster-mutating tools (config patch, restart, remediation) exist but are gated:
`ENABLE_WRITE_TOOLS=true` **and** a non-production `DEPLOY_ENV` are both
required (`app/write_authz.py`). Production deployments cannot enable them.

## Triggering conditions — when to open an AI incident

- Confidently wrong remediation advice posted repeatedly to Slack that other
  responders are acting on.
- An unexpected FlinkDeployment CR patch, restart, or savepoint with no
  corresponding human change (check the audit log first — see Evidence).
- An agent-opened GitHub PR that is wrong or unexpected.
- Anomalous Anthropic API spend or Slack posting volume.

## Containment — in order of escalation

### 1. Kill switch (preferred: selective, evidence-preserving)

Trips within one kubelet ConfigMap sync interval (typically ≤ 1 minute) **plus
up to one poll interval (60s)**. Stops the autonomous path and all writes;
keeps the process alive, so read-only chat stays available for investigation
and the in-memory remediation history survives.

#### Scope: pick the switch that matches the blast radius you want

The sidecar reads one file, `AGENT_KILL_SWITCH_FILE` (default
`/etc/flink-ai-debugger/kill-switch`); **which ConfigMap backs that file
decides how many debuggers one patch stops.** Check the pod before patching:

```bash
kubectl -n <namespace> get pod <jobmanager-pod> \
  -o jsonpath='{.spec.volumes[?(@.name=="ai-debugger-kill-switch")].configMap.name}'
```

| Switch | ConfigMap name | Blast radius |
|---|---|---|
| **Namespace-wide** (default; `k8s/flink-ai-debugger-kill-switch-configmap.yaml`) | `flink-ai-debugger-kill-switch` | Engaging it halts **every** AI debugger sidecar in the namespace that mounts this ConfigMap — all deployments at once, not just the one misbehaving. |
| **Per-deployment** (one ConfigMap per job, rendered by your deployment tooling) | `<deployment>-kill-switch` | Engaging it halts **only** the sidecar of that FlinkDeployment; every other debugger in the namespace keeps running. |

Use the per-deployment switch when one agent is misbehaving; use the
namespace-wide switch when the fault is systemic (bad model release, shared
credential compromise, runaway spend across jobs). Both mount at the same path,
so the app code and every command below are identical — only the ConfigMap
name differs. A pod mounts exactly one of them (whichever its manifest names).

#### Volume contract (what the FlinkDeployment manifest must render)

The sidecar only reads a file; the manifest decides whether that file exists.
A pod whose FlinkDeployment does not mount the volume logs
`Runtime kill switch NOT operable (state=not-mounted)` at startup and the
switch cannot be engaged for it. The contract your manifest (or the tooling
that renders it) must carry, under `spec.jobManager.podTemplate.spec`:

```yaml
volumes:
  - name: ai-debugger-kill-switch
    configMap:
      name: flink-ai-debugger-kill-switch   # or <deployment>-kill-switch (per-job)
      optional: true                        # an absent ConfigMap must not block pod startup
containers:
  - name: ai-debugger-sidecar
    volumeMounts:
      - name: ai-debugger-kill-switch
        mountPath: /etc/flink-ai-debugger   # dirname of AGENT_KILL_SWITCH_FILE; key `kill-switch` is the file
        readOnly: true
        # NO subPath: a subPath mount never receives ConfigMap updates, which
        # would silently disable the whole control.
```

`tests/test_kill_switch.py` parses this block and checks it against the path
the code reads, so the contract and the code cannot drift apart silently.

Engage (namespace-wide; substitute `<deployment>-kill-switch` for one job):

```bash
kubectl -n <namespace> patch configmap flink-ai-debugger-kill-switch \
  --type merge -p '{"data":{"kill-switch":"true"}}'
```

> Accepted engage values are exactly `1`, `true`, or `halt` (case-insensitive,
> surrounding whitespace and a UTF-8 BOM ignored). Any other value — including
> `on`, `yes`, `engaged`, `stop` — means RELEASED. Copy the command above
> verbatim. Always set the value under `data`, never `binaryData`: a value that
> is not valid UTF-8 (or a file over 64 bytes) is treated as **unreadable** —
> the switch fails open (agent keeps running) and the sidecar logs
> `kill-switch file unreadable ... failing OPEN` once.

Confirm engagement (sidecar logs):

```bash
kubectl -n <namespace> logs <jobmanager-pod> -c ai-debugger-sidecar --since=5m \
  | grep "Grafana poller idle — operator kill switch is engaged"
```

While engaged:
- No NEW autonomous cycles start: the Grafana poller idles (no Grafana fetch,
  no new LLM invocations).
- No NEW analyses start within a cycle already under way either: the switch is
  re-checked per alert, right before each analysis would begin, so if it trips
  while the first of several alerts is being analysed the remaining alerts are
  skipped without an LLM call (audited as `ai_query_skipped` with
  `reason=agent_halted`; they are re-evaluated on the first cycle after
  release).
- No further Slack posts: the poller suppresses the post of any in-flight
  analysis, and the agent's `send_to_slack` tool refuses.
- All writes refuse everywhere: `POST /api/remediation/apply`, `/rollback`,
  `/approve`, `/reject` and `GET /api/remediation/pending` return 403 (audited as `agent_halted`, distinct from the authorization
  denial `remediation_denied`); the agent's write tools (`update_flink_config`,
  `restart_flink_job`, `apply_remediation`, `create_github_pr`) return a
  halted error (audited as `write_tool_halted`), and so do the GitHub
  source reads (`list_github_files`, `read_github_file`). Proposals waiting
  for approval cannot be approved until release.
- `GET /api/health` still returns 200; read-only chat still answers;
  `GET /api/remediation/history` still serves.
- The halt is enforced **per operation**, not at agent construction: a sidecar
  that starts while the switch is engaged still registers its write tools and
  describes itself as write-enabled; the tools refuse at call time and work
  again the moment the switch is released — no restart or rebuild needed
  (this matters after step 3, which recreates the pod).

Release: patch the value back to `"false"` and confirm the
`Grafana poller resuming — operator kill switch released` log line.

**Limits of this control:**
- Not instantaneous: kubelet ConfigMap sync (≤ ~1 min) + up to one poll interval.
- An analysis already in flight when the switch trips completes its READ-ONLY
  diagnostic steps (including its already-started LLM exchange); its cluster
  writes are refused and its Slack post is suppressed. To hard-stop in-flight
  work immediately, escalate to step 2 or 3.
- Requires the ConfigMap volume to be mounted (see the volume contract above).
  The sidecar logs `Runtime kill switch armed` at startup when it is; a pod
  that logs `Runtime kill switch NOT operable (state=not-mounted|unreadable)`
  (a deployment whose manifest lacks the mount, or a `binaryData` value) has
  no operable switch — fall back to step 2.
- An unreadable kill file is warned about once per failure episode
  (`kill-switch file unreadable ... failing OPEN`); the warning re-arms after
  the file reads successfully again (`kill-switch file readable again`), so a
  repeat breakage is logged, not swallowed.
- Scope is fixed by the mounted ConfigMap (see the scope table above): with the
  namespace-wide switch you cannot stop one debugger without stopping all of
  them; with a per-deployment switch you cannot stop all of them with one
  patch (loop over `kubectl get configmap -l app=flink-ai-debugger-kill-switch`
  or patch each `<deployment>-kill-switch`).
- A stopping poller cancels any in-flight analysis; that run closes with an
  `ai_query_result` audit event carrying `status=cancelled`.
- Engagement/release attribution lives in the Kubernetes audit log (ConfigMap
  edit), not in app logs.
- Threat-model boundary: the switch contains a MISBEHAVING AGENT (the agent's
  own tools cannot edit the ConfigMap — it is mounted read-only and no tool
  writes arbitrary ConfigMaps). It does NOT contain an attacker with code
  execution in the sidecar: that process runs under the FlinkDeployment's own
  ServiceAccount (`example-flink-job` in the example), whose job Role can patch
  config maps, so it could patch the ConfigMap via the Kubernetes API. For that
  scenario go straight to steps 2/3 and credential revocation.

### 2. Scale to zero (coarse, evidence-destroying on the sidecar)

Suspends the whole Flink job (JobManager pod included). Stops everything, but
takes the job and its UI down and loses the sidecar's in-memory state —
**capture evidence first** (below).

```bash
kubectl -n <namespace> patch flinkdeployment <deployment-name> \
  --type merge -p '{"spec":{"job":{"state":"suspended"}}}'
```

### 3. Delete the pod (last resort)

```bash
kubectl -n <namespace> delete pod <jobmanager-pod>
```

Works in about a minute, but: **it destroys `AutoRemediator.history` — the only
copy of what the agent changed — and the metrics deque.** Capture evidence
first. The operator recreates the pod; the sidecar restarts clean (poller
included), so this does not durably stop the agent unless you also trip the
kill switch or scale to zero.

A plain `SIGTERM`/rolling restart now stops the poller cleanly — confirm
`Grafana alert poller stopped` in the terminating pod's logs.

## Evidence capture — BEFORE steps 2 or 3

```bash
# 1. Remediation history (in-memory only — lost on pod restart)
curl -s http://127.0.0.1:8765/api/remediation/history   # from inside the pod
# or via the gateway: GET <gateway>/<deployment>/chat/api/remediation/history

# 2. Sidecar logs incl. the structured JSON audit channel (stdout)
kubectl -n <namespace> logs <jobmanager-pod> -c ai-debugger-sidecar --timestamps > sidecar.log

# 3. Recent Slack posts in the alert channel (screenshot / permalink)
# 4. Any agent-opened PRs: audit events `github_pr` carry repo/branch/pr_number
```

Notes: audit records carry `actor`-less identity by design (no per-user header
is forwarded in-pod); correlate with the audit event's `source_ip`, the
`instance` field, and correlation ids. Streaming requests can run the graph
once per stream — if a historical incident predates the single-execution fix,
expect possible duplicate events per request.

## Credential revocation that actually takes effect

All five credentials are fetched from the secret provider and cached in process memory with a
TTL (`SECRET_CACHE_TTL_SECONDS`) plus auth-failure invalidation:

- **Anthropic key / Grafana SA token / Slack / GitHub / Postgres:** revoke or
  rotate at the secret provider. With a provider that serves live values, a rotated value
  propagates at the next TTL expiry or on the first 401 (the client invalidates and
  re-fetches, failing closed while the re-fetch backs off). With the built-in
  `SECRET_PROVIDER=env`, values are container environment variables that never change in a
  running container: restart the pod after rotating the Secret. For immediate effect,
  revoke at the provider **and** restart the pod (after evidence capture) or trip the kill
  switch.
- Revoking a credential upstream **without** rotating it at the secret provider stops the
  integration at the provider but the process keeps trying — pair it with the
  kill switch.

## Reverting an agent-opened GitHub PR

1. Find the PR: audit event `github_pr` (repo, branch, `pr_number`), or the
   Slack summary the run posted.
2. Close the PR and delete the branch in the target repo. Never merge an
   agent PR during an active incident.
3. If it was merged: `git revert` the merge commit via a human-reviewed PR.
4. If PAT compromise is suspected, revoke the GitHub token at the secret provider (see above).

## Validation exercise

Run annually in a test namespace (an SRE unfamiliar with the service, unaided,
timed):

1. Kill switch on → `Grafana poller idle — operator kill switch is engaged`
   logged, no Slack posts, `/api/health` 200, chat answers; off → polling resumes.
2. With `ENABLE_WRITE_TOOLS=true` (non-production only): `/api/remediation/apply`
   returns 403 while tripped; agent write tools return the halted error.
3. `SIGTERM` the pod → `Grafana alert poller stopped` appears before exit.
4. Trip the switch → `GET /api/remediation/history` still serves; contrast with
   pod deletion, after which it is empty.

| Exercise | Date | Environment | Result | Notes |
|---|---|---|---|---|
| Initial validation | 2026-11-10 | Local kind cluster, Apache Flink Kubernetes Operator 1.13 | Pass (steps 1–4) | Example manifest with write tools on, `DEPLOY_ENV=test`. Switch on: poller idle line logged after ~67s, no Grafana fetch while idle, `/api/health` 200, chat answered; off: polling resumed. `/api/remediation/apply` and `/pending` 403, `update_flink_config` returned the halted error. Pod deletion logged `Grafana alert poller stopped` before exit. History served while tripped and was empty after deletion. Not covered: Grafana was an unreachable stub (no alerts), Slack and GitHub were not configured, and the exercise was run by an automated agent (about 5 minutes), not an unaided SRE. |
