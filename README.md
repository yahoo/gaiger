# Gaiger

An autonomous SRE agent for Apache Flink® jobs on Kubernetes, running as a diagnostics sidecar.
It runs next to the Flink JobManager, reads the Flink REST API and the Kubernetes API,
and answers operator questions ("why is this job backpressured?") through a LangGraph
ReAct agent backed by Claude. Cluster-mutating fixes exist but are off by default.

---

## Quick start

Point it at any reachable Flink JobManager REST endpoint and open the chat UI.

```bash
docker build -t gaiger .

docker run --rm -p 127.0.0.1:8765:8765 \
  -e SECRET_PROVIDER=env \
  -e ANTHROPIC_API_KEY=<your-anthropic-key> \
  -e FLINK_JM_ENDPOINT=http://<your-flink-cluster>-rest:8081 \
  -e ALLOW_NON_LOOPBACK_BIND=true -e HOST=0.0.0.0 \
  -e OTEL_SDK_DISABLED=true \
  -e POSTGRES_ENABLED=false \
  gaiger
```

Open <http://localhost:8765>. The chat UI is served at `/` and streams answers over SSE.

Notes:

- `ALLOW_NON_LOOPBACK_BIND=true HOST=0.0.0.0` is needed for Docker port publishing; the bind is loopback unless both are set. `-p 127.0.0.1:8765:8765` keeps the published port on your machine's loopback: the API has no authentication, so never publish it on all interfaces.
- `OTEL_SDK_DISABLED=true` skips the OTLP exporter when no collector is running.
- Without in-cluster credentials, Kubernetes-backed tools return errors; Flink tools still work.

---

## Deploy as a Flink JobManager sidecar

The intended shape is one sidecar container per JobManager pod, sharing the pod
network so the Flink REST API is reachable on `localhost:8081`.

1. Apply RBAC in the namespace your FlinkDeployments run in.
   Edit `<your-namespace>` in [`k8s/rbac.yaml`](k8s/rbac.yaml), then:

   ```bash
   kubectl apply -f k8s/rbac.yaml
   ```

   `flink-ai-debugger-role` grants reads only. Cluster writes come from the
   FlinkDeployment's own ServiceAccount (`patch` on this deployment only), which the
   Flink job code in the same pod also holds. Never bind the sidecar to the operator's account.
   **The namespace is the real security boundary.** The JobManager also holds your
   Flink operator's job Role, which lets it create pods (it needs this for
   TaskManagers, and Kubernetes cannot limit it by name). A pod it creates can run
   under any ServiceAccount in the same namespace. Run these FlinkDeployments in a
   namespace with no more powerful ServiceAccount in it (keep the operator's own
   account elsewhere), and treat every job in that namespace as one trust domain.
   Also apply [`k8s/flink-ai-debugger-kill-switch-configmap.yaml`](k8s/flink-ai-debugger-kill-switch-configmap.yaml);
   the example mounts it so the kill switch works.

2. Add the sidecar to your `FlinkDeployment`.
   [`k8s/example-flink-deployment.yaml`](k8s/example-flink-deployment.yaml) is a complete
   example; replace `<your-namespace>` and
   `<your-image-registry>/<org>/gaiger:<tag>`, then apply it or merge the
   sidecar container into your own manifest.

3. Reach the UI. The sidecar has no Service of its own and binds loopback by default.
   For a quick look:

   ```bash
   kubectl port-forward pod/<jobmanager-pod> 8765:8765 -n <your-namespace>
   ```

   For real use, front it with your authenticating reverse proxy (see Security model)
   and set `ROOT_PATH` if it lives under a subpath. If that proxy forwards the public
   host name unchanged, list it in `INBOUND_ALLOWED_HOSTS`.

4. Limit egress. Set `EGRESS_ALLOWED_HOSTS` to the hosts the sidecar may call, and apply a
   network-level limit underneath it: [`k8s/example-egress-networkpolicy.yaml`](k8s/example-egress-networkpolicy.yaml)
   (fill in your CIDRs; it covers the whole pod, so allow what the Flink job needs too).

### Access model

The sidecar makes **no access decision of its own**: it binds loopback and
authenticates nobody, so whatever authenticating reverse proxy you place in front
of it (see Security model) is the only authorization there is. Scope that
proxy's application assignment accordingly:

1. Assign the authenticating proxy's application **only to the team that owns the
   Flink jobs in that namespace**.
2. Assign **no broad group** (not `Everyone`, not an all-employees group, not any
   group wider than the owning team).
3. Reason: anyone assigned can use **every** route, including
   `POST /api/remediation/apply` on a deployment that has write tools enabled.

For local debugging only, bypass the proxy with the `kubectl port-forward` above.

### Incident response & kill switch

The sidecar can run an autonomous loop (Grafana poller -> LLM -> Slack). The
operational procedure for stopping it (a selective runtime kill switch backed by a
ConfigMap, no restart required; graduated containment; evidence capture;
credential revocation) is documented in
[`docs/AI_INCIDENT_RESPONSE.md`](docs/AI_INCIDENT_RESPONSE.md). Apply
[`k8s/flink-ai-debugger-kill-switch-configmap.yaml`](k8s/flink-ai-debugger-kill-switch-configmap.yaml)
before the FlinkDeployment so the switch is operable.

### Debugging the sidecar's Flink connection

```bash
./DEBUG_FLINK_CONNECTION.sh <DEPLOYMENT> [NAMESPACE]      # inspects the first Ready JobManager pod of that FlinkDeployment (label selector); namespace defaults to `default`
FLINK_DEPLOYMENT_NAME=<name> ./DEBUG_FLINK_CONNECTION.sh  # same, deployment from the environment (the sidecar's own variable name)
POD_NAME=<pod> ./DEBUG_FLINK_CONNECTION.sh <DEPLOYMENT>   # bypass pod resolution (e.g. to inspect a pod that is not Ready)
DEBUG=1 ./DEBUG_FLINK_CONNECTION.sh <DEPLOYMENT>          # trace every command (the env and log captures stay untraced)
```

Workstation-only (not shipped in the image). Requires `kubectl` on `PATH`. The FlinkDeployment name has no default: with neither the positional nor `FLINK_DEPLOYMENT_NAME` set the script prints usage and exits 2 rather than guess a target. Runs under `set -euo pipefail`: a failing `kubectl` aborts non-zero at the first failing section; the in-pod `curl` connectivity probes (each bounded by `--connect-timeout 5 --max-time 20`) report failure and continue, since a failing probe is the diagnosis. Values starting with `-` (positional or env-provided) and more than two arguments are rejected. The environment section prints only variables whose name mentions `FLINK` or `SSL`, with credential-looking values redacted, and `DEBUG=1` never traces the captured environment or log tail. The in-pod `curl -k` is deliberate: with Flink REST SSL enabled the JobManager certificate's CN is the service identity, so a loopback `https://localhost:8081` call cannot pass hostname verification.

---

## Configuration

All configuration is environment variables. Secrets are read by `SECRET_PROVIDER=env`,
the only built-in provider; `app/secret_provider.py` documents how to plug in another backend.

| Variable | Default | Purpose |
|---|---|---|
| **Secrets** | | |
| `SECRET_PROVIDER` | `env` | Secret backend. Only `env` is built in; anything else fails closed. |
| `SECRET_CACHE_TTL_SECONDS` | `3600` | Cached credentials are re-read from the provider after this many seconds and after an authentication failure. With `SECRET_PROVIDER=env`, values come from container environment variables, which do not change until the pod restarts: restart the pod after rotating a Secret. |
| `ANTHROPIC_API_KEY` | — | Required. Claude API key for the agent. |
| `SLACK_BOT_TOKEN` | — | Optional. Enables Slack posting. |
| `GITHUB_TOKEN` | — | Optional. Enables GitHub source reading and PR creation, together with `TARGET_REPO` and the write gate (`ENABLE_WRITE_TOOLS=true` in a non-production `DEPLOY_ENV`): the read tools register only where the PR tool does. |
| `POSTGRES_PASSWORD` | — | Required only when `POSTGRES_ENABLED=true`. |
| `GRAFANA_SA_TOKEN` | — | Optional. Enables the Grafana alert poller (with `GRAFANA_URL`). |
| **Server** | | |
| `HOST` | `127.0.0.1` | Bind address. Loopback always, so the port is not reachable from other pods; `HOST` is honoured only when `ALLOW_NON_LOOPBACK_BIND=true` is also set; a non-loopback `HOST` without it has no effect and logs a startup `WARNING` naming the opt-in. |
| `ALLOW_NON_LOOPBACK_BIND` | — | `true` lets `HOST` override the loopback bind (logged loudly). Debug only; never set it in a manifest. |
| `PORT` | `8765` | Listen port. |
| `ROOT_PATH` | — | URL prefix when served under a subpath by a reverse proxy (e.g. `/chat`). |
| `CORS_ALLOWED_ORIGINS` | — | Comma-separated allowed origins. Empty denies cross-origin; wildcards are ignored. |
| `INBOUND_ALLOWED_HOSTS` | — | Extra `Host` header names the API answers to (comma-separated). `127.0.0.1` and `localhost` are always allowed (port-forward, probes, a pod-local proxy to `127.0.0.1:8765`); any other Host gets 400 (DNS-rebinding defence). A proxy that forwards the public host name unchanged must list it here. Separate from `EGRESS_ALLOWED_HOSTS` (outbound). `*` is ignored. |
| **Model** | | |
| `ANTHROPIC_MODEL` | `claude-sonnet-4-5-20250929` | Model for interactive chat. |
| `GRAFANA_ALERT_MODEL` | `claude-opus-4-20250514` | Model for alert-triggered analyses. It differs from the chat default on purpose: unattended analyses favour depth, chat favours latency. Pin both to model ids you have evaluated, and review them when Anthropic announces a model deprecation (see Anthropic's model deprecations page). |
| **Flink** | | |
| `FLINK_JM_ENDPOINT` | `http://127.0.0.1:8081` | Flink JobManager REST endpoint. |
| `FLINK_SSL_VERIFY` | `true` | TLS certificate verification to the JobManager is on by default. Set `false` to skip it (dev/test only; logs a warning). |
| `FLINK_SSL_CA_BUNDLE` | — | Optional CA bundle the JobManager's REST certificate is verified against. Unset or absent file: the system trust store is used. |
| `FLINK_DEPLOYMENT_NAME` | — | Name of the `FlinkDeployment` CR. Scopes event queries, config patches, and alert matching. |
| **Kubernetes** | | |
| `POD_NAME` / `POD_NAMESPACE` | — | Inject via `fieldRef` in the pod spec. |
| **Write gating** | | |
| `ENABLE_WRITE_TOOLS` | `false` | Registers `update_flink_config`, `restart_flink_job`, `apply_remediation` (and the GitHub tools when GitHub is configured). Cluster writes and pull requests still need a person to approve each one. |
| `WRITE_PROPOSAL_TTL_SECONDS` | `600` | How long an agent-proposed cluster write or pull request waits for Approve / Reject (60–3600). Proposals are single use and held in memory. |
| `DEPLOY_ENV` | — | Environment label (`nonprod`, `dev`, `test`, `staging` enable; `prod`/`prd`/`production` and anything unrecognised force-disable write tools regardless of the flag). `ALLOW_WRITE_TOOLS_WITHOUT_ENV=true` applies only when `DEPLOY_ENV` is unset, for local development. |
| `SAVEPOINT_COMPLETION_TIMEOUT_SECONDS` | `300` | A live remediation patches the job only after its savepoint reports `COMPLETED`; if it fails or does not complete in this time, the remediation stops and reports the failure. Polled every `SAVEPOINT_POLL_INTERVAL_SECONDS` (default `5`). Needs `state.savepoints.dir`. |
| `AGENT_KILL_SWITCH_FILE` | `/etc/flink-ai-debugger/kill-switch` | Path of the runtime kill-switch flag file (a ConfigMap volume mount; `1`/`true`/`halt` engages). Which ConfigMap backs it sets the blast radius: namespace-wide `flink-ai-debugger-kill-switch` or per-deployment `<deployment>-kill-switch`. See [`docs/AI_INCIDENT_RESPONSE.md`](docs/AI_INCIDENT_RESPONSE.md). |
| `EGRESS_ALLOWED_HOSTS` | — | Comma-separated hostnames every non-loopback outbound destination must match: `FLINK_JM_ENDPOINT`, `GITHUB_API_BASE`, `GRAFANA_URL`, `OTEL_EXPORTER_OTLP_ENDPOINT`, the Anthropic endpoint (`ANTHROPIC_API_URL`, else `ANTHROPIC_BASE_URL`, else `api.anthropic.com` — include it when pinning) and `POSTGRES_HOST`. Unset = allowlist off for destinations without a built-in known-host set (`GITHUB_API_BASE` then falls back to `api.github.com`); https is still required for all non-loopback URL destinations, and a violating destination fails startup. When set, the list is authoritative for every destination (it replaces the built-in GitHub set, so list the GitHub host too). Not covered (fixed destinations secured by TLS trust): the Kubernetes API and the Slack Web API (`slack.com`). |
| **Audit** | | |
| `AUDIT_TRUSTED_PROXY_HOPS` | `0` | Number of trusted proxies that append to `X-Forwarded-For`. `0` ignores the header and records the socket peer; set it to your proxy chain's real depth (the example manifest sets `1`) and the client IP is read that many entries from the right. Also keys the rate limits. |
| **PostgreSQL (optional)** | | |
| `POSTGRES_ENABLED` | `false` | Opt-in. Set `true` if you run the operator's JDBC autoscaler state store. Connection failure is non-fatal. |
| `POSTGRES_HOST` | `localhost` | Use `<your-postgres-host>`. TLS is always on. |
| `POSTGRES_PORT` | `5432` | |
| `POSTGRES_DB` | `flink_autoscaler` | |
| `POSTGRES_USER` | `flink` | |
| **Slack (optional)** | | |
| `SLACK_DEFAULT_CHANNEL` | — | Channel for analysis reports, e.g. `#<your-alerts-channel>`. The bot must be a member. The destination is pinned by configuration; the model cannot choose a channel. |
| `SLACK_ALLOWED_CHANNELS` | — | Optional extra sink-side destinations (comma-separated). The permitted set is this list plus `SLACK_DEFAULT_CHANNEL` and `GRAFANA_ALERT_SLACK_CHANNEL`; any other destination is refused, and with none of the three set every send is refused. |
| **Grafana alert polling (optional)** | | |
| `GRAFANA_URL` | — | Grafana base URL. Poller is disabled until this and `GRAFANA_SA_TOKEN` are set. |
| `GRAFANA_POLL_INTERVAL` | `60` | Seconds between polls. |
| `GRAFANA_POLLER_RE_EVAL_INTERVAL` | `900` | Seconds before a still-firing alert is re-analyzed. |
| `GRAFANA_ALERT_SLACK_CHANNEL` | `SLACK_DEFAULT_CHANNEL` | Separate channel for alert analyses. |
| `GRAFANA_MAX_ANALYSES_PER_CYCLE` | `3` | Alert analyses started per poll; the rest wait for the next poll (`alert_analysis_dropped` audit event). |
| **GitHub (optional)** | | |
| `TARGET_REPO` | — | `owner/repo` the agent may read from and open PRs against. Fixed by config; the model cannot change it. |
| `GITHUB_API_BASE` | `https://api.github.com` | Override for GitHub Enterprise. Must be `https://` and, unless `EGRESS_ALLOWED_HOSTS` is set, `api.github.com`; any other host fails startup. |
| `ENABLE_ALERT_FLOW_PRS` | `false` | `true` lets the unattended alert flow propose PRs; each still opens only when a person approves it. Off by default: alert text is attacker-influenced. |
| `GITHUB_PR_MAX_PER_DAY` | `5` | Approved PRs that may be opened in any rolling 24 hours (0–100); more are refused at approval and audited as `github_pr_rejected` / `daily_cap`. |
| `GITHUB_PR_ALLOWED_PREFIXES` | — | Optional comma-separated path prefixes a PR may change (e.g. `src/main/`); other paths are refused. |
| **Telemetry** | | |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | `http://localhost:4317` | OTLP/gRPC collector for metrics and traces. |
| `OTEL_SERVICE_NAME` | `FLINK_DEPLOYMENT_NAME` or `flink-ai-debugger` | `service.name` resource attribute. |
| `OTEL_SDK_DISABLED` | — | `true` disables telemetry entirely. |


---

### Narrowing credentials

All credentials are long-lived values read from the environment. Keep each as narrow and
short-lived as your platform allows:

- **GitHub**: prefer a GitHub App installation token scoped to `TARGET_REPO` only, with
  Contents and Pull requests read/write and nothing else, minted for the pod and refreshed
  before expiry. A fine-grained personal token, if used, must name only `TARGET_REPO`, carry
  the same two permissions, and have an expiry.
- **Grafana**: a service-account token with the Viewer role on the alerting API and an
  expiry date; rotate it before it lapses.
- **PostgreSQL**: a SELECT-only role; where your database supports it, use certificate or
  cloud IAM authentication instead of a static password.
- **Anthropic**: a key used only by this deployment, so revoking it affects nothing else.

With `SECRET_PROVIDER=env`, a rotated Secret takes effect only after the pod restarts.

## Security model

| Control | What it does | Why |
|---|---|---|
| Write gate | Mutating tools register only when `ENABLE_WRITE_TOOLS=true`. Same check guards the agent, `POST /api/remediation/apply` and the approve / reject routes. | One switch, no bypass path. |
| Human approval | Agent cluster writes and pull requests are proposals; they run only when a person clicks Approve (`POST /api/remediation/approve`). The model has no tool for that route and never sees the proposal id; proposals are single use and expire. | Planted text in logs or alerts cannot change the cluster or open a PR on its own. |
| PR limits | Alert-flow PR proposals need `ENABLE_ALERT_FLOW_PRS`; `GITHUB_PR_MAX_PER_DAY` caps approved PRs; `GITHUB_PR_ALLOWED_PREFIXES` restricts paths (checked when proposed and again when approved). | Bounds what a steered agent can get pushed, even with approval. |
| Production hard-stop | Write tools are enabled only when `DEPLOY_ENV` is positively a non-production environment; `prod` or an unrecognised/blank value force-disables them (fail closed). It can only disable, never enable. | A flag left on in a prod manifest cannot expose the mutating surface. |
| Config allowlist | `update_flink_config` accepts only keys in `ALLOWED_FLINK_CONFIG_KEYS` (`app/kubernetes_client.py`): autoscaler tuning, parallelism, TM memory/slots, checkpoint interval/timeout, incremental state. Each value must match its key's schema (single line, bounded length, shape and range). | Bounds what a model-chosen patch can touch; a value cannot smuggle another key. |
| Savepoint first | A catalogued remediation waits for a completed savepoint and stops if it fails; needs `state.savepoints.dir`. A direct `update_flink_config` takes no savepoint. | A failed backup never precedes a patch. |
| Fixed PR target | GitHub reads and PRs go only to `TARGET_REPO`; the model cannot supply a repo. | Prevents prompt content from redirecting the token. |
| Target repo CI | `TARGET_REPO` CI must run `ai-debugger/**` branches and same-repo PRs from them without secrets, or require approval before workflows run. | Approving a proposal pushes the branch before code review of the PR, so otherwise model-written code runs in CI before review. |
| PR text egress | PR title, body and commit message pass the credential mask and the prompt-leakage gate; markdown/HTML images are removed. A file read that resolves to a different path (symlink) is refused. | PR text is published; an image fetch leaks its URL. |
| Audit trail | One JSON line per query, tool call, and remediation on stdout (`app.audit` logger), with a correlation id per flow. Sensitive fields are redacted at the emit point. | Durable via your cluster log pipeline; no database needed. |
| Client IP | The socket peer by default; with `AUDIT_TRUSTED_PROXY_HOPS` set, taken from `X-Forwarded-For` right-indexed by that depth. | XFF entries a caller adds are attacker-controlled. |
| No built-in auth | The sidecar authenticates nobody. Bind stays on loopback; deploy behind your SSO or authenticating reverse proxy. | The pod plus your front proxy is the trust boundary. |
| Host allowlist | Requests whose `Host` is not loopback or listed in `INBOUND_ALLOWED_HOSTS` get 400. | A DNS-rebinding page cannot reach a port-forwarded API. |
| Cross-site POSTs | Every `POST` must be `application/json`; `Sec-Fetch-Site: cross-site`/`same-site` or a foreign `Origin` is refused unless the origin is in `CORS_ALLOWED_ORIGINS`. Remediation routes are rate-limited. | Another site cannot drive the API through a signed-in browser. |
| Read masking | Credentials are masked in the plain log stream and in `/api/logs/*` and `/api/diagnostics/*` responses. | Job logs and parameters can carry secrets. |
| Telemetry content-off | Traces carry span structure, timing, and tool/model names only. Prompt and completion capture is force-disabled and not overridable. | Spans often egress to a shared observability backend. |
| Hardened surface | API docs endpoints (`/docs`, `/redoc`, `/openapi.json`) are disabled; CORS denies by default; error messages are sanitized. | Smaller attack surface. |

Report vulnerabilities per [SECURITY.md](SECURITY.md).

---

## What the agent can do

14 read-only tools are always registered: job status and config, checkpoint details,
backpressure and skew analysis, recent exceptions, Kubernetes logs and events, operator
metrics, thread dumps, autoscaler info, Flink operator logs, Slack posting, and a
root-cause-plus-fix proposal. With write tools enabled it gains `update_flink_config`,
`restart_flink_job` and `apply_remediation`, and, when `GITHUB_TOKEN` + `TARGET_REPO` are
also set, `list_github_files`, `read_github_file` and `create_github_pr` (20 tools total).
The GitHub reads sit under the write gate too: repository source is sent to the model
only where the agent may also propose a PR.

Writes are proposals: `update_flink_config`, `restart_flink_job`, a live
`apply_remediation` and `create_github_pr` record a pending action and change nothing.
The UI shows it with Approve / Reject (for a PR, with the proposed file); only Approve
runs it. The alert-triggered flow never registers the cluster-write tools, and
registers the GitHub tools only with `ENABLE_ALERT_FLOW_PRS=true`; even then a PR is
only proposed. The alert's Slack post says a change awaits approval, and the UI's
Pending Approvals button lists it (`GET /api/remediation/pending`). Raise
`WRITE_PROPOSAL_TTL_SECONDS` if alert-flow proposals expire before anyone looks.

Remediation catalog (`app/auto_remediator.py`): increase checkpoint timeout, enable
incremental checkpoints, adjust checkpoint interval, stabilize autoscaler, emergency
savepoint, increase TM memory, increase network buffers, plus code-level proposals for
blocking I/O and data skew.

---

## HTTP API

| Method | Path | Description |
|---|---|---|
| `GET` | `/` | Chat UI |
| `GET` | `/api/health` | Health and dependency status |
| `GET` | `/api/job/status` | Current job summary |
| `POST` | `/api/query` | AI analysis, single JSON response |
| `POST` | `/api/query/stream` | AI analysis, SSE stream with keepalives |
| `GET` | `/api/diagnostics/full` | Flink + Kubernetes + autoscaler snapshot |
| `POST` | `/api/diagnostics/thread-dump` | TaskManager thread-dump analysis |
| `POST` | `/api/diagnostics/skewness` | Data-skew analysis |
| `GET` | `/api/logs/{log_type}` | JobManager / TaskManager / operator logs |
| `GET` | `/api/autoscaler/events\|errors\|status` | Autoscaler data (PostgreSQL) |
| `POST` | `/api/remediation/apply` | Apply a catalog fix (write-gated, waits for a completed savepoint) |
| `GET` | `/api/remediation/history` | Applied remediations |
| `POST` | `/api/remediation/rollback` | Savepoint info for reverting an action |
| `GET` | `/api/remediation/pending` | Agent proposals awaiting a decision (write-gated) |
| `POST` | `/api/remediation/approve` | Run an agent-proposed cluster write or open a proposed PR (`{"proposal_id": ...}`; write-gated) |
| `POST` | `/api/remediation/reject` | Drop an agent proposal |
| `GET` | `/api/metrics/timeseries` | In-memory metrics history (up to 6 h) |

Every `POST` must send `Content-Type: application/json`.

---

## Optional integrations

| Integration | Enable with | Guide |
|---|---|---|
| Slack notifications | `SLACK_BOT_TOKEN`, `SLACK_DEFAULT_CHANNEL` | [docs/SLACK_QUICK_SETUP.md](docs/SLACK_QUICK_SETUP.md), [docs/SLACK_MESSAGE_IMPROVEMENTS.md](docs/SLACK_MESSAGE_IMPROVEMENTS.md) |
| Grafana alert polling | `GRAFANA_URL`, `GRAFANA_SA_TOKEN`, `FLINK_DEPLOYMENT_NAME` | [docs/GRAFANA_WEBHOOK_SETUP.md](docs/GRAFANA_WEBHOOK_SETUP.md) |
| GitHub PRs | `GITHUB_TOKEN`, `TARGET_REPO`, `ENABLE_WRITE_TOOLS=true` | Section above; `app/github_client.py` |
| PostgreSQL autoscaler state | `POSTGRES_ENABLED=true` + `POSTGRES_*` | [docs/POSTGRES_SETUP_GUIDE.md](docs/POSTGRES_SETUP_GUIDE.md), [docs/AUTOSCALER_DATA_SOURCE_OPTIONS.md](docs/AUTOSCALER_DATA_SOURCE_OPTIONS.md) |
| Own metrics and traces | OTLP collector on `localhost:4317` | [docs/MONITORING.md](docs/MONITORING.md) |

**GitHub PRs and the target repo's CI.** An approved `create_github_pr` proposal creates an
`ai-debugger/<slug>` branch in `TARGET_REPO` and commits to it before the pull request exists,
so `on: push` and `pull_request` workflows there run model-written files before anyone reviews them. `TARGET_REPO` CI must run
`ai-debugger/**` branches and same-repo PRs from them without secrets, or require approval before
workflows run; otherwise model-written code runs in CI before review.

Architecture and trust boundaries: [ARCHITECTURE.md](ARCHITECTURE.md).

---

## Development

```bash
python3.12 -m venv .venv && source .venv/bin/activate
pip install --require-hashes -r requirements.lock
pip install -r requirements-dev.txt

# Run locally against a port-forwarded JobManager
SECRET_PROVIDER=env ANTHROPIC_API_KEY=<your-key> \
  OTEL_SDK_DISABLED=true POSTGRES_ENABLED=false \
  python -m app.main

# Tests (no LLM calls)
SECRET_PROVIDER=env ANTHROPIC_API_KEY=dummy python -m pytest tests/
```

Stack: Python 3.12, FastAPI, LangGraph, `langchain-anthropic`, aiohttp, asyncpg,
`kubernetes` client, PyGithub, OpenTelemetry.

---

## Contributing and license

See [CONTRIBUTING.md](CONTRIBUTING.md). Commits must carry a DCO sign-off (`git commit -s`).

Apache License 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).

## Naming and trademarks

Gaiger was developed internally as "Flink AI Debugger". Kubernetes resource names, the
kill-switch path (`/etc/flink-ai-debugger/kill-switch`), the `ai-debugger-sidecar`
container name and telemetry defaults keep that prefix so existing deployments and
runbooks keep working.

Apache®, Apache Flink®, and Flink® are either registered trademarks or trademarks of the
Apache Software Foundation in the United States and/or other countries. Gaiger is not
affiliated with, endorsed by, or sponsored by the Apache Software Foundation.
