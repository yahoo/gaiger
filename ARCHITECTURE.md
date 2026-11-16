# Architecture

Gaiger is a Python sidecar that runs inside the Apache Flink JobManager pod
and diagnoses the job running there. Operators ask questions in a chat UI; a LangGraph
ReAct agent decides which diagnostic tools to call, gathers live data from the Flink
REST API and the Kubernetes API, and streams its reasoning and verdict back.

## Deployment shape

One sidecar per JobManager pod. It shares the pod network, so Flink REST is `localhost:8081`
and the sidecar's own port (`8765`) is bound to loopback.

```
┌──────────────────────────────────────────────────────────────┐
│  Flink JobManager Pod                                        │
│                                                              │
│  ┌────────────────────┐        ┌───────────────────────────┐ │
│  │ flink-main         │◀───────│ gaiger sidecar            │ │
│  │ REST :8081         │  http  │ FastAPI + LangGraph :8765 │ │
│  └────────────────────┘        └──────┬──────────┬─────────┘ │
│                                       │          │            │
│  ┌────────────────────┐               │          │            │
│  │ otel-collector     │◀── OTLP ──────┘          │            │
│  │ :4317 (optional)   │                          │            │
│  └────────────────────┘                          │            │
└──────────────────────────────────────────────────┼────────────┘
                                                   │
        ┌───────────────┬───────────────┬──────────┼──────────┬──────────────┐
        ▼               ▼               ▼          ▼          ▼              ▼
   Kubernetes API   Anthropic API   PostgreSQL   Slack API  GitHub API   Grafana API
   (events, logs,   (Claude)        (autoscaler  (optional) (optional)   (optional,
    pods, CR patch)                  state, opt.)                         alert poll)
```

Ingress is the operator's responsibility: a `kubectl port-forward` for ad-hoc use, or an
authenticating reverse proxy (SSO) in front of the pod for shared use. `ROOT_PATH` lets the
UI live under a subpath.

## Components

| File | Responsibility |
|---|---|
| `app/main.py` | FastAPI app, routes, startup wiring, SSE streaming, RBAC self-check |
| `app/langgraph_agent.py` | ReAct agent, system prompt, tool registration, prompt-leak filter |
| `app/write_authz.py` | Single write gate: `ENABLE_WRITE_TOOLS` AND not production (`DEPLOY_ENV`) |
| `app/audit.py` | Structured JSON audit events on stdout, correlation ids, field sanitization, client IP |
| `app/flink_client.py` | Flink REST: jobs, checkpoints, metrics, backpressure, savepoints |
| `app/kubernetes_client.py` | Kubernetes API: events, logs, pods, `FlinkDeployment` reads, allowlisted config patch |
| `app/auto_remediator.py` | Remediation catalog, savepoint-before-patch, rollback info |
| `app/postgres_client.py` | Optional read-only queries of the operator's autoscaler tables |
| `app/metrics_collector.py` | Background poll of Flink metrics into an in-memory ring (6 h) |
| `app/grafana_poller.py` | Optional: polls firing Grafana alerts for this deployment and runs analyses |
| `app/github_client.py` | Optional: read files and open PRs against a fixed `TARGET_REPO` |
| `app/slack_client.py` | Optional: post Block Kit messages via a bot token |
| `app/telemetry.py` | OpenTelemetry metrics and traces, content capture off |
| `app/secret_provider.py` | Loads secrets from env into memory; extension point for other backends |
| `app/ui/` | Static chat UI (`index.html`) |

## Request flow

```
Browser ──▶ your auth proxy ──▶ sidecar :8765
                                   │
                                   ├─ GET  /                  chat UI
                                   ├─ POST /api/query/stream  agent run, SSE
                                   ├─ GET  /api/diagnostics/* direct snapshots
                                   └─ POST /api/remediation/* write-gated
```

An agent run:

1. `main.py` binds a correlation id and emits an `ai_query` audit event.
2. The agent loops: model picks a tool, the tool calls Flink REST / Kubernetes / Postgres, the
   result is truncated and returned to the model.
3. Each tool call is audited with the same correlation id.
4. The final answer streams to the browser; `ai_query_result` is audited with the tools used.

## Streaming

`/api/query/stream` runs the agent exactly once and streams that single execution over
Server-Sent Events. Narration, tool-call markers, and the final answer are events in the same
stream; a `: keepalive` comment is emitted periodically so idle timers in intermediate proxies
do not close the connection. There is no replay or reconnect: a dropped stream is not resumed,
because re-running would re-execute tools, including any write tools.

`/api/query` is the non-streaming equivalent for programmatic callers.

## Write path

```
ENABLE_WRITE_TOOLS=true ──┐
                          ├── AND ──▶ write_tools_enabled()
DEPLOY_ENV not prod ──────┘               │
                                          ├─ agent registers update_flink_config,
                                          │  restart_flink_job, apply_remediation,
                                          │  create_github_pr (if GitHub configured);
                                          │  all only propose, a person approves
                                          └─ POST /api/remediation/apply accepts requests
```

- Environment detection only disables. Write tools require `DEPLOY_ENV` to positively name a
  non-production environment; production or an unrecognised value fails closed.
- `update_flink_config` rejects any key outside `ALLOWED_FLINK_CONFIG_KEYS`.
- `apply_remediation` triggers a savepoint first and records it for rollback.
- At startup, when writes are enabled, the sidecar runs `SelfSubjectAccessReview` for the
  permissions it needs and logs loudly if RBAC denies them.

## Trust boundaries and controls

| Boundary | Trust assumption | Control |
|---|---|---|
| Client → sidecar | Anyone who reaches the port is trusted. | No built-in auth. Loopback bind by default; your proxy authenticates. CORS denied by default. API docs disabled. |
| Sidecar → Flink REST | Localhost, same pod. | `FLINK_SSL_VERIFY` for HTTPS endpoints. |
| Sidecar → Kubernetes API | Pod ServiceAccount (the FlinkDeployment's own). | `k8s/rbac.yaml`: reads, plus `patch` on this deployment only; writes also need the in-app write gate and human approval. |
| Model output → cluster | Model output is untrusted. | Write gate, human approval of every cluster write and PR, config key allowlist and value schema, completed-savepoint-first, fixed `TARGET_REPO`, PR caps. |
| Model output → user | The prompt is not a secret (it ships in this repo), but a deployment's prompt plus live context should not be exfiltrated wholesale. | Leakage filter on prompt-extraction attempts, as an anti-exfiltration control (answers, Slack and PR text); sanitized error messages. |
| Sidecar → observability | Backend may be shared. | Traces carry metadata only; content-off flags are force-set. |
| Sidecar → audit sink | Log pipeline may be widely readable. | Allowlist of exempt fields; everything else truncated and secret/PII-masked at emit. |
| Proxy chain → audit | XFF entries a caller adds are spoofable. | Socket peer by default; with `AUDIT_TRUSTED_PROXY_HOPS` set, client IP read right-indexed by that depth. |

## Data and state

- No persistent disk. Metrics history lives in memory and is lost on restart.
- Secrets are read once at startup into process memory; never re-exported or logged.
- PostgreSQL is read-only and optional; it holds the Flink operator's autoscaler state, not
  the debugger's own state.
- The audit trail is stdout; retention is whatever your cluster log pipeline provides.

## Extension points

- Secrets: replace the `fetch_*` bodies in `app/secret_provider.py` with your backend.
- Tools: add a `@tool` in `langgraph_agent.py`; register it in the read-only list or under the
  write gate, never outside both.
- Allowlist: extend `ALLOWED_FLINK_CONFIG_KEYS` deliberately; every key is a model-reachable knob.
