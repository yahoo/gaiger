# Monitoring the Gaiger Sidecar

The sidecar emits its own OpenTelemetry metrics and agent traces. This page covers what
is emitted, what never leaves the pod, and which alert rules to add for your deployment.

## Export

| Setting | Default | Note |
|---|---|---|
| `OTEL_EXPORTER_OTLP_ENDPOINT` | `http://localhost:4317` | OTLP/gRPC, plaintext; run a collector in the pod or on the node |
| `OTEL_SERVICE_NAME` | `FLINK_DEPLOYMENT_NAME` or `flink-ai-debugger` | `service.name` on every signal |
| `OTEL_SDK_DISABLED` | — | `true` turns telemetry off (local dev without a collector) |

Telemetry is best-effort: setup never raises and the record helpers no-op on error, so an
observability failure cannot break a request or an agent run.

## Metrics

Emitted by `app/telemetry.py`:

| Metric | Type | Labels | Emitted at |
|---|---|---|---|
| `ai_queries_total` | counter | `status` (ok/error), `mode` (sync/stream) | `/api/query`, `/api/query/stream` |
| `ai_query_duration_seconds` | histogram | — | query completion (success and error) |
| `webhook_requests_total` | counter | `source` (grafana), `outcome` (ok/error) | Grafana alert-poller analyses |
| `remediations_applied_total` | counter | `type`, `dry_run`, `status` | the auto-remediator choke point |

All labels are low-cardinality enums: no free text, user content, or identifiers.

## Tracing: content capture is off

LangGraph/LangChain agent spans and FastAPI request spans export to the same collector.
Because spans typically leave the pod for a shared observability backend, no operator
question, agent completion, message content, or tool-call text is exported. Spans carry
structure, timing, token counts, and model/tool names only.

The content-off flags are force-set at startup and cannot be overridden from the
deployment environment (regression-locked by
`tests/test_telemetry.py::test_content_capture_off_flags_cannot_be_overridden`).
Do not attempt to enable content capture while spans egress to a shared sink.

## Recommended alert rules

Alert rules are per deployment and owned by the team running the sidecar. At minimum:

1. **Query-rate alert** on `ai_queries_total` — detects cost DoS (runaway or abusive
   LLM query volume). Baseline your normal interactive rate and alert on a sustained
   multiple of it.
2. **Remediation alert** on `remediations_applied_total{dry_run="false"}` — flags
   unexpected cluster mutations. Filter on the `dry_run` label: `apply_remediation`
   previews by default, and a preview increments the same counter with
   `dry_run="true"` while changing nothing, so an unfiltered rule fires on every
   dry run. Any `dry_run="false"` increment outside a known incident window deserves
   a look; consider alerting on every such increment if your deployment runs with
   write tools disabled.

In addition to the two OTel-counter rules above, the audit stream (structured JSON
on stdout, shipped by your log pipeline -- see `app/audit.py`) carries events that
should be consumed by saved searches / alerts in your log backend (audit records age
out after your index's retention window, so alert rather than search later):

3. **Remediation denied** on `event=remediation_denied`: the write-authz 403.
   Five or more in 10 minutes indicates someone probing the cluster-mutation endpoint
   (surface mapping).
4. **Agent error rate** on `event=ai_query_result status=error`: agent failures are
   recorded honestly; alert when the error ratio rises above your baseline.
5. **GitHub PR opened** on `event=github_pr`: the highest-consequence external write
   (commit + PR under the repo-scoped token). Any occurrence deserves a look.
6. **Kill switch engaged** on `event=agent_halted OR event=write_tool_halted OR
   event=ai_query_skipped`: containment is active. Expected during an incident; any
   occurrence outside one means someone engaged the switch.
7. **Prompt leakage** on `event=prompt_leakage_withheld OR
   event=prompt_leakage_stream_suppressed` (any occurrence) and
   `event=prompt_leakage_redacted` (above your baseline): an attempt to pull the system
   prompt out through an answer, Slack or a PR.
8. **Rate limiting** on `event=rate_limited`, and **refused requests** on
   `event=request_refused` (cross-site / non-JSON POSTs): a burst means a script or a
   hostile page is driving the API.
9. **Rejected agent arguments** on `event=*_rejected` (`config_update_rejected`,
   `github_pr_rejected`, `github_read_rejected`, `github_list_rejected`,
   `remediation_type_rejected`, `logs_type_rejected`, `write_approve_rejected`): the
   model or a caller tried something the controls refuse. Several in one
   `correlation_id` suggest a planted instruction steering the agent.
10. **Write approved** on `event=write_approved`: a person approved an agent-proposed
    cluster write. Review each one; `write_proposed` without a later decision is normal
    (proposals expire).
11. **Alert analyses dropped** on `event=alert_analysis_dropped`: more firing alerts
    than `GRAFANA_MAX_ANALYSES_PER_CYCLE` in one poll.
12. **Audit gap** on `seq` discontinuity per `instance`: audit records carry a
   monotonic per-process `seq` plus a per-process `instance` id that partitions the
   streams (seq resets to 1 on each process start, and the instance id keeps
   replicas/restarts from interleaving into false gaps). A `seq` gap within one
   `instance` means dropped audit records, pipeline loss rather than real silence.

## Audit trail

Separate from telemetry: `app/audit.py` writes one JSON line per query, tool call, and
remediation to stdout on the `app.audit` logger. Ship container stdout with your existing
log pipeline, filter on the `event` field, and use `correlation_id` to reconstruct a flow.

### Event catalogue

| Area | Events |
|---|---|
| Queries | `ai_query`, `ai_query_stream`, `ai_query_result`, `ai_query_skipped` |
| Data reads | `data_access` (`route` names the read: `get_logs`, `full_diagnostics`, `thread_dump`, `skewness_analysis`, `autoscaler_*`, `job_status`, `metrics_timeseries`, `remediation_history`, `remediation_pending`) |
| Cluster writes | `write_proposed`, `write_approved`, `write_rejected`, `write_approve_rejected`, `write_reject_unknown`, `config_update`, `job_restart`, `remediation`, `rollback_lookup` |
| Refusals | `remediation_denied`, `config_update_rejected`, `remediation_type_rejected`, `logs_type_rejected`, `request_refused`, `rate_limited` |
| Kill switch | `agent_halted`, `write_tool_halted`, `ai_query_skipped` |
| GitHub | `github_list`, `github_list_rejected`, `github_read`, `github_read_rejected`, `github_pr`, `github_pr_rejected` |
| Slack | `slack_send` |
| Prompt leakage | `prompt_leakage_redacted`, `prompt_leakage_withheld`, `prompt_leakage_stream_suppressed` |
| Alert poller | `alert_analysis_dropped` |

Every record carries `event`, `ts` (UTC), `seq`, `instance`, `classification`,
`source_ip` (see `AUDIT_TRUSTED_PROXY_HOPS`), `auth`, `actor` and, inside a flow,
`correlation_id`.

### Audit sink requirements

Audit records are classified confidential: they hold the operator's question text
(credential- and PII-masked, truncated), tool names, config keys and request metadata.
The sink that stores them must be:

- **Access-controlled**: readable only by the team that owns the deployment and your
  security responders, not by everyone who can read application logs.
- **Append-only**: the writer cannot modify or delete records (a log index with
  write-once retention, or an object store with object lock).
- **Retained** for at least 180 days, or longer if your policy requires; alert rules
  above must run against it while records are still present.
- **Monitored for gaps**: rule 12 detects lost records.

## Per-tool metrics: deliberately not implemented

`tool_calls_total{tool_name}` and `tool_call_duration_seconds` were considered and
declined: every agent tool call is already a trace span carrying the tool name and duration,
so per-tool volume and latency, including an agent looping on a mutating tool, are
observable from trace data without a duplicate metric pipeline. Revisit only if your trace
retention or sampling proves too short for loop detection.
