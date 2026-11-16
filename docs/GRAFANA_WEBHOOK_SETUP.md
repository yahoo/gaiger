# Grafana Alert Integration

The sidecar polls Grafana's Alertmanager API for firing alerts that belong to this Flink
deployment, runs a root-cause analysis with the agent, and posts the result to Slack.
The alert is only the trigger; all evidence comes live from the Flink REST API and
Kubernetes.

Polling, not webhooks: the sidecar sits behind your ingress and binds loopback, so it
reaches out to Grafana rather than exposing an inbound endpoint.

## How it works

| Step | Detail |
|---|---|
| Poll | `GET <GRAFANA_URL>/api/alertmanager/grafana/api/v2/alerts` every `GRAFANA_POLL_INTERVAL` s |
| Filter | Keep alerts whose `job` or `flink_deployment` label equals `FLINK_DEPLOYMENT_NAME` |
| Dedup | Key on (fingerprint, startsAt); re-analyze a still-firing alert after `GRAFANA_POLLER_RE_EVAL_INTERVAL` s |
| Analyze | Run the agent with `GRAFANA_ALERT_MODEL`; the alert is treated as ground truth, not re-verified |
| Deliver | Post verdict + action to `GRAFANA_ALERT_SLACK_CHANNEL` (or `SLACK_DEFAULT_CHANNEL`), details as a thread reply |

Write tools are never used from the alert path; remediation is proposed (or opened as a PR
when GitHub is configured), not applied.

## Setup

### 1. Create a Grafana service account token

Works for Grafana Cloud and self-hosted Grafana 9+.

1. Administration → Service accounts → Add service account.
2. Role: `Viewer` is sufficient (the poller only reads alerts).
3. Add a token; copy it once.

If your organization restricts service-account creation, ask your Grafana admins for a
read-only token scoped to the folder that holds your Flink alert rules.

**Verify the role before go-live:** with the configured token, a write such as
`POST /api/dashboards/db` must return `403`, while
`GET /api/alertmanager/grafana/api/v2/alerts` returns `200`. A token that can write
can also edit or silence alert rules; the poller never needs that.

### 2. Label your alert rules

Every alert rule the poller should pick up needs a label matching the sidecar's
`FLINK_DEPLOYMENT_NAME` exactly:

```yaml
labels:
  job: <your-flink-cluster>            # or
  flink_deployment: <your-flink-cluster>
```

Keeping the rules in one folder per team makes the token scope and ownership obvious.

### 3. Configure the sidecar

```yaml
env:
  - name: GRAFANA_URL
    value: https://<your-grafana-host>
  - name: GRAFANA_SA_TOKEN
    valueFrom:
      secretKeyRef: { name: flink-ai-debugger-secrets, key: grafana-sa-token }
  - name: FLINK_DEPLOYMENT_NAME
    value: <your-flink-cluster>
  - name: SLACK_BOT_TOKEN
    valueFrom:
      secretKeyRef: { name: flink-ai-debugger-secrets, key: slack-bot-token }
  - name: GRAFANA_ALERT_SLACK_CHANNEL
    value: "#<your-alerts-channel>"
```

The poller starts only when `GRAFANA_URL`, `GRAFANA_SA_TOKEN`, and `FLINK_DEPLOYMENT_NAME`
are all set. Slack setup is in [SLACK_QUICK_SETUP.md](SLACK_QUICK_SETUP.md).

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `GRAFANA_URL` | — | Grafana base URL; unset disables the poller |
| `GRAFANA_SA_TOKEN` | — | Service-account token (read via `SECRET_PROVIDER=env`) |
| `GRAFANA_POLL_INTERVAL` | `60` | Seconds between polls |
| `GRAFANA_POLLER_RE_EVAL_INTERVAL` | `900` | Seconds before a still-firing alert is analyzed again |
| `GRAFANA_ALERT_MODEL` | `claude-opus-4-20250514` | Model for alert analyses |
| `GRAFANA_ALERT_SLACK_CHANNEL` | `SLACK_DEFAULT_CHANNEL` | Channel for alert analyses |

## Troubleshooting

| Symptom (startup log) | Fix |
|---|---|
| `GRAFANA_URL not set — Grafana alert poller disabled` | Set `GRAFANA_URL` |
| `Grafana SA token not configured — alert poller disabled` | Set `GRAFANA_SA_TOKEN` |
| `FLINK_DEPLOYMENT_NAME not set — Grafana poller disabled` | Set it to the `FlinkDeployment` name |
| HTTP 401/403 from Grafana | Token expired or lacks read access to the alert folder |
| Alerts firing but never analyzed | Label value must equal `FLINK_DEPLOYMENT_NAME` exactly |
| Analysis runs, nothing in Slack | Bot not in the channel; see the Slack guide |
