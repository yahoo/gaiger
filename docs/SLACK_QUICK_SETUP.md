# Slack Integration

The agent posts analysis results to a Slack channel on request ("send this to Slack"),
and the Grafana alert poller posts every alert analysis there automatically.

Requires a Slack app with a bot token. Messages go through `chat.postMessage` using
Block Kit for formatting (see [SLACK_MESSAGE_IMPROVEMENTS.md](SLACK_MESSAGE_IMPROVEMENTS.md)).

## 1. Create the Slack app

1. <https://api.slack.com/apps> → Create New App → From scratch.
2. OAuth & Permissions → Bot Token Scopes → add `chat:write`.
3. Install to Workspace; copy the Bot User OAuth Token (`xoxb-...`).

`chat:write` is the only scope needed. The bot can post only to channels it has joined.

## 2. Create the channel and invite the bot

```
/create #<your-alerts-channel>
/invite @<your-bot-name>
```

## 3. Configure the sidecar

Store the token in a Kubernetes Secret (or whatever your secrets tooling provides) and
expose it as an environment variable:

```yaml
env:
  - name: SLACK_BOT_TOKEN
    valueFrom:
      secretKeyRef: { name: flink-ai-debugger-secrets, key: slack-bot-token }
  - name: SLACK_DEFAULT_CHANNEL
    value: "#<your-alerts-channel>"
```

Local run:

```bash
export SLACK_BOT_TOKEN=xoxb-your-token
export SLACK_DEFAULT_CHANNEL="#<your-alerts-channel>"
```

Both variables are read at startup. Without `SLACK_BOT_TOKEN`, the `send_to_slack` tool
reports Slack as unconfigured and everything else keeps working.

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `SLACK_BOT_TOKEN` | — | Bot token; enables Slack posting |
| `SLACK_DEFAULT_CHANNEL` | — | Channel for reports; bot must be a member |
| `GRAFANA_ALERT_SLACK_CHANNEL` | `SLACK_DEFAULT_CHANNEL` | Separate channel for alert-triggered analyses |

## Verify

Ask in the chat UI:

> Send job status to Slack

A formatted message should appear in `SLACK_DEFAULT_CHANNEL`.

## Troubleshooting

| Error | Fix |
|---|---|
| `not_in_channel` | `/invite` the bot into the target channel |
| `missing_scope` | Add `chat:write` to the bot scopes and reinstall the app |
| `invalid_auth` | Token is wrong, revoked, or from a different workspace |
| `channel_not_found` | Use the channel name with `#` or the channel ID; private channels need the bot invited |
| Nothing posted, no error | `SLACK_BOT_TOKEN` empty at startup; check the pod env |
