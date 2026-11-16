# Autoscaler Data Source Options

Where should Gaiger read Flink autoscaler history from? The Flink Kubernetes
Operator can keep autoscaler state in two places, and the debugger has a client for each.

## Option A: PostgreSQL (JDBC)

The operator writes autoscaler state and events to PostgreSQL; the debugger reads them
(`app/postgres_client.py`, read-only).

| Pros | Cons |
|---|---|
| History over days/weeks/months | PostgreSQL to run and maintain |
| Survives operator restarts | One-time operator reconfiguration |
| Queryable by Grafana / BI tools | Extra infrastructure dependency |
| Aggregates across clusters | |

Use for: production, trend analysis, audit requirements, long-running jobs.

## Option B: Kubernetes CRD status

The operator stores current state in the `FlinkDeployment` `.status`; the debugger reads
it via the Kubernetes API (`app/kubernetes_client.py`).

| Pros | Cons |
|---|---|
| Zero setup | Current state and recent events only |
| No external dependency | Lost when the `FlinkDeployment` is deleted |
| Native Kubernetes primitives | No long-term trends |

Use for: development, short-lived jobs, minimal infrastructure.

---

## Current implementation

Both clients exist. The agent's `get_autoscaler_info` tool reads from the Kubernetes CRD,
which works with no setup. The `/api/autoscaler/*` REST endpoints read from PostgreSQL when
`POSTGRES_ENABLED=true` and the tables exist.

---

## Switching the agent to PostgreSQL

### 1. Configure the operator for JDBC

Set the operator's autoscaler state-store and event-handler to JDBC (see the Flink
Kubernetes Operator docs for `kubernetes.operator.job.autoscaler.state-store.type` /
`event-handler.type` and the JDBC URL/credential settings), then restart the operator.

### 2. Create the tables

Follow [POSTGRES_SETUP_GUIDE.md](POSTGRES_SETUP_GUIDE.md).

### 3. Point the debugger at the database

```bash
POSTGRES_ENABLED=true
POSTGRES_HOST=<your-postgres-host>
POSTGRES_DB=flink_autoscaler
POSTGRES_USER=<your-db-user>
POSTGRES_PASSWORD=<your-password>
```

### 4. Verify data is arriving

After a few autoscaler evaluation cycles:

```bash
PGSSLMODE=verify-full psql -h <your-postgres-host> -U <your-db-user> -d flink_autoscaler \
     -c 'SELECT COUNT(*) FROM t_flink_autoscaler_state_store;'
```

### 5. Change the tool's data source

In `app/langgraph_agent.py`, the `get_autoscaler_info` tool calls
`k8s.get_comprehensive_autoscaler_info(...)`. Swap in
`await pg.get_comprehensive_autoscaler_info(job_id, hours=hours)`, or use the hybrid below.

---

## Hybrid: PostgreSQL first, CRD fallback

```python
async def get_autoscaler_info(hours: int = 5) -> str:
    job_id = await flink.get_running_job_id()
    try:
        result = await pg.get_comprehensive_autoscaler_info(job_id, hours=hours)
        if result and not result.get("error"):
            return _truncate(result)
    except Exception as e:
        logger.warning("PostgreSQL failed, falling back to Kubernetes: %s", e)

    result = k8s.get_comprehensive_autoscaler_info(job_id, hours=hours)
    return _truncate(result)
```

---

## Decision matrix

| Requirement | PostgreSQL | Kubernetes CRD |
|---|---|---|
| Historical analysis (weeks/months) | yes | no |
| Zero setup | no | yes |
| Survives operator restart | yes | no |
| External tool access | yes | limited |
| Audit / compliance | yes | no |
| Simplest implementation | no | yes |

Recommendation: PostgreSQL for production; CRD for development.
