# PostgreSQL Table Setup Guide

Optional. Only needed if your Flink Kubernetes Operator autoscaler writes its state and
events to PostgreSQL (JDBC state store / event handler) and you want Gaiger to
read that history. The debugger never writes to these tables.

## Manual setup required

The Flink autoscaler does not create its PostgreSQL tables. Create them before starting
a Flink job with the JDBC autoscaler store enabled.

---

## Quick setup

Every `psql` example sets `PGSSLMODE=verify-full`, so the server certificate and host name are
verified before the password is sent. If your server uses a private CA, also set
`PGSSLROOTCERT=<path-to-ca-bundle>`.

### Option 1: psql, interactive

```bash
PGSSLMODE=verify-full psql -h <your-postgres-host> -p 5432 -U <your-db-user> -d flink_autoscaler

\i POSTGRES_TABLE_SETUP.sql
```

### Option 2: psql, from file

```bash
PGSSLMODE=verify-full psql -h <your-postgres-host> -p 5432 -U <your-db-user> -d flink_autoscaler \
     -f POSTGRES_TABLE_SETUP.sql
```

### Option 3: GUI client (DBeaver / pgAdmin / DataGrip)

1. Connect:
   - Host: `<your-postgres-host>`
   - Port: `5432`
   - Database: `flink_autoscaler`
   - User: `<your-db-user>`
   - Password: `<your-password>`
2. Open `POSTGRES_TABLE_SETUP.sql` and execute it.

---

## Tables created

### 1. `t_flink_autoscaler_state_store`

Autoscaler state: parallelism decisions and metric snapshots.

| Column | Type | Description |
|---|---|---|
| `job_key` | VARCHAR(255), PK | Job identifier |
| `state_value` | TEXT | JSON blob with autoscaler state |
| `update_time` | TIMESTAMP | Last update |

Index: `idx_state_update_time` on `update_time`.

### 2. `t_flink_autoscaler_event_handler`

Autoscaler events: ScalingReport, Normal, Warning, AutoscalerError.

| Column | Type | Description |
|---|---|---|
| `event_key` | VARCHAR(255), PK | Event identifier |
| `job_key` | VARCHAR(255) | Owning job |
| `event_type` | VARCHAR(50) | ScalingReport / Normal / Warning / AutoscalerError |
| `reason` | VARCHAR(255) | Short reason |
| `message` | TEXT | Detailed message |
| `event_count` | INTEGER | Occurrences |
| `create_time` | TIMESTAMP | Created |
| `update_time` | TIMESTAMP | Last update |

Indexes: `idx_event_job_key`, `idx_event_update_time`, `idx_event_type`.

---

## Verification

```sql
-- Tables
SELECT schemaname, tablename, tableowner
FROM pg_tables
WHERE tablename IN ('t_flink_autoscaler_state_store', 't_flink_autoscaler_event_handler');
```

```sql
-- Indexes (expect 2 primary keys + 4 named indexes)
SELECT tablename, indexname
FROM pg_indexes
WHERE tablename IN ('t_flink_autoscaler_state_store', 't_flink_autoscaler_event_handler');
```

```sql
-- Row counts (0 until the autoscaler writes)
SELECT 'state_store' AS table_name, COUNT(*) FROM t_flink_autoscaler_state_store
UNION ALL
SELECT 'event_store' AS table_name, COUNT(*) FROM t_flink_autoscaler_event_handler;
```

---

## Kubernetes Job (optional)

To run the setup in-cluster:

```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: postgres-init
  namespace: <your-namespace>
spec:
  template:
    spec:
      restartPolicy: Never
      containers:
        - name: postgres-init
          image: postgres:15
          command:
            - psql
            - -h
            - <your-postgres-host>
            - -U
            - <your-db-user>
            - -d
            - flink_autoscaler
            - -c
            - |
              CREATE TABLE IF NOT EXISTS t_flink_autoscaler_state_store (
                job_key VARCHAR(255) PRIMARY KEY,
                state_value TEXT NOT NULL,
                update_time TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
              );
              CREATE INDEX IF NOT EXISTS idx_state_update_time ON t_flink_autoscaler_state_store(update_time);

              CREATE TABLE IF NOT EXISTS t_flink_autoscaler_event_handler (
                event_key VARCHAR(255) PRIMARY KEY,
                job_key VARCHAR(255) NOT NULL,
                event_type VARCHAR(50) NOT NULL,
                reason VARCHAR(255),
                message TEXT,
                event_count INTEGER DEFAULT 1,
                create_time TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                update_time TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
              );
              CREATE INDEX IF NOT EXISTS idx_event_job_key ON t_flink_autoscaler_event_handler(job_key);
              CREATE INDEX IF NOT EXISTS idx_event_update_time ON t_flink_autoscaler_event_handler(update_time);
              CREATE INDEX IF NOT EXISTS idx_event_type ON t_flink_autoscaler_event_handler(event_type);
          env:
            # Verify the server certificate and host name; with a private CA,
            # also mount the CA bundle and set PGSSLROOTCERT to its path.
            - name: PGSSLMODE
              value: verify-full
            - name: PGPASSWORD
              valueFrom:
                secretKeyRef:
                  name: postgres-credentials
                  key: password
```

```bash
kubectl apply -f postgres-init-job.yaml
kubectl logs -f job/postgres-init -n <your-namespace>
```

---

## Troubleshooting

| Error | Cause | Fix |
|---|---|---|
| `relation does not exist` | Tables not created | Run the setup SQL |
| `permission denied` | User lacks CREATE | `GRANT CREATE ON DATABASE flink_autoscaler TO <your-admin-user>;` -- run setup as a DDL role; the debugger's own role stays SELECT-only and must exist before `POSTGRES_ENABLED=true` is set |
| `database does not exist` | No database yet | `CREATE DATABASE flink_autoscaler;` |
| Connection timeout | Network / firewall | Check security groups, network policies, and that the pod can reach `<your-postgres-host>:5432` |
| TLS handshake failure | Server has no TLS | The debugger always connects with TLS; enable TLS on the server or terminate it in front |

---

## Testing from Gaiger

```bash
export POSTGRES_ENABLED=true
export POSTGRES_HOST=<your-postgres-host>
export POSTGRES_PORT=5432
export POSTGRES_DB=flink_autoscaler
export POSTGRES_USER=<your-db-user>       # SELECT-only application role
export SECRET_PROVIDER=env                # the built-in provider; see app/secret_provider.py to plug in a backend
export POSTGRES_PASSWORD=<your-password>

SECRET_PROVIDER=env ANTHROPIC_API_KEY=<your-key> python -m app.main

curl http://localhost:8765/api/health
# "postgres": { "connected": true, ... }
```

---

## Summary

1. Create the tables with `POSTGRES_TABLE_SETUP.sql`.
2. Verify with the queries above.
3. Configure the Flink operator autoscaler with the JDBC URL.
4. Start the Flink job; the autoscaler writes state and events.
5. Point Gaiger at the same database (read-only).
