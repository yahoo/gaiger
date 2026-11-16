#!/usr/bin/env bash
# Debug Flink connection issues in Kubernetes.
#
# Usage: ./DEBUG_FLINK_CONNECTION.sh <DEPLOYMENT> [NAMESPACE]
#        FLINK_DEPLOYMENT_NAME=<name> ./DEBUG_FLINK_CONNECTION.sh
#
#   DEPLOYMENT  FlinkDeployment whose JobManager to inspect. Required (positional
#               or $FLINK_DEPLOYMENT_NAME -- the same variable the sidecar itself
#               reads, so a sidecar env block can be sourced as-is); there is
#               deliberately no default -- the script must not guess which
#               cluster it is debugging. The pod is resolved by label selector
#               to the first READY JobManager; never hardcode a pod instance, it
#               goes stale on the next reschedule.
#   NAMESPACE   Kubernetes namespace. Defaults to "default".
#
#   POD_NAME=<pod> ./DEBUG_FLINK_CONNECTION.sh <DEPLOYMENT>  # bypass resolution
#   DEBUG=1 ./DEBUG_FLINK_CONNECTION.sh <DEPLOYMENT>         # trace (set -x)
#
# Strict mode: any failing kubectl command aborts immediately with a non-zero
# exit, so a stale pod/container reference can no longer print five confident
# section headings over output that never ran. The connectivity curl probes are
# the one deliberate exception: a failing probe IS the diagnosis in a
# connection-debug script, so those report the failure and continue.
set -euo pipefail

if [[ "${DEBUG:-0}" == "1" ]]; then
    set -x
fi

# set -x traces every `VAR="$(...)"` assignment WITH its value. For the two
# captures below that value is the sidecar's whole environment / its log tail,
# either of which may carry env-provided secrets, so tracing is suspended
# around them and restored afterwards. The `{ ...; } 2>/dev/null` keeps the
# `set +x` itself out of the trace.
trace_off() { { set +x; } 2> /dev/null; }
trace_on() {
    if [[ "${DEBUG:-0}" == "1" ]]; then
        set -x
    fi
}

usage() {
    echo "Usage: $0 <DEPLOYMENT> [NAMESPACE]" >&2
    echo "       FLINK_DEPLOYMENT_NAME=<name> $0" >&2
    echo "  DEPLOYMENT  FlinkDeployment name (required; no default -- the script does not guess)" >&2
    echo "  NAMESPACE   defaults to 'default'" >&2
}

# Every value this script hands to kubectl -- positionals AND environment
# overrides -- must not be parseable as a kubectl flag.
reject_flag_like() {
    local what="${1}" value="${2}"
    if [[ "${value}" == -* ]]; then
        echo "ERROR: ${what} must not start with '-' (got '${value}')." >&2
        usage
        exit 2
    fi
}

# Exactly two optional positionals; a third would be silently dropped otherwise
# (a typo'd namespace would then debug the wrong cluster without saying so).
if (( $# > 2 )); then
    echo "ERROR: too many arguments ($#)." >&2
    usage
    exit 2
fi

for arg in "$@"; do
    reject_flag_like "arguments" "${arg}"
done

# Under strict mode a missing kubectl would already abort (exit 127), but with
# a bare "command not found" instead of a diagnosis. Say what is missing.
if ! command -v kubectl > /dev/null 2>&1; then
    echo "ERROR: kubectl not found on PATH; this script only wraps kubectl." >&2
    exit 127
fi

NAMESPACE="${2:-default}"

# Which FlinkDeployment: positional first, $FLINK_DEPLOYMENT_NAME second, and
# deliberately NO default -- a debug script that guesses its target debugs the
# wrong cluster with confidence. Fail closed with usage instead.
DEPLOYMENT="${1:-${FLINK_DEPLOYMENT_NAME:-}}"
if [[ -z "${DEPLOYMENT}" ]]; then
    echo "ERROR: no FlinkDeployment given (positional DEPLOYMENT or FLINK_DEPLOYMENT_NAME env)." >&2
    usage
    exit 2
fi
# The env-sourced values get the same flag check as the positionals.
reject_flag_like "FLINK_DEPLOYMENT_NAME" "${DEPLOYMENT}"
reject_flag_like "POD_NAME" "${POD_NAME:-}"

# The Flink Kubernetes operator labels every pod app=<FlinkDeployment name>,
# component=jobmanager|taskmanager, type=flink-native-kubernetes (verified
# against a live operator-managed deployment).
# component=jobmanager narrows the match to the JobManager pod, the only pod
# carrying the debugger sidecar.
#
# With JobManager HA there can be two matching pods; a terminating or
# not-yet-started one would make every exec below fail for the wrong reason.
# List "<name> <Ready-condition>" per pod and take the first that is Ready.
# Under pipefail a failing kubectl still aborts here (awk's status is masked
# only when kubectl itself succeeded). POD_NAME in the environment bypasses
# resolution for the case where you need to look at a specific (e.g. not
# Ready) pod.
POD_NAME="${POD_NAME:-$(kubectl get pod -n "${NAMESPACE}" \
    -l "app=${DEPLOYMENT},component=jobmanager" \
    -o jsonpath='{range .items[*]}{.metadata.name}{" "}{.status.conditions[?(@.type=="Ready")].status}{"\n"}{end}' \
    | awk '$2 == "True" { print $1; exit }')}"

if [[ -z "${POD_NAME}" ]]; then
    echo "ERROR: no Ready JobManager pod found for app=${DEPLOYMENT} in namespace ${NAMESPACE}." >&2
    echo "       (check the FlinkDeployment name, or set POD_NAME=<pod> to bypass resolution)" >&2
    exit 1
fi

# Container name per the same manifest. NOT "flink-ai-debugger-sidecar": the
# manifest defines no container of that name, and a kubectl exec -c using it
# fails on every call.
CONTAINER="ai-debugger-sidecar"

# Every in-pod curl is bounded: a JobManager that accepts the TCP connection
# and then hangs must not hang the diagnosis with it.
CURL_TIMEOUTS=(--connect-timeout 5 --max-time 20)

echo "Debugging pod '${POD_NAME}' (container '${CONTAINER}') in namespace '${NAMESPACE}'"

echo ""
echo "=== Checking AI Debugger Environment ==="
# Capture first, grep second: if kubectl exec fails, strict mode aborts loudly
# HERE, instead of a piped grep turning the failure into "no FLINK/SSL
# variables" output that is indistinguishable from "the command never ran".
# The capture runs untraced (see trace_off), and only variables whose NAME
# mentions FLINK or SSL are printed; of those, anything that looks like a
# credential (PASSWORD/SECRET/TOKEN/KEY/CREDENTIAL in the name) has its value
# redacted. The rest of the sidecar environment never reaches the terminal.
trace_off
ENV_OUT="$(kubectl exec -n "${NAMESPACE}" "${POD_NAME}" -c "${CONTAINER}" -- env)"
ENV_MATCHES="$(grep -E '^[^=]*(FLINK|SSL)[^=]*=' <<< "${ENV_OUT}" || true)"
if [[ -n "${ENV_MATCHES}" ]]; then
    sed -E 's/^([^=]*(PASSWORD|SECRET|TOKEN|KEY|CREDENTIAL)[^=]*)=.*$/\1=<redacted>/' <<< "${ENV_MATCHES}"
else
    echo "No FLINK/SSL environment variables set."
fi
unset ENV_OUT ENV_MATCHES
trace_on

echo ""
echo "=== Checking if Flink container is running ==="
kubectl get pod -n "${NAMESPACE}" "${POD_NAME}" -o jsonpath='{.status.containerStatuses[*].name}'
echo ""
kubectl get pod -n "${NAMESPACE}" "${POD_NAME}" -o jsonpath='{.status.containerStatuses[?(@.name=="flink-main-container")].ready}'

echo ""
echo "=== Testing connection from sidecar to Flink ==="
# curl -k below is deliberate and is safe ONLY here: these curls run INSIDE the
# target pod against https://localhost:8081, in the pod's own network namespace,
# so there is no network position from which to interpose on the connection.
# Why -k is needed at all: a hardened FlinkDeployment sets
# security.ssl.rest.enabled=true (spec.flinkConfiguration) with a keystore
# whose certificate CN is the service identity issued by the platform's
# certificate authority, not "localhost". A curl to https://localhost:8081
# therefore fails hostname verification even with that CA trusted; -k skips
# that check for this loopback probe.
# DO NOT copy -k to any call that leaves the pod.
echo "Testing HTTP:"
kubectl exec -n "${NAMESPACE}" "${POD_NAME}" -c "${CONTAINER}" -- \
    curl -s "${CURL_TIMEOUTS[@]}" -o /dev/null -w "HTTP: %{http_code}\n" http://localhost:8081 2>&1 \
    || echo "HTTP probe failed (expected when REST SSL is enabled: the JM redirects/refuses plain HTTP)"

echo "Testing HTTPS:"
kubectl exec -n "${NAMESPACE}" "${POD_NAME}" -c "${CONTAINER}" -- \
    curl -s -k "${CURL_TIMEOUTS[@]}" -o /dev/null -w "HTTPS: %{http_code}\n" https://localhost:8081 2>&1 \
    || echo "HTTPS probe failed (unexpected with REST SSL enabled; check the flink-main-container is Ready)"

echo ""
echo "=== Checking Flink REST API ==="
# In-pod localhost call; -k is justified by the comment above and, exactly as
# there, must not be copied to any call that leaves the pod.
# Capture, then truncate: with `... | head -20 || echo`, head closing the pipe
# early on a >20-line response made the pipeline fail under pipefail and
# printed a false "probe failed". Now the exit status is curl's alone.
if OVERVIEW="$(kubectl exec -n "${NAMESPACE}" "${POD_NAME}" -c "${CONTAINER}" -- \
    curl -s -k "${CURL_TIMEOUTS[@]}" https://localhost:8081/v1/overview 2>&1)"; then
    head -20 <<< "${OVERVIEW}"
else
    printf '%s\n' "${OVERVIEW}"
    echo "HTTPS REST API probe failed (see the HTTPS probe above)"
fi

echo ""
echo "=== Checking AI Debugger logs for errors ==="
# Capture first (strict mode aborts if kubectl itself fails), then check
# explicitly: with the old `kubectl logs | grep -i error`, the pipeline's exit
# status came from grep, so "no errors found" and "kubectl never ran" were
# indistinguishable. Untraced for the same reason as the env capture: the log
# tail is not something set -x should echo wholesale to stderr.
trace_off
LOG_OUT="$(kubectl logs -n "${NAMESPACE}" "${POD_NAME}" -c "${CONTAINER}" --tail=30)"
grep -i error <<< "${LOG_OUT}" || echo "No 'error' lines in the last 30 log lines."
unset LOG_OUT
trace_on
