# Copyright Yahoo, Licensed under the terms of the Apache 2.0 license. See LICENSE for terms.

"""OpenTelemetry setup for the AI debugger — app metrics + agent tracing.

Signals are exported OTLP/gRPC to the in-pod otel-collector (default 127.0.0.1:4317),
which forwards them to the cluster o11y gateway. Everything here is best-effort: an
absent or UNREACHABLE collector must never block startup or fail a request.

One deliberate exception to best-effort: the collector DESTINATION is validated
against the egress policy (app.egress_policy) before any exporter is built, and a
violation raises out of setup_telemetry and fails startup. Plaintext ("insecure")
gRPC is used only when the resolved endpoint host is actually loopback — the
intra-pod hop — never assumed. A deployment that repoints
OTEL_EXPORTER_OTLP_ENDPOINT off-box must use https (and pass the allowlist, when
set), otherwise the pod refuses to start instead of silently streaming spans and
metrics off-box in cleartext.

Tracing is configured CONTENT-CAPTURE-OFF: agent/LLM spans carry structure, timing,
and token counts only — never the operator's question or the agent's answer — because
the spans leave the pod for a shared observability backend.

Opt out entirely with OTEL_SDK_DISABLED=true (e.g. local dev without a collector).
Override the collector with OTEL_EXPORTER_OTLP_ENDPOINT.
"""
import logging
import os
from typing import Optional, Tuple
from urllib.parse import urlparse

from app.egress_policy import is_loopback, validate_destination

logger = logging.getLogger(__name__)

_ENABLED = False
_instruments: dict = {}


def _endpoint() -> str:
    return os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4317")


def _validated_endpoint() -> Tuple[str, bool]:
    """Validate the OTLP destination and derive the transport security mode.

    Returns (endpoint, insecure). insecure (plaintext gRPC) is permitted ONLY
    when the resolved host is actually loopback — the manifest's intra-pod-hop
    argument — instead of being asserted unconditionally. Raises
    EgressPolicyError on a violation: a policy breach must fail startup
    (fail closed), unlike a merely-unreachable collector.
    """
    endpoint = validate_destination(
        _endpoint(), name="OTEL_EXPORTER_OTLP_ENDPOINT",
        require_https=True, allow_loopback=True,
    )
    return endpoint, is_loopback(urlparse(endpoint).hostname or "")


def setup_telemetry(fastapi_app) -> bool:
    """Initialize metrics + tracing. Idempotent, best-effort — never raises,
    EXCEPT for an egress-policy violation on the OTLP endpoint, which must
    fail startup (see module docstring).

    Returns True if telemetry was enabled."""
    global _ENABLED
    if _ENABLED:
        return True
    if os.getenv("OTEL_SDK_DISABLED", "").lower() in ("1", "true", "yes"):
        logger.info("OpenTelemetry disabled via OTEL_SDK_DISABLED")
        return False
    # Egress-policy check runs OUTSIDE the best-effort try below: an endpoint
    # that violates the policy must fail startup, not degrade to "telemetry
    # disabled" while the misconfiguration goes unnoticed.
    endpoint, insecure = _validated_endpoint()
    try:
        from opentelemetry import metrics, trace
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.metrics import MeterProvider
        from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
        from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import OTLPMetricExporter
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter

        service_name = (
            os.getenv("OTEL_SERVICE_NAME")
            or os.getenv("FLINK_DEPLOYMENT_NAME")
            or "flink-ai-debugger"
        )
        resource = Resource.create({"service.name": service_name})

        # Metrics: OTLP/gRPC to the collector. `insecure` (plaintext) is derived
        # from the endpoint actually being loopback — never asserted (TLS at the
        # gateway hop covers the onward leg of the intra-pod default).
        reader = PeriodicExportingMetricReader(OTLPMetricExporter(endpoint=endpoint, insecure=insecure))
        metrics.set_meter_provider(MeterProvider(resource=resource, metric_readers=[reader]))

        # Tracing
        tracer_provider = TracerProvider(resource=resource)
        tracer_provider.add_span_processor(
            BatchSpanProcessor(OTLPSpanExporter(endpoint=endpoint, insecure=insecure))
        )
        trace.set_tracer_provider(tracer_provider)

        _init_instruments()
        _instrument_fastapi(fastapi_app)
        _instrument_langchain(tracer_provider)

        _ENABLED = True
        logger.info(
            "OpenTelemetry enabled — metrics+traces → %s (service.name=%s, content-capture OFF)",
            endpoint, service_name,
        )
        return True
    except Exception as e:
        logger.warning("OpenTelemetry setup failed — metrics/tracing disabled, app continues: %s", e)
        return False


def _init_instruments() -> None:
    from opentelemetry import metrics
    meter = metrics.get_meter("flink-ai-debugger")
    _instruments["ai_queries_total"] = meter.create_counter(
        "ai_queries_total", unit="1",
        description="AI /api/query invocations, labelled by status and mode",
    )
    _instruments["ai_query_duration_seconds"] = meter.create_histogram(
        "ai_query_duration_seconds", unit="s",
        description="AI query wall-clock duration",
    )
    _instruments["webhook_requests_total"] = meter.create_counter(
        "webhook_requests_total", unit="1",
        description="Inbound alert/webhook analyses, labelled by source and outcome",
    )
    _instruments["remediations_applied_total"] = meter.create_counter(
        "remediations_applied_total", unit="1",
        description="Remediation attempts, labelled by type, dry_run, and status",
    )


def _instrument_fastapi(fastapi_app) -> None:
    try:
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
        FastAPIInstrumentor.instrument_app(fastapi_app)
    except Exception as e:
        logger.warning("FastAPI OTel instrumentation skipped: %s", e)


def _instrument_langchain(tracer_provider) -> None:
    # Content capture OFF. hide_inputs/hide_outputs redact the top-level input/output
    # VALUES, but per-message content (llm.input_messages.*.message.content), tool-call
    # args/results, and free text are governed by the GRANULAR flags — so set all of them
    # to guarantee no prompt/completion/tool content ever leaves for the shared o11y
    # backend, regardless of the resolved openinference version. Env vars are the
    # version-safe source of truth (unknown env vars are ignored) and TraceConfig() reads
    # them by default.
    #
    # FORCE-set (not setdefault): spans cross the pod trust boundary to the shared o11y
    # gateway, so content-off is a security control, not a tunable default. An
    # OPENINFERENCE_HIDE_*=false in a deployment manifest must never be able to re-enable
    # prompt/completion capture.
    for _flag in (
        "OPENINFERENCE_HIDE_INPUTS", "OPENINFERENCE_HIDE_OUTPUTS",
        "OPENINFERENCE_HIDE_INPUT_MESSAGES", "OPENINFERENCE_HIDE_OUTPUT_MESSAGES",
        "OPENINFERENCE_HIDE_INPUT_TEXT", "OPENINFERENCE_HIDE_OUTPUT_TEXT",
    ):
        os.environ[_flag] = "true"
    try:
        from openinference.instrumentation.langchain import LangChainInstrumentor
        try:
            from openinference.instrumentation import TraceConfig
            config = TraceConfig(hide_inputs=True, hide_outputs=True)
            LangChainInstrumentor().instrument(tracer_provider=tracer_provider, config=config)
        except Exception:
            # Older openinference without TraceConfig — the env vars above still hide content.
            LangChainInstrumentor().instrument(tracer_provider=tracer_provider)
    except Exception as e:
        logger.warning("LangChain OTel instrumentation skipped: %s", e)


# ── Safe record helpers (no-op when telemetry is disabled or on any error) ──

def record_query(status: str, mode: str, duration_s: Optional[float] = None) -> None:
    if not _ENABLED:
        return
    try:
        _instruments["ai_queries_total"].add(1, {"status": status, "mode": mode})
        if duration_s is not None:
            _instruments["ai_query_duration_seconds"].record(duration_s, {"status": status, "mode": mode})
    except Exception:
        pass


def record_webhook(source: str, outcome: str) -> None:
    if not _ENABLED:
        return
    try:
        _instruments["webhook_requests_total"].add(1, {"source": source, "outcome": outcome})
    except Exception:
        pass


def record_remediation(remediation_type: str, dry_run: bool, status: str) -> None:
    if not _ENABLED:
        return
    try:
        _instruments["remediations_applied_total"].add(
            1, {"type": remediation_type, "dry_run": str(bool(dry_run)).lower(), "status": status}
        )
    except Exception:
        pass
