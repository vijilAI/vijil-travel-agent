"""OpenTelemetry setup for Dome telemetry emission.

This module configures OTEL exporters to send traces and metrics to the
Vijil observability stack (Tempo/Mimir via OTEL Collector).

Environment Variables:
    OTEL_EXPORTER_OTLP_ENDPOINT: OTLP collector endpoint
        Default: http://otel-collector.vijil-telemetry.svc.cluster.local:4318
    OTEL_SERVICE_NAME: Service name for traces
        Default: vijil-travel-agent
    TEAM_ID: Team ID for multi-tenant filtering (optional)
"""

import os
import logging
from typing import Any, Optional

from openinference.instrumentation.strands_agents import StrandsAgentsToOpenInferenceProcessor
from opentelemetry import trace, metrics
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, SpanExporter
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
from opentelemetry.sdk.resources import Resource, SERVICE_NAME
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.exporter.otlp.proto.http.metric_exporter import OTLPMetricExporter

logger = logging.getLogger(__name__)


# Default OTEL collector endpoint (inside Kind cluster)
DEFAULT_OTLP_ENDPOINT = "http://otel-collector.vijil-telemetry.svc.cluster.local:4318"

# Default service name
DEFAULT_SERVICE_NAME = "vijil-travel-agent"


def setup_telemetry(
    otlp_endpoint: Optional[str] = None,
    service_name: Optional[str] = None,
) -> tuple[trace.Tracer, metrics.Meter]:
    """Set up OpenTelemetry tracing and metrics exporters.

    Configures OTLP HTTP exporters to send telemetry to the observability stack.
    The endpoint defaults to the in-cluster OTEL Collector service.

    Args:
        otlp_endpoint: OTLP collector endpoint (default: from env or cluster URL)
        service_name: Service name for resource attributes

    Returns:
        Tuple of (Tracer, Meter) for creating spans and metrics
    """
    endpoint = otlp_endpoint or os.environ.get(
        "OTEL_EXPORTER_OTLP_ENDPOINT", DEFAULT_OTLP_ENDPOINT
    )
    svc_name = service_name or os.environ.get("OTEL_SERVICE_NAME", DEFAULT_SERVICE_NAME)

    logger.info(f"Setting up OTEL telemetry: endpoint={endpoint}, service={svc_name}")

    resource = Resource.create({SERVICE_NAME: svc_name})

    # Set up tracing
    trace_exporter = OTLPSpanExporter(endpoint=f"{endpoint}/v1/traces")
    trace.set_tracer_provider(build_tracer_provider(resource, trace_exporter))

    # Set up metrics
    metric_exporter = OTLPMetricExporter(endpoint=f"{endpoint}/v1/metrics")
    metric_reader = PeriodicExportingMetricReader(
        metric_exporter,
        export_interval_millis=5000,
    )
    meter_provider = MeterProvider(resource=resource, metric_readers=[metric_reader])
    metrics.set_meter_provider(meter_provider)

    tracer = trace.get_tracer(svc_name)
    meter = metrics.get_meter(svc_name)

    logger.info("OTEL telemetry setup complete")
    return tracer, meter


def build_tracer_provider(resource: Resource, span_exporter: SpanExporter) -> TracerProvider:
    """Build a tracer provider that exports Strands spans with OpenInference kinds.

    The OpenInference processor rewrites Strands span attributes in place when a
    span ends, so it is added before the exporting processor; added after, the
    exporter would ship the spans unconverted.
    """
    tracer_provider = TracerProvider(resource=resource)
    tracer_provider.add_span_processor(StrandsAgentsToOpenInferenceProcessor())
    tracer_provider.add_span_processor(BatchSpanProcessor(span_exporter))
    return tracer_provider


def instrument_inbound_requests(app: Any, tracer_provider: Optional[trace.TracerProvider] = None) -> None:
    """Open a server span per request that continues the caller's W3C traceparent.

    Without this, a caller's trace cannot join the agent's spans. The default
    tracer_provider is the global one that setup_telemetry installs.
    """
    FastAPIInstrumentor.instrument_app(app, tracer_provider=tracer_provider)


def get_team_id() -> Optional[str]:
    """Get team ID from environment for multi-tenant filtering."""
    return os.environ.get("TEAM_ID")
