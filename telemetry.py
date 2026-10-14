import os
import logging
from typing import Optional

from opentelemetry import trace, metrics
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
from opentelemetry.sdk.resources import Resource, SERVICE_NAME
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.exporter.otlp.proto.http.metric_exporter import OTLPMetricExporter

logger = logging.getLogger(__name__)

DEFAULT_OTLP_ENDPOINT = "http://otel-collector.vijil-telemetry.svc.cluster.local:4318"

DEFAULT_SERVICE_NAME = "vijil-travel-agent"

def setup_telemetry(
    otlp_endpoint: Optional[str] = None,
    service_name: Optional[str] = None,
) -> tuple[trace.Tracer, metrics.Meter]:
    endpoint = otlp_endpoint or os.environ.get(
        "OTEL_EXPORTER_OTLP_ENDPOINT", DEFAULT_OTLP_ENDPOINT
    )
    svc_name = service_name or os.environ.get("OTEL_SERVICE_NAME", DEFAULT_SERVICE_NAME)

    logger.info(f"Setting up OTEL telemetry: endpoint={endpoint}, service={svc_name}")

    resource = Resource.create({SERVICE_NAME: svc_name})

    trace_exporter = OTLPSpanExporter(endpoint=f"{endpoint}/v1/traces")
    tracer_provider = TracerProvider(resource=resource)
    tracer_provider.add_span_processor(BatchSpanProcessor(trace_exporter))
    trace.set_tracer_provider(tracer_provider)

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

def get_team_id() -> Optional[str]:
    return os.environ.get("TEAM_ID")
