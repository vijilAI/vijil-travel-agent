"""Inbound trace context joins the agent's spans, and Strands spans export with OpenInference kinds."""

import pytest
from fastapi.testclient import TestClient
from openinference.instrumentation.strands_agents import StrandsAgentsToOpenInferenceProcessor
from opentelemetry import trace
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.trace import SpanKind

import agent
import telemetry

# A caller's W3C trace context: version-traceid-parentid-flags.
CALLER_TRACE_ID = "4bf92f3577b34da6a3ce929d0e0e4736"
CALLER_SPAN_ID = "00f067aa0ba902b7"
TRACEPARENT = f"00-{CALLER_TRACE_ID}-{CALLER_SPAN_ID}-01"

# Any value enables telemetry; setup_telemetry is replaced, so nothing is sent here.
OTEL_ENV = {"OTEL_EXPORTER_OTLP_ENDPOINT": "http://127.0.0.1:4318"}


@pytest.fixture
def spans(monkeypatch) -> InMemorySpanExporter:
    """Replace setup_telemetry with one that installs an in-memory global tracer provider.

    The real setup_telemetry installs an OTLP-exporting global provider, which OTel
    lets a process set only once. Until the fake runs, the global provider stays
    unconfigured, as it does in a process started without OTEL.
    """
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    monkeypatch.setattr(trace, "_TRACER_PROVIDER", None)

    def install_in_memory_provider(otlp_endpoint):
        monkeypatch.setattr(trace, "_TRACER_PROVIDER", provider)
        return provider.get_tracer("test"), object()

    monkeypatch.setattr(telemetry, "setup_telemetry", install_in_memory_provider)
    return exporter


def _get_agent_card(app) -> None:
    response = TestClient(app).get("/.well-known/agent-card.json", headers={"traceparent": TRACEPARENT})
    assert response.status_code == 200


def _server_spans(exporter: InMemorySpanExporter) -> list:
    return [s for s in exporter.get_finished_spans() if s.kind is SpanKind.SERVER]


def test_inbound_traceparent_trace_id_is_on_the_agent_server_span(spans):
    app = agent.create_concurrent_a2a_app(agent.create_agent)

    tracer, meter = agent.configure_telemetry(app, OTEL_ENV)
    _get_agent_card(app)

    assert tracer is not None and meter is not None
    # The span asserts below check the outcome. FastAPI releases with native tracing
    # meet them once a global provider is set, even without the instrumentor; older
    # releases do not, so this flag is what pins the instrumentor itself.
    assert getattr(app, "_is_instrumented_by_opentelemetry", False)
    server_spans = _server_spans(spans)
    assert len(server_spans) == 1
    assert format(server_spans[0].context.trace_id, "032x") == CALLER_TRACE_ID
    assert server_spans[0].parent is not None
    assert format(server_spans[0].parent.span_id, "016x") == CALLER_SPAN_ID


def test_without_otel_endpoint_telemetry_is_off_and_no_server_span_is_recorded(spans):
    app = agent.create_concurrent_a2a_app(agent.create_agent)

    tracer, meter = agent.configure_telemetry(app, {})
    _get_agent_card(app)

    assert (tracer, meter) == (None, None)
    assert not getattr(app, "_is_instrumented_by_opentelemetry", False)
    assert _server_spans(spans) == []


def test_failed_telemetry_setup_leaves_the_app_uninstrumented(spans, monkeypatch):
    def failing_setup(otlp_endpoint):
        raise RuntimeError("collector config rejected")

    monkeypatch.setattr(telemetry, "setup_telemetry", failing_setup)
    app = agent.create_concurrent_a2a_app(agent.create_agent)

    tracer, meter = agent.configure_telemetry(app, OTEL_ENV)
    _get_agent_card(app)

    assert (tracer, meter) == (None, None)
    assert not getattr(app, "_is_instrumented_by_opentelemetry", False)
    assert _server_spans(spans) == []


def test_instrumentation_failure_keeps_telemetry_enabled(spans, monkeypatch):
    def failing_instrument(app):
        raise RuntimeError("middleware stack already built")

    monkeypatch.setattr(telemetry, "instrument_inbound_requests", failing_instrument)
    app = agent.create_concurrent_a2a_app(agent.create_agent)

    tracer, meter = agent.configure_telemetry(app, OTEL_ENV)

    # setup_telemetry already installed exporting providers, so telemetry is on.
    assert tracer is not None and meter is not None


def test_strands_tool_span_exports_with_openinference_tool_kind():
    exporter = InMemorySpanExporter()
    provider = telemetry.build_tracer_provider(Resource.create({}), exporter)

    with provider.get_tracer("strands").start_as_current_span(
        "execute_tool search_flights", attributes={"gen_ai.system": "strands-agents"}
    ):
        pass
    provider.force_flush()

    processors = provider._active_span_processor._span_processors
    assert isinstance(processors[0], StrandsAgentsToOpenInferenceProcessor)
    [exported] = exporter.get_finished_spans()
    assert exported.attributes["openinference.span.kind"] == "TOOL"
