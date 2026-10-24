"""Provider, Dome mode, and certificate settings come from the environment."""

import asyncio
import sys
import threading
import types
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
from fastapi.testclient import TestClient

import agent

GROQ_BASE_URL = "https://api.groq.com/openai/v1"
GROQ_MODEL_ID = "llama-3.1-8b-instant"

# Not a real token: three dot-separated segments, the shape of a compact JWS.
FAKE_JWS = "eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJ0ZXN0In0.c2lnbmF0dXJl"


@pytest.fixture(autouse=True)
def _empty_database(monkeypatch, tmp_path):
    """Point create_agent's config loaders at an empty file, not whatever DB_PATH an earlier test left."""
    import db.connection

    monkeypatch.setattr(db.connection, "DB_PATH", tmp_path / "env_config.db")


def _model_of(monkeypatch, **env):
    for name in ("AGENT_BASE_URL", "AGENT_MODEL_ID", "AGENT_API_KEY"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("GROQ_API_KEY", "groq-key-for-test")
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    return agent.create_agent().model


def test_agent_model_uses_endpoint_and_model_id_from_env(monkeypatch):
    model = _model_of(
        monkeypatch,
        AGENT_BASE_URL="http://llm-gateway.example:8080/v1",
        AGENT_MODEL_ID="proxied-model",
        AGENT_API_KEY="gateway-key-for-test",
    )

    assert model.get_config()["model_id"] == "proxied-model"
    assert model.client_args["base_url"] == "http://llm-gateway.example:8080/v1"


def test_agent_model_defaults_to_groq_llama(monkeypatch):
    model = _model_of(monkeypatch)

    assert model.get_config()["model_id"] == GROQ_MODEL_ID
    assert model.client_args["base_url"] == GROQ_BASE_URL
    assert model.client_args["api_key"] == "groq-key-for-test"


def test_agent_model_uses_agent_api_key_not_groq_key_for_custom_endpoint(monkeypatch):
    model = _model_of(
        monkeypatch,
        AGENT_BASE_URL="http://llm-gateway.example:8080/v1",
        AGENT_API_KEY="gateway-key-for-test",
    )

    assert model.client_args["api_key"] == "gateway-key-for-test"


@pytest.mark.parametrize("blank", [None, "", "  \t"])
def test_custom_endpoint_without_agent_api_key_is_an_explicit_error(monkeypatch, blank):
    env = {"AGENT_BASE_URL": "http://llm-gateway.example:8080/v1"}
    if blank is not None:
        env["AGENT_API_KEY"] = blank

    with pytest.raises(agent.ModelConfigError, match="AGENT_API_KEY"):
        _model_of(monkeypatch, **env)


def test_main_refuses_to_start_when_custom_endpoint_has_no_agent_api_key(monkeypatch):
    monkeypatch.setenv("AGENT_BASE_URL", "http://llm-gateway.example:8080/v1")
    monkeypatch.delenv("AGENT_API_KEY", raising=False)

    with pytest.raises(agent.ModelConfigError, match="AGENT_API_KEY"):
        _run_main_with(monkeypatch, "off")


def test_default_endpoint_ignores_agent_api_key(monkeypatch):
    monkeypatch.setenv("AGENT_API_KEY", "gateway-key-for-test")

    model = _model_of(monkeypatch)

    assert model.client_args["api_key"] == "groq-key-for-test"


@pytest.mark.parametrize("blank", [None, "", "  \t"])
def test_default_endpoint_without_groq_key_is_an_explicit_error(blank):
    # A None key lets the OpenAI SDK fall back to OPENAI_API_KEY and send it to Groq.
    env = {"OPENAI_API_KEY": "openai-key-that-must-not-reach-groq"}
    if blank is not None:
        env["GROQ_API_KEY"] = blank

    with pytest.raises(agent.ModelConfigError, match="GROQ_API_KEY"):
        agent.resolve_model_settings(env)


def test_request_to_custom_host_carries_agent_api_key_and_never_the_groq_key(monkeypatch):
    seen_headers: list[dict[str, str]] = []

    class _Handler(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802 - http.server API
            seen_headers.append({k.lower(): v for k, v in self.headers.items()})
            self.send_response(401)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"{}")

        def log_message(self, *args):
            return None

    server = HTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        model = _model_of(
            monkeypatch,
            AGENT_BASE_URL=f"http://127.0.0.1:{server.server_port}/v1",
            AGENT_API_KEY="gateway-key-for-test",
        )

        async def _call():
            async for _ in model.stream([{"role": "user", "content": [{"text": "hi"}]}]):
                pass

        with pytest.raises(Exception):  # noqa: B017 - the fake host answers 401; only the request matters
            asyncio.run(_call())
    finally:
        server.shutdown()
        server.server_close()

    assert len(seen_headers) == 1
    assert seen_headers[0]["authorization"] == "Bearer gateway-key-for-test"
    assert "groq-key-for-test" not in " ".join(seen_headers[0].values())


@pytest.mark.parametrize("blank", ["", " ", "  \t\n"])
def test_blank_provider_env_falls_back_to_defaults(monkeypatch, blank):
    model = _model_of(monkeypatch, AGENT_BASE_URL=blank, AGENT_MODEL_ID=blank)

    assert model.get_config()["model_id"] == GROQ_MODEL_ID
    assert model.client_args["base_url"] == GROQ_BASE_URL


@pytest.mark.parametrize(
    ("environ", "expected"),
    [
        ({}, "off"),
        ({"DOME_MODE": "off"}, "off"),
        ({"DOME_MODE": "shadow"}, "shadow"),
        ({"DOME_MODE": "enforce"}, "enforce"),
        # Legacy toggle: 1 enforces, anything else leaves Dome off, as before.
        ({"DOME_ENABLED": "1"}, "enforce"),
        ({"DOME_ENABLED": "0"}, "off"),
        ({"DOME_ENABLED": "true"}, "off"),
        # DOME_MODE wins over the legacy toggle; blank counts as unset.
        ({"DOME_MODE": "shadow", "DOME_ENABLED": "1"}, "shadow"),
        ({"DOME_MODE": "", "DOME_ENABLED": "1"}, "enforce"),
    ],
)
def test_resolve_dome_mode(environ, expected):
    assert agent.resolve_dome_mode(environ) == expected


@pytest.mark.parametrize("raw", ["enforced", "ON", "1", "true"])
def test_unknown_dome_mode_is_rejected_not_treated_as_off(raw):
    with pytest.raises(ValueError, match="DOME_MODE"):
        agent.resolve_dome_mode({"DOME_MODE": raw})


class _RecordingDome:
    """Stands in for vijil_dome.Dome; records how main() constructs it."""

    instances: list["_RecordingDome"] = []

    def __init__(self, config, enforce=True):
        self.enforce = enforce
        _RecordingDome.instances.append(self)


_CONSOLE_NOTIFICATIONS: list[str] = []


class _RecordingHookProvider:
    def __init__(self, dome, agent_id=None, team_id=None):
        self.dome = dome


def _run_main_with(monkeypatch, mode_name: str) -> list[_RecordingDome]:
    """Run main() up to uvicorn with a fake vijil_dome; return the Dome instances built."""
    mode = agent.DomeMode(mode_name)
    _RecordingDome.instances = []
    fake_dome = types.ModuleType("vijil_dome")
    fake_dome.Dome = _RecordingDome
    fake_strands = types.ModuleType("vijil_dome.integrations.strands")
    fake_strands.DomeHookProvider = _RecordingHookProvider
    monkeypatch.setitem(sys.modules, "vijil_dome", fake_dome)
    monkeypatch.setitem(sys.modules, "vijil_dome.integrations", types.ModuleType("vijil_dome.integrations"))
    monkeypatch.setitem(sys.modules, "vijil_dome.integrations.strands", fake_strands)

    async def _no_op():
        return None

    seed_module = types.ModuleType("db.seed_data")
    seed_module.seed_data = _no_op
    monkeypatch.setitem(sys.modules, "db.seed_data", seed_module)
    monkeypatch.setattr(agent, "init_db", _no_op)
    monkeypatch.setattr(agent.uvicorn, "run", lambda *args, **kwargs: None)
    monkeypatch.setattr(agent, "DOME_MODE", mode)
    monkeypatch.setattr(agent, "DOME_ENABLED", mode is not agent.DomeMode.OFF)
    monkeypatch.setattr(agent, "_dome_hooks", None)
    _CONSOLE_NOTIFICATIONS.clear()
    monkeypatch.setattr(agent, "_notify_console_dome_active", lambda: _CONSOLE_NOTIFICATIONS.append("domed"))
    monkeypatch.delenv("GENOME_PATH", raising=False)
    monkeypatch.delenv("OTEL_EXPORTER_OTLP_ENDPOINT", raising=False)

    agent.main()
    return _RecordingDome.instances


def test_main_builds_an_enforcing_dome_in_enforce_mode(monkeypatch):
    instances = _run_main_with(monkeypatch, "enforce")

    assert [d.enforce for d in instances] == [True]


def test_main_builds_a_non_enforcing_dome_in_shadow_mode(monkeypatch):
    instances = _run_main_with(monkeypatch, "shadow")

    assert [d.enforce for d in instances] == [False]


def test_main_builds_no_dome_when_mode_is_off(monkeypatch):
    instances = _run_main_with(monkeypatch, "off")

    assert instances == []
    assert agent._dome_hooks is None


def _agent_card_json(monkeypatch, **env) -> dict:
    monkeypatch.delenv("VIJIL_CERTIFICATE_JWS", raising=False)
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    app = agent.create_concurrent_a2a_app(agent.create_agent)
    return TestClient(app).get("/.well-known/agent-card.json").json()


def test_certificate_from_env_is_embedded_in_the_agent_card_extension(monkeypatch):
    card = _agent_card_json(monkeypatch, VIJIL_CERTIFICATE_JWS=FAKE_JWS)

    extensions = card["capabilities"]["extensions"]
    assert len(extensions) == 1
    assert extensions[0]["uri"] == agent.VIJIL_CERTIFICATE_EXTENSION_URI
    assert extensions[0]["params"] == {"jws": FAKE_JWS}
    assert extensions[0]["required"] is False


def test_agent_card_has_no_extension_when_certificate_is_unset(monkeypatch):
    card = _agent_card_json(monkeypatch)

    assert not card["capabilities"].get("extensions")
    assert card["capabilities"]["streaming"] is True


@pytest.mark.parametrize("raw", ["not-a-jws", "a.b", "a..c", "a.b.c.d"])
def test_malformed_certificate_is_rejected_not_published(raw):
    with pytest.raises(ValueError, match="VIJIL_CERTIFICATE_JWS"):
        agent.build_certificate_extensions({"VIJIL_CERTIFICATE_JWS": raw})


PROTECTED_CLAIMS = ("PROTECTED", "SECURED", "Domed")


@pytest.mark.parametrize("mode_name", ["off", "shadow"])
def test_identity_does_not_claim_protection_unless_enforcing(mode_name):
    identity = agent.agent_identity(agent.DomeMode(mode_name))

    for claim in PROTECTED_CLAIMS:
        assert claim not in identity.name
        assert claim not in identity.description


def test_identity_claims_protection_in_enforce_mode():
    identity = agent.agent_identity(agent.DomeMode.ENFORCE)

    assert "Domed" in identity.name
    assert "PROTECTED" in identity.description
    assert "SECURED" in identity.description


@pytest.mark.parametrize(
    ("mode_name", "claims_protection"), [("off", False), ("shadow", False), ("enforce", True)]
)
def test_agent_card_identity_follows_dome_mode(monkeypatch, mode_name, claims_protection):
    monkeypatch.setattr(agent, "DOME_MODE", agent.DomeMode(mode_name))

    card = _agent_card_json(monkeypatch)

    claimed = any(c in card["name"] or c in card["description"] for c in PROTECTED_CLAIMS)
    assert claimed is claims_protection


@pytest.mark.parametrize(("mode_name", "claims_protection"), [("shadow", False), ("enforce", True)])
def test_strands_agent_identity_follows_dome_mode(monkeypatch, mode_name, claims_protection):
    monkeypatch.setattr(agent, "DOME_MODE", agent.DomeMode(mode_name))
    monkeypatch.setenv("GROQ_API_KEY", "groq-key-for-test")

    built = agent.create_agent()

    claimed = any(c in built.name or c in (built.description or "") for c in PROTECTED_CLAIMS)
    assert claimed is claims_protection


@pytest.mark.parametrize(
    ("mode_name", "expected_notifications"), [("off", []), ("shadow", []), ("enforce", ["domed"])]
)
def test_console_is_told_domed_only_in_enforce_mode(monkeypatch, mode_name, expected_notifications):
    _run_main_with(monkeypatch, mode_name)

    assert _CONSOLE_NOTIFICATIONS == expected_notifications


@pytest.mark.parametrize("mode", list(agent.DomeMode))
def test_identity_does_not_hardcode_the_model_as_groq_llama(mode):
    identity = agent.agent_identity(mode)

    assert "Model: Groq" not in identity.description
    assert "AGENT_MODEL_ID" in identity.description
