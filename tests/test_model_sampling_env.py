"""AGENT_TEMPERATURE and AGENT_PROVIDER_ORDER reach every model request, or the agent refuses to start.

The model client is the real OpenAI SDK client on an httpx MockTransport, so each test sees the
JSON body the agent would send, and no test opens a socket.
"""

import asyncio
import json

import httpx
import openai
import pytest
import strands.models.openai as strands_openai

import agent
from tests.test_env_config import _run_main_with

OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"
# Strands reaches the client through the shared openai module, so keep the real class before patching it.
_REAL_ASYNC_OPENAI = openai.AsyncOpenAI


@pytest.fixture(autouse=True)
def _empty_database(monkeypatch, tmp_path):
    """Point create_agent's config loaders at an empty file, not whatever DB_PATH an earlier test left."""
    import db.connection

    monkeypatch.setattr(db.connection, "DB_PATH", tmp_path / "sampling_env.db")


@pytest.fixture
def sent_bodies(monkeypatch) -> list[dict]:
    """Replace the model client with one that records each request body and answers 401."""
    bodies: list[dict] = []

    def _handler(request: httpx.Request) -> httpx.Response:
        bodies.append(json.loads(request.content))
        return httpx.Response(401, json={"error": {"message": "stubbed"}})

    def _stub_client(**client_args):
        stubbed = {
            "max_retries": 0,
            "http_client": httpx.AsyncClient(transport=httpx.MockTransport(_handler)),
        }
        return _REAL_ASYNC_OPENAI(**(client_args | stubbed))

    monkeypatch.setattr(strands_openai.openai, "AsyncOpenAI", _stub_client)
    return bodies


def _set_env(monkeypatch, **env):
    for name in (
        "AGENT_BASE_URL",
        "AGENT_MODEL_ID",
        "AGENT_API_KEY",
        "AGENT_TEMPERATURE",
        "AGENT_PROVIDER_ORDER",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("GROQ_API_KEY", "groq-key-for-test")
    for name, value in env.items():
        monkeypatch.setenv(name, value)


def _model_calls(monkeypatch, calls: int = 1, **env):
    """Build the agent's model from env and make `calls` model requests through it."""
    _set_env(monkeypatch, **env)
    model = agent.create_agent().model

    async def _call():
        async for _ in model.stream([{"role": "user", "content": [{"text": "hi"}]}]):
            pass

    for _ in range(calls):
        with pytest.raises(openai.AuthenticationError):
            asyncio.run(_call())


def test_unset_settings_send_neither_temperature_nor_provider(monkeypatch, sent_bodies):
    _model_calls(monkeypatch)

    assert len(sent_bodies) == 1
    assert "temperature" not in sent_bodies[0]
    assert "provider" not in sent_bodies[0]
    assert sent_bodies[0]["max_tokens"] == 4096


def test_unset_settings_on_openrouter_send_neither(monkeypatch, sent_bodies):
    _model_calls(monkeypatch, AGENT_BASE_URL=OPENROUTER_BASE_URL, AGENT_API_KEY="or-key-for-test")

    assert "temperature" not in sent_bodies[0]
    assert "provider" not in sent_bodies[0]


@pytest.mark.parametrize(("raw", "expected"), [("0", 0.0), ("0.0", 0.0), (" 0.7 ", 0.7), ("2", 2.0)])
def test_temperature_is_sent_on_every_call(monkeypatch, sent_bodies, raw, expected):
    _model_calls(monkeypatch, calls=2, AGENT_TEMPERATURE=raw)

    assert len(sent_bodies) == 2
    assert [body["temperature"] for body in sent_bodies] == [expected, expected]


def test_provider_order_is_sent_on_every_openrouter_call(monkeypatch, sent_bodies):
    _model_calls(
        monkeypatch,
        calls=2,
        AGENT_BASE_URL=OPENROUTER_BASE_URL,
        AGENT_API_KEY="or-key-for-test",
        AGENT_PROVIDER_ORDER="Fireworks, together",
    )

    expected = {"order": ["Fireworks", "together"], "allow_fallbacks": False}
    assert len(sent_bodies) == 2
    assert [body["provider"] for body in sent_bodies] == [expected, expected]


def test_both_settings_together_on_openrouter(monkeypatch, sent_bodies):
    _model_calls(
        monkeypatch,
        AGENT_BASE_URL=OPENROUTER_BASE_URL,
        AGENT_API_KEY="or-key-for-test",
        AGENT_TEMPERATURE="0",
        AGENT_PROVIDER_ORDER="Fireworks",
    )

    assert sent_bodies[0]["temperature"] == 0.0
    assert sent_bodies[0]["provider"] == {"order": ["Fireworks"], "allow_fallbacks": False}
    assert sent_bodies[0]["max_tokens"] == 4096


@pytest.mark.parametrize("raw", ["", "  ", "warm", "0,5", "-0.1", "2.01", "nan", "inf", "-inf"])
def test_invalid_temperature_is_an_explicit_error(monkeypatch, raw):
    _set_env(monkeypatch, AGENT_TEMPERATURE=raw)

    with pytest.raises(agent.ModelConfigError, match="AGENT_TEMPERATURE"):
        agent.create_agent()


@pytest.mark.parametrize("raw", ["", " ", ",", "Fireworks,,together", "Fireworks, ", " ,Fireworks"])
def test_provider_order_with_an_empty_name_is_an_explicit_error(monkeypatch, raw):
    _set_env(
        monkeypatch,
        AGENT_BASE_URL=OPENROUTER_BASE_URL,
        AGENT_API_KEY="or-key-for-test",
        AGENT_PROVIDER_ORDER=raw,
    )

    with pytest.raises(agent.ModelConfigError, match="AGENT_PROVIDER_ORDER"):
        agent.create_agent()


@pytest.mark.parametrize(
    "base_url",
    [None, "http://llm-gateway.example:8080/v1", "https://openrouter.ai.attacker.example/api/v1"],
)
def test_provider_order_off_openrouter_is_an_explicit_error(monkeypatch, base_url):
    env = {"AGENT_PROVIDER_ORDER": "Fireworks"}
    if base_url is not None:
        env |= {"AGENT_BASE_URL": base_url, "AGENT_API_KEY": "gateway-key-for-test"}
    _set_env(monkeypatch, **env)

    with pytest.raises(agent.ModelConfigError, match="AGENT_PROVIDER_ORDER.*OpenRouter"):
        agent.create_agent()


def test_main_refuses_to_start_on_an_invalid_temperature(monkeypatch):
    _set_env(monkeypatch, AGENT_TEMPERATURE="3")

    with pytest.raises(agent.ModelConfigError, match="AGENT_TEMPERATURE"):
        _run_main_with(monkeypatch, "off")


def test_main_refuses_to_start_on_a_provider_order_off_openrouter(monkeypatch):
    _set_env(monkeypatch, AGENT_PROVIDER_ORDER="Fireworks")

    with pytest.raises(agent.ModelConfigError, match="AGENT_PROVIDER_ORDER"):
        _run_main_with(monkeypatch, "off")
