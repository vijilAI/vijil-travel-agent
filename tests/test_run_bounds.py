"""Model selection and run bounds (turn cap + wall-clock) for every agent path.

No network or API keys. The real Strands event loop runs; only the model is
replaced by a scripted stand-in (``_ScriptedModel``) that keeps requesting a tool,
the way the live llama-3.1-8b-instant run looped for 266 tool calls. Without the
bounds the stand-in eventually ends with ``RUNAWAY_ANSWER``; with them the request
must fail and that text must never reach the caller.
"""

from __future__ import annotations

import asyncio
import json
import threading
import time
from collections.abc import AsyncIterator
from typing import Any

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from strands import Agent, tool
from strands.models.model import Model

import agent as agent_module
from agentcore_routes import register_agentcore_routes

RUNAWAY_ANSWER = "RUNAWAY-ANSWER-AFTER-UNBOUNDED-LOOP"
INVOKE_BODY = {"messages": [{"role": "user", "content": "Search flights from SFO to JFK."}]}


class _ScriptedModel(Model):
    """Requests ``tool_name`` on each of its first ``loops`` calls, then answers."""

    def __init__(self, loops: int, tool_name: str = "no_such_tool", delay_s: float = 0.0):
        self.loops = loops
        self.tool_name = tool_name
        self.delay_s = delay_s
        self.calls = 0
        self.config: dict[str, Any] = {"model_id": "scripted"}

    def update_config(self, **model_config: Any) -> None:
        self.config.update(model_config)

    def get_config(self) -> dict[str, Any]:
        return self.config

    async def structured_output(self, output_model, prompt, system_prompt=None, **kwargs):  # type: ignore[override]
        raise NotImplementedError
        yield  # pragma: no cover

    async def stream(self, messages, tool_specs=None, system_prompt=None, **kwargs) -> AsyncIterator[Any]:  # type: ignore[override]
        self.calls += 1
        if self.delay_s:
            await asyncio.sleep(self.delay_s)
        yield {"messageStart": {"role": "assistant"}}
        if self.calls <= self.loops:
            use_id = f"call-{self.calls}"
            yield {"contentBlockStart": {"start": {"toolUse": {"toolUseId": use_id, "name": self.tool_name}}}}
            yield {"contentBlockDelta": {"delta": {"toolUse": {"input": json.dumps({})}}}}
            yield {"contentBlockStop": {}}
            yield {"messageStop": {"stopReason": "tool_use"}}
        else:
            yield {"contentBlockDelta": {"delta": {"text": RUNAWAY_ANSWER}}}
            yield {"contentBlockStop": {}}
            yield {"messageStop": {"stopReason": "end_turn"}}


@pytest.fixture
def scripted(monkeypatch):
    """Route create_agent's model to a _ScriptedModel; return an installer for it."""
    holder: dict[str, _ScriptedModel] = {}

    def install(model: _ScriptedModel) -> _ScriptedModel:
        holder["model"] = model
        monkeypatch.setattr(agent_module, "OpenAIModel", lambda **_kw: holder["model"])
        return model

    for name in ("TRAVEL_AGENT_MAX_TURNS", "TRAVEL_AGENT_TURN_TIMEOUT_S", "AGENT_SYSTEM_PROMPT", "GENOME_PATH"):
        monkeypatch.delenv(name, raising=False)
    return install


def _invocations(body: dict = INVOKE_BODY):
    app = FastAPI()
    register_agentcore_routes(app, handler=agent_module._agentcore_chat)
    return TestClient(app).post("/invocations", json=body)


def _run_chat() -> str | None:
    return asyncio.run(
        agent_module.run_chat_completion(
            [agent_module.ChatMessage(role="user", content="go")], raise_on_failure=True
        )
    )


# --- A1: model --------------------------------------------------------------

def test_model_defaults_to_gpt_oss_120b_on_groq(monkeypatch):
    monkeypatch.delenv("TRAVEL_AGENT_MODEL", raising=False)
    config = agent_module.create_agent().model.get_config()
    assert config["model_id"] == "openai/gpt-oss-120b"
    assert config["params"] == {"max_tokens": 4096}
    assert agent_module.MODEL_BASE_URL == "https://api.groq.com/openai/v1"


def test_model_is_overridable_by_env(monkeypatch):
    monkeypatch.setenv("TRAVEL_AGENT_MODEL", "llama-3.3-70b-versatile")
    assert agent_module.create_agent().model.get_config()["model_id"] == "llama-3.3-70b-versatile"


# --- A2: bound configuration -------------------------------------------------

def test_bounds_default_to_8_turns_and_90_seconds(monkeypatch):
    monkeypatch.delenv("TRAVEL_AGENT_MAX_TURNS", raising=False)
    monkeypatch.delenv("TRAVEL_AGENT_TURN_TIMEOUT_S", raising=False)
    expected = agent_module.RunBounds(max_turns=8, timeout_s=90.0)
    assert agent_module.run_bounds_from_env() == expected
    built = agent_module.create_agent()
    assert isinstance(built, agent_module.BoundedAgent)
    assert built.bounds == expected


def test_bounds_read_env(monkeypatch):
    monkeypatch.setenv("TRAVEL_AGENT_MAX_TURNS", "3")
    monkeypatch.setenv("TRAVEL_AGENT_TURN_TIMEOUT_S", "12.5")
    assert agent_module.run_bounds_from_env() == agent_module.RunBounds(max_turns=3, timeout_s=12.5)


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("TRAVEL_AGENT_MAX_TURNS", "0"),
        ("TRAVEL_AGENT_MAX_TURNS", "eight"),
        ("TRAVEL_AGENT_MAX_TURNS", "2.5"),
        ("TRAVEL_AGENT_TURN_TIMEOUT_S", "-1"),
        ("TRAVEL_AGENT_TURN_TIMEOUT_S", "soon"),
        ("TRAVEL_AGENT_TURN_TIMEOUT_S", "nan"),
        ("TRAVEL_AGENT_TURN_TIMEOUT_S", "inf"),
    ],
)
def test_bad_bound_settings_fail_loudly(monkeypatch, name, value):
    monkeypatch.setenv(name, value)
    with pytest.raises(ValueError, match=name):
        agent_module.run_bounds_from_env()


# --- A2: turn cap -----------------------------------------------------------

def test_turn_cap_makes_invocations_fail_with_502(scripted):
    model = scripted(_ScriptedModel(loops=50))
    resp = _invocations()
    assert resp.status_code == 502
    assert resp.json() == {"error": "Agent execution failed."}
    assert RUNAWAY_ANSWER not in resp.text
    assert model.calls == 8  # default cap: eight model turns, then stop


def test_turn_cap_is_read_from_env(scripted, monkeypatch):
    monkeypatch.setenv("TRAVEL_AGENT_MAX_TURNS", "3")
    model = scripted(_ScriptedModel(loops=50))
    assert _invocations().status_code == 502
    assert model.calls == 3


def test_run_within_the_cap_still_answers(scripted):
    model = scripted(_ScriptedModel(loops=2))
    resp = _invocations()
    assert resp.status_code == 200
    assert resp.json()["response"].strip() == RUNAWAY_ANSWER
    assert model.calls == 3


def test_turn_cap_raises_from_run_chat_completion(scripted):
    scripted(_ScriptedModel(loops=50))
    with pytest.raises(agent_module.AgentRunBoundExceeded, match="8-turn cap"):
        _run_chat()


def test_turn_cap_on_v1_chat_completions_returns_the_error_text_not_an_answer(scripted):
    scripted(_ScriptedModel(loops=50))
    app = FastAPI()
    agent_module.add_chat_completions_endpoint(app)
    resp = TestClient(app).post(
        "/v1/chat/completions",
        json={"model": "m", "messages": [{"role": "user", "content": "go"}]},
    )
    content = resp.json()["choices"][0]["message"]["content"]
    assert content == agent_module.ConcurrentA2AExecutor.ERROR_MESSAGE
    assert RUNAWAY_ANSWER not in resp.text


# --- A2: wall-clock bound ---------------------------------------------------

def test_timeout_makes_invocations_fail_with_502(scripted, monkeypatch):
    monkeypatch.setenv("TRAVEL_AGENT_MAX_TURNS", "1000")
    monkeypatch.setenv("TRAVEL_AGENT_TURN_TIMEOUT_S", "0.5")
    model = scripted(_ScriptedModel(loops=60, delay_s=0.1))
    started = time.monotonic()
    resp = _invocations()
    elapsed = time.monotonic() - started
    assert resp.status_code == 502
    assert RUNAWAY_ANSWER not in resp.text
    assert elapsed < 3.0, elapsed
    assert model.calls < 60


def test_timeout_message_names_the_setting(scripted, monkeypatch):
    monkeypatch.setenv("TRAVEL_AGENT_MAX_TURNS", "1000")
    monkeypatch.setenv("TRAVEL_AGENT_TURN_TIMEOUT_S", "0.3")
    scripted(_ScriptedModel(loops=60, delay_s=0.1))
    with pytest.raises(agent_module.AgentRunBoundExceeded, match="TRAVEL_AGENT_TURN_TIMEOUT_S"):
        _run_chat()


@tool
def blocking_tool() -> str:
    """Blocks well past the deadline and ignores cancellation."""
    time.sleep(3.0)
    return "late"


def test_hard_stop_abandons_a_tool_that_ignores_cancellation(monkeypatch):
    monkeypatch.setenv("TRAVEL_AGENT_TURN_TIMEOUT_S", "0.2")
    monkeypatch.setattr(agent_module, "HARD_STOP_GRACE_S", 0.2)
    bounds = agent_module.run_bounds_from_env()

    def factory(messages=None):
        return agent_module.BoundedAgent(
            bounds=bounds,
            model=_ScriptedModel(loops=5, tool_name="blocking_tool"),
            tools=[blocking_tool],
            callback_handler=None,
        )

    monkeypatch.setattr(agent_module, "create_agent", factory)

    async def timed_run() -> float:
        # Timed inside the loop: asyncio.run() itself waits for the abandoned
        # worker thread at shutdown, which a long-lived server loop never does.
        started = time.monotonic()
        with pytest.raises(agent_module.AgentRunBoundExceeded, match="abandoned"):
            await agent_module.run_chat_completion(
                [agent_module.ChatMessage(role="user", content="go")], raise_on_failure=True
            )
        return time.monotonic() - started

    assert asyncio.run(timed_run()) < 2.0


@pytest.mark.parametrize(
    "override", [{"cancel_signal": threading.Event()}, {"limits": {"turns": 500}}]
)
def test_bounded_agent_refuses_caller_overrides_of_its_bounds(override):
    bounded = agent_module.BoundedAgent(
        bounds=agent_module.RunBounds(max_turns=2, timeout_s=5.0),
        model=_ScriptedModel(loops=0),
        callback_handler=None,
    )
    with pytest.raises(TypeError, match="cancel_signal and limits"):
        bounded("hi", **override)


def test_plain_strands_agent_does_not_raise_on_its_turn_cap():
    """Why BoundedAgent exists: strands reports the cap as a normal result."""
    unbounded = Agent(model=_ScriptedModel(loops=50), callback_handler=None)
    result = unbounded("go", limits={"turns": 2})
    assert result.stop_reason == "limit_turns"


# --- A2: the A2A path -------------------------------------------------------

def _a2a_message() -> dict:
    return {
        "jsonrpc": "2.0",
        "id": "r1",
        "method": "message/send",
        "params": {
            "message": {
                "role": "user",
                "parts": [{"kind": "text", "text": "Search flights from SFO to JFK."}],
                "messageId": "m1",
            }
        },
    }


def _a2a_send(app) -> dict:
    resp = TestClient(app).post("/", json=_a2a_message())
    assert resp.status_code == 200
    return resp.json()


def test_turn_cap_fails_the_a2a_task(scripted):
    model = scripted(_ScriptedModel(loops=50))
    body = _a2a_send(agent_module.create_concurrent_a2a_app(agent_module.create_agent))
    text = json.dumps(body)
    assert body["result"]["status"]["state"] == "failed", text[:500]
    assert RUNAWAY_ANSWER not in text
    assert agent_module.ConcurrentA2AExecutor.ERROR_MESSAGE not in text
    assert model.calls == 8


def test_timeout_fails_the_a2a_task(scripted, monkeypatch):
    monkeypatch.setenv("TRAVEL_AGENT_MAX_TURNS", "1000")
    monkeypatch.setenv("TRAVEL_AGENT_TURN_TIMEOUT_S", "0.5")
    scripted(_ScriptedModel(loops=60, delay_s=0.1))
    started = time.monotonic()
    body = _a2a_send(agent_module.create_concurrent_a2a_app(agent_module.create_agent))
    assert time.monotonic() - started < 3.0
    assert body["result"]["status"]["state"] == "failed", json.dumps(body)[:500]
    assert RUNAWAY_ANSWER not in json.dumps(body)


def test_a2a_run_within_the_cap_completes(scripted):
    scripted(_ScriptedModel(loops=1))
    body = _a2a_send(agent_module.create_concurrent_a2a_app(agent_module.create_agent))
    assert body["result"]["status"]["state"] == "completed", json.dumps(body)[:500]
    assert RUNAWAY_ANSWER in json.dumps(body)


def test_a2a_hard_stop_fails_the_task_when_a_tool_ignores_cancellation(monkeypatch):
    monkeypatch.setattr(agent_module, "HARD_STOP_GRACE_S", 0.2)
    bounds = agent_module.RunBounds(max_turns=50, timeout_s=0.2)

    def factory():
        return agent_module.BoundedAgent(
            bounds=bounds,
            model=_ScriptedModel(loops=5, tool_name="blocking_tool"),
            tools=[blocking_tool],
            callback_handler=None,
        )

    async def timed_send() -> tuple[float, dict]:
        # Timed inside the loop, as in the chat-path hard-stop test.
        app = agent_module.create_concurrent_a2a_app(factory)
        started = time.monotonic()
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://agent") as client:
            resp = await client.post("/", json=_a2a_message())
        return time.monotonic() - started, resp.json()

    elapsed, body = asyncio.run(timed_send())
    assert elapsed < 2.0, elapsed
    assert body["result"]["status"]["state"] == "failed", json.dumps(body)[:500]
    assert "abandoned" in json.dumps(body)
    assert RUNAWAY_ANSWER not in json.dumps(body)


def test_a2a_request_cancellation_stops_the_run(monkeypatch):
    """A cancelled request (client gone, shutdown) must not leave the run calling tools."""
    seen: dict[str, bool] = {"agent_cancelled": False, "run_cancelled": False}

    class _HangingExecutor:
        def __init__(self, _agent):
            pass

        async def execute(self, _context, _queue):
            try:
                await asyncio.sleep(60)
            except asyncio.CancelledError:
                seen["run_cancelled"] = True
                raise

    class _Agent:
        bounds = agent_module.RunBounds(max_turns=8, timeout_s=60.0)

        def cancel(self):
            seen["agent_cancelled"] = True

    monkeypatch.setattr(agent_module, "StrandsA2AExecutor", _HangingExecutor)
    executor = agent_module.ConcurrentA2AExecutor(lambda: _Agent())

    async def cancel_mid_run() -> None:
        request = asyncio.create_task(executor._run_with_hard_stop(_Agent(), None, None))
        await asyncio.sleep(0.05)
        request.cancel()
        with pytest.raises(asyncio.CancelledError):
            await request
        await asyncio.sleep(0)  # let the inner run observe its cancellation

    asyncio.run(cancel_mid_run())
    assert seen == {"agent_cancelled": True, "run_cancelled": True}


# --- throttling: no model call after the run is cut off -----------------------

class _ThrottledModel(_ScriptedModel):
    """Every call is throttled (Groq 429); records when each call happened."""

    def __init__(self) -> None:
        super().__init__(loops=0)
        self.call_times: list[float] = []

    async def stream(self, messages, tool_specs=None, system_prompt=None, **kwargs) -> AsyncIterator[Any]:  # type: ignore[override]
        from strands.types.exceptions import ModelThrottledException

        self.calls += 1
        self.call_times.append(time.monotonic())
        raise ModelThrottledException("429 Too Many Requests")
        yield  # pragma: no cover


def test_no_model_retry_after_the_deadline(scripted, monkeypatch):
    """A throttled run stops calling the model once it is cut off.

    strands' default retry sleeps 4-64 s between attempts and ignores
    cancellation, so the model was called again after the client had its 502.
    """
    monkeypatch.setenv("TRAVEL_AGENT_TURN_TIMEOUT_S", "0.5")
    monkeypatch.setattr(agent_module, "HARD_STOP_GRACE_S", 0.3)
    model = scripted(_ThrottledModel())

    from strands.types.exceptions import ModelThrottledException

    async def run_then_wait() -> float:
        # Either failure is correct: the run is cut off, or the throttle surfaces
        # because no retry is attempted after the deadline. Never an answer.
        with pytest.raises((agent_module.AgentRunBoundExceeded, ModelThrottledException)):
            await agent_module.run_chat_completion(
                [agent_module.ChatMessage(role="user", content="go")], raise_on_failure=True
            )
        returned = time.monotonic()
        await asyncio.sleep(3.0)  # longer than the 2 s first backoff
        return returned

    returned = asyncio.run(run_then_wait())
    assert model.calls >= 1
    assert all(t <= returned + 0.3 for t in model.call_times), (
        f"model called after the request failed: {[round(t - returned, 2) for t in model.call_times]}"
    )


def test_bounded_agent_installs_the_cancellable_retry_strategy():
    bounded = agent_module.BoundedAgent(
        bounds=agent_module.run_bounds_from_env(),
        model=_ScriptedModel(loops=0), callback_handler=None,
    )
    assert isinstance(bounded._retry, agent_module.CancellableRetryStrategy)
    assert bounded._retry._max_attempts == 3
