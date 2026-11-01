"""The chat completions endpoint bounds each agent run and reports an expiry as a typed error."""

import asyncio
import concurrent.futures
import os
import re
import subprocess
import sys
import threading
import time
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI
from strands import Agent, tool
from strands.models import Model

import agent
from tests.fake_agent import FakeAgent

REQUEST_BODY = {"messages": [{"role": "user", "content": "Book me a flight to Lisbon"}]}

# The run must overshoot the timeout, and the outer guard must sit between them, so
# an endpoint with no bound fails the test at the guard instead of hanging it.
TINY_TIMEOUT_SECONDS = 0.05
FAKE_RUN_SECONDS = 5.0
GUARD_SECONDS = 2.0


class _SlowAgent(FakeAgent):
    """Stands in for the Strands agent: blocks its worker thread until released."""

    def __init__(self, release: threading.Event):
        super().__init__()
        self._release = release

    def __call__(self, user_text: str) -> str:
        self._release.wait(timeout=FAKE_RUN_SECONDS)
        return f"late answer to: {user_text}"


async def _post_chat(app: FastAPI, release: threading.Event) -> tuple[httpx.Response, float]:
    """POST one chat request; return the response and how long the endpoint took to answer.

    The worker thread is released before the loop closes, because asyncio.run waits
    for it on shutdown and that wait is not the endpoint's latency.
    """
    transport = httpx.ASGITransport(app=app)
    started = time.monotonic()
    try:
        async with httpx.AsyncClient(transport=transport, base_url="http://agent") as client:
            response = await asyncio.wait_for(
                client.post("/v1/chat/completions", json=REQUEST_BODY), timeout=GUARD_SECONDS
            )
        return response, time.monotonic() - started
    finally:
        release.set()


def _chat_app() -> FastAPI:
    app = FastAPI()
    agent.add_chat_completions_endpoint(app)
    return app


def test_slow_agent_run_returns_typed_timeout_error_promptly(monkeypatch):
    release = threading.Event()
    monkeypatch.setattr(agent, "create_agent", lambda messages=None: _SlowAgent(release))
    monkeypatch.setattr(agent, "CHAT_RUN_TIMEOUT_SECONDS", TINY_TIMEOUT_SECONDS, raising=False)

    response, elapsed = asyncio.run(_post_chat(_chat_app(), release))

    assert response.status_code == 504
    error = response.json()["error"]
    assert error["code"] == "agent_run_timeout"
    assert error["type"] == "timeout_error"
    assert str(TINY_TIMEOUT_SECONDS) in error["message"]
    # Distinct from the generic failure answer and never a chat completion.
    assert agent.ConcurrentA2AExecutor.ERROR_MESSAGE not in response.text
    assert "choices" not in response.json()
    assert elapsed < GUARD_SECONDS



def test_a_failing_cancel_still_answers_the_typed_timeout(monkeypatch):
    """The 504 must not depend on the run cancelling cleanly: a cancel() that raises
    would otherwise fall through to the generic 200 error answer."""
    release = threading.Event()

    class _CancelRaises(_SlowAgent):
        def cancel(self) -> None:
            raise RuntimeError("cancel failed")

    monkeypatch.setattr(agent, "create_agent", lambda messages=None: _CancelRaises(release))
    monkeypatch.setattr(agent, "CHAT_RUN_TIMEOUT_SECONDS", TINY_TIMEOUT_SECONDS, raising=False)

    response, _ = asyncio.run(_post_chat(_chat_app(), release))

    assert response.status_code == 504
    assert response.json()["error"]["code"] == "agent_run_timeout"

def test_agent_run_within_timeout_still_answers_200(monkeypatch):
    release = threading.Event()
    release.set()
    monkeypatch.setattr(agent, "create_agent", lambda messages=None: _SlowAgent(release))
    monkeypatch.setattr(agent, "CHAT_RUN_TIMEOUT_SECONDS", GUARD_SECONDS, raising=False)

    response, _ = asyncio.run(_post_chat(_chat_app(), release))

    assert response.status_code == 200
    content = response.json()["choices"][0]["message"]["content"]
    assert content == "late answer to: Book me a flight to Lisbon"


def test_agent_exception_keeps_generic_error_message_answer(monkeypatch):
    def _failing_agent(messages=None):
        raise RuntimeError("model unreachable")

    monkeypatch.setattr(agent, "create_agent", _failing_agent)

    response, _ = asyncio.run(_post_chat(_chat_app(), threading.Event()))

    assert response.status_code == 200
    content = response.json()["choices"][0]["message"]["content"]
    assert content == agent.ConcurrentA2AExecutor.ERROR_MESSAGE


@pytest.mark.parametrize("raw", ["0", "-5", "abc", "nan", "inf"])
def test_timeout_setting_rejects_values_that_would_not_bound_the_run(raw):
    with pytest.raises(ValueError):
        agent._read_timeout_seconds(raw)


def test_timeout_setting_parses_a_positive_number_of_seconds():
    assert agent._read_timeout_seconds("2.5") == 2.5


REPO_ROOT = Path(__file__).resolve().parent.parent


def _proxy_upstream_timeout_seconds() -> int:
    """The smallest urlopen timeout in the checked-in Lambda proxy (handler.py)."""
    found = re.findall(r"urlopen\([^)]*timeout=(\d+)", (REPO_ROOT / "handler.py").read_text())
    assert found, "handler.py no longer sets an upstream timeout; update this test"
    return min(int(n) for n in found)


def test_default_timeout_is_below_the_proxy_upstream_timeout():
    upstream = _proxy_upstream_timeout_seconds()

    assert agent.DEFAULT_CHAT_RUN_TIMEOUT_SECONDS < upstream


def test_effective_default_with_no_env_is_the_documented_default():
    """Import agent in a clean process: the value the endpoint actually uses, not the constant."""
    env = {k: v for k, v in os.environ.items() if k != "CHAT_RUN_TIMEOUT_SECONDS"}
    code = "import agent; print(agent.CHAT_RUN_TIMEOUT_SECONDS)"
    out = subprocess.run(
        [sys.executable, "-c", code], cwd=REPO_ROOT, env=env, capture_output=True, text=True, check=True
    )

    effective = float(out.stdout.strip().splitlines()[-1])
    assert effective == agent.DEFAULT_CHAT_RUN_TIMEOUT_SECONDS
    assert effective < _proxy_upstream_timeout_seconds()


def test_timeout_error_raised_inside_the_agent_is_not_reported_as_a_run_timeout(monkeypatch):
    """A socket-level TimeoutError from a tool is an agent failure, not the run deadline."""

    def _agent_with_inner_timeout(messages=None):
        def _run(user_text):
            raise TimeoutError("tool socket timed out")

        return FakeAgent(_run)

    monkeypatch.setattr(agent, "create_agent", _agent_with_inner_timeout)
    monkeypatch.setattr(agent, "CHAT_RUN_TIMEOUT_SECONDS", GUARD_SECONDS, raising=False)

    response, _ = asyncio.run(_post_chat(_chat_app(), threading.Event()))

    assert response.status_code == 200
    assert response.json()["choices"][0]["message"]["content"] == agent.ConcurrentA2AExecutor.ERROR_MESSAGE


def test_timeout_abandons_the_worker_it_cannot_stop(monkeypatch):
    """Documents the limit: the 504 does not cancel a run already executing in its thread."""
    release = threading.Event()
    finished = threading.Event()

    class _Agent(FakeAgent):
        def __call__(self, user_text):
            release.wait(timeout=FAKE_RUN_SECONDS)
            finished.set()
            return "late"

    monkeypatch.setattr(agent, "create_agent", lambda messages=None: _Agent())
    monkeypatch.setattr(agent, "CHAT_RUN_TIMEOUT_SECONDS", TINY_TIMEOUT_SECONDS, raising=False)

    async def _go():
        transport = httpx.ASGITransport(app=_chat_app())
        async with httpx.AsyncClient(transport=transport, base_url="http://agent") as client:
            response = await client.post("/v1/chat/completions", json=REQUEST_BODY)
        still_running = not finished.is_set()
        release.set()
        return response, still_running

    response, still_running = asyncio.run(_go())

    assert response.status_code == 504
    assert still_running


def test_runs_queued_behind_a_stuck_run_are_dropped_not_started_late(monkeypatch):
    """With every worker busy, a timed-out request must not start its run after the 504."""
    release = threading.Event()
    started: list[str] = []

    def _factory(messages=None):
        def _run(user_text):
            started.append(user_text)
            release.wait(timeout=FAKE_RUN_SECONDS)
            return "late"

        return FakeAgent(_run)

    one_worker = concurrent.futures.ThreadPoolExecutor(max_workers=1)
    monkeypatch.setattr(agent, "create_agent", _factory)
    monkeypatch.setattr(agent, "CHAT_RUN_TIMEOUT_SECONDS", TINY_TIMEOUT_SECONDS, raising=False)
    monkeypatch.setattr(agent, "_CHAT_RUN_EXECUTOR", one_worker, raising=False)

    def _body(text: str) -> dict:
        return {"messages": [{"role": "user", "content": text}]}

    async def _go():
        transport = httpx.ASGITransport(app=_chat_app())
        async with httpx.AsyncClient(transport=transport, base_url="http://agent") as client:
            first = await client.post("/v1/chat/completions", json=_body("first"))
            second = await client.post("/v1/chat/completions", json=_body("second"))
        started_at_response = list(started)
        release.set()
        return first, second, started_at_response

    try:
        first, second, started_at_response = asyncio.run(_go())
    finally:
        release.set()
        one_worker.shutdown(wait=True)

    assert first.status_code == 504
    assert second.status_code == 504
    assert started_at_response == ["first"]
    assert started == ["first"], f"queued run started after its request timed out: {started}"


def test_executor_size_setting_rejects_non_positive_integers():
    for raw in ("0", "-1", "abc", "2.5"):
        with pytest.raises(ValueError):
            agent._read_worker_count(raw)
    assert agent._read_worker_count("4") == 4


# ── a timed-out run stops issuing tool calls (DIAMOND-751) ──


class _ScriptedModel(Model):
    """A Strands model that plays a fixed script, one turn per call: a tool call or a final answer.

    ``before_turn`` runs (in the agent's worker thread) before a turn is streamed, so
    a test can hold the model until the request has already timed out.
    """

    def __init__(self, turns: list[str | None], before_turn=lambda turn: None):
        self._turns = turns  # tool name to call, or None for a plain-text answer
        self._before_turn = before_turn
        self.calls = 0

    def update_config(self, **model_config):
        pass

    def get_config(self):
        return {}

    async def structured_output(self, output_model, prompt, system_prompt=None, **kwargs):
        raise NotImplementedError
        yield  # pragma: no cover

    async def stream(self, messages, tool_specs=None, system_prompt=None, **kwargs):
        turn = self.calls
        self.calls += 1
        await asyncio.to_thread(self._before_turn, turn)
        tool = self._turns[turn] if turn < len(self._turns) else None
        yield {"messageStart": {"role": "assistant"}}
        if tool is None:
            yield {"contentBlockDelta": {"delta": {"text": "done"}}}
            yield {"contentBlockStop": {}}
            yield {"messageStop": {"stopReason": "end_turn"}}
            return
        yield {"contentBlockStart": {"start": {"toolUse": {"toolUseId": f"call-{turn}", "name": tool}}}}
        yield {"contentBlockDelta": {"delta": {"toolUse": {"input": "{}"}}}}
        yield {"contentBlockStop": {}}
        yield {"messageStop": {"stopReason": "tool_use"}}


def _run_until_timed_out(monkeypatch, real_agent: Agent, timed_out: threading.Event) -> httpx.Response:
    """POST one chat request against ``real_agent``; return the 504 once the worker run has ended.

    ``timed_out`` is set when the endpoint has answered, so the scripted model and
    tools can wait for the deadline to have passed before they act.
    """
    one_worker = concurrent.futures.ThreadPoolExecutor(max_workers=1)
    monkeypatch.setattr(agent, "create_agent", lambda messages=None: real_agent)
    monkeypatch.setattr(agent, "CHAT_RUN_TIMEOUT_SECONDS", TINY_TIMEOUT_SECONDS, raising=False)
    monkeypatch.setattr(agent, "_CHAT_RUN_EXECUTOR", one_worker, raising=False)

    async def _go() -> httpx.Response:
        transport = httpx.ASGITransport(app=_chat_app())
        async with httpx.AsyncClient(transport=transport, base_url="http://agent") as client:
            response = await asyncio.wait_for(
                client.post("/v1/chat/completions", json=REQUEST_BODY), timeout=GUARD_SECONDS
            )
        timed_out.set()
        return response

    try:
        response = asyncio.run(_go())
    finally:
        timed_out.set()
        one_worker.shutdown(wait=True)  # the abandoned run has finished: no tool can run later
    return response


def test_a_tool_the_model_asks_for_after_the_timeout_never_executes(monkeypatch):
    executed: list[str] = []
    timed_out = threading.Event()

    @tool
    def book_flight() -> str:
        """Book a flight (side effect)."""
        executed.append("book_flight")
        return "booked"

    model = _ScriptedModel(["book_flight"], before_turn=lambda turn: timed_out.wait(FAKE_RUN_SECONDS))
    real_agent = Agent(model=model, tools=[book_flight], callback_handler=None)
    response = _run_until_timed_out(monkeypatch, real_agent, timed_out)

    assert response.status_code == 504
    assert response.json()["error"]["tool_calls_started"] == 0
    assert executed == [], "a tool ran after the caller was told the run timed out"


def test_a_cancelled_run_refuses_each_later_tool_call_and_runs_none():
    """The hook itself, through Strands' real tool executor: once cancelled, no tool starts."""
    executed: list[str] = []

    @tool
    def book_flight() -> str:
        """Book a flight (side effect)."""
        executed.append("book_flight")
        return "booked"

    real_agent = Agent(model=_ScriptedModel(["book_flight", None]), tools=[book_flight], callback_handler=None)
    cancellation = agent.RunCancellation()
    real_agent.hooks.add_hook(cancellation)
    assert cancellation.cancel() == 0

    real_agent("book it")

    assert executed == []
    results = [
        block["toolResult"] for message in real_agent.messages for block in message["content"] if "toolResult" in block
    ]
    assert [r["status"] for r in results] == ["error"]
    assert results[0]["content"][0]["text"] == agent.RunCancellation.REFUSAL


def test_a_tool_already_running_at_the_timeout_is_counted_and_the_run_stops_after_it(monkeypatch):
    """A tool in flight cannot be stopped; the 504 says one had started, and no model call follows it."""
    executed: list[str] = []
    timed_out = threading.Event()

    @tool
    def book_flight() -> str:
        """Book a flight (side effect)."""
        timed_out.wait(FAKE_RUN_SECONDS)  # still running when the deadline fires
        executed.append("book_flight")
        return "booked"

    @tool
    def charge_card() -> str:
        """Charge a card (side effect)."""
        executed.append("charge_card")
        return "charged"

    model = _ScriptedModel(["book_flight", "charge_card", None])
    real_agent = Agent(model=model, tools=[book_flight, charge_card], callback_handler=None)
    response = _run_until_timed_out(monkeypatch, real_agent, timed_out)

    assert response.status_code == 504
    error = response.json()["error"]
    assert error["tool_calls_started"] == 1
    assert "1 tool call" in error["message"]
    assert executed == ["book_flight"]
    assert model.calls == 1, "the run asked the model for another step after it timed out"
