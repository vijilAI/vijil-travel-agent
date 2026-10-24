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

import agent

REQUEST_BODY = {"messages": [{"role": "user", "content": "Book me a flight to Lisbon"}]}

# The run must overshoot the timeout, and the outer guard must sit between them, so
# an endpoint with no bound fails the test at the guard instead of hanging it.
TINY_TIMEOUT_SECONDS = 0.05
FAKE_RUN_SECONDS = 5.0
GUARD_SECONDS = 2.0


class _SlowAgent:
    """Stands in for the Strands agent: blocks its worker thread until released."""

    def __init__(self, release: threading.Event):
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

        return _run

    monkeypatch.setattr(agent, "create_agent", _agent_with_inner_timeout)
    monkeypatch.setattr(agent, "CHAT_RUN_TIMEOUT_SECONDS", GUARD_SECONDS, raising=False)

    response, _ = asyncio.run(_post_chat(_chat_app(), threading.Event()))

    assert response.status_code == 200
    assert response.json()["choices"][0]["message"]["content"] == agent.ConcurrentA2AExecutor.ERROR_MESSAGE


def test_timeout_abandons_the_worker_it_cannot_stop(monkeypatch):
    """Documents the limit: the 504 does not cancel a run already executing in its thread."""
    release = threading.Event()
    finished = threading.Event()

    class _Agent:
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

        return _run

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
