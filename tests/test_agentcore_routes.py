"""Tests for the AgentCore HTTP contract (POST /invocations, POST /, GET /ping).

No network or API keys: the LLM is stubbed at ``agent.create_agent``; the chat
coroutine, the dispatcher and (where noted) the real A2A application are real.
"""

import importlib
import os
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.responses import JSONResponse

import agent as agent_module
from agentcore_routes import register_agentcore_routes


class _FakeAgent:
    """Stands in for a Strands Agent: callable(user_text) -> object with str()."""

    def __init__(self, calls: list, history, reply: str):
        self._calls = calls
        self._history = history
        self._reply = reply

    def __call__(self, user_text: str) -> str:
        self._calls.append({"history": self._history, "user_text": user_text})
        return self._reply


@pytest.fixture
def chat_calls(monkeypatch):
    """Patch create_agent; record (history, user_text) for every chat run."""
    calls: list[dict] = []

    def fake_create_agent(messages=None):
        return _FakeAgent(calls, messages, "stub travel reply")

    monkeypatch.setattr(agent_module, "create_agent", fake_create_agent)
    return calls


class _RecordingA2A:
    """Stands in for the A2AFastAPIApplication that owns _handle_requests."""

    def __init__(self):
        self.requests = []

    async def _handle_requests(self, request):
        body = await request.json()  # must still be readable after dispatch
        self.requests.append(body)
        return JSONResponse({"jsonrpc": "2.0", "id": 1, "result": "from-a2a"})


def _client(a2a_app=None, handler=None) -> TestClient:
    app = FastAPI()
    register_agentcore_routes(
        app, handler=handler or agent_module._agentcore_chat, a2a_app=a2a_app
    )
    return TestClient(app)


# --- chat bodies -----------------------------------------------------------

@pytest.mark.parametrize("path", ["/invocations", "/"])
def test_chat_body_reaches_chat_coroutine_with_right_messages(chat_calls, path):
    a2a = _RecordingA2A()
    resp = _client(a2a).post(
        path,
        json={
            "model": "ignored",
            "messages": [
                {"role": "system", "content": "be terse"},
                {"role": "user", "content": "first question"},
                {"role": "assistant", "content": "first answer"},
                {"role": "user", "content": "find me a flight to Oslo"},
            ],
        },
    )
    assert resp.status_code == 200
    assert resp.json() == {"response": "stub travel reply"}
    assert len(chat_calls) == 1
    assert chat_calls[0]["user_text"] == "find me a flight to Oslo"
    # System message skipped (same as /v1/chat/completions); prior turns kept.
    assert chat_calls[0]["history"] == [
        {"role": "user", "content": [{"text": "first question"}]},
        {"role": "assistant", "content": [{"text": "first answer"}]},
    ]
    assert a2a.requests == []  # a chat body must not reach A2A


def test_single_message_has_no_history(chat_calls):
    resp = _client().post(
        "/invocations", json={"messages": [{"role": "user", "content": "hi"}]}
    )
    assert resp.json() == {"response": "stub travel reply"}
    assert chat_calls == [{"history": None, "user_text": "hi"}]


def test_system_prompt_field_is_accepted_and_handler_receives_it():
    seen = {}

    async def handler(messages, system_prompt=None):
        seen["messages"] = messages
        seen["system_prompt"] = system_prompt
        return "ok"

    resp = _client(handler=handler).post(
        "/invocations",
        json={"messages": [{"role": "user", "content": "x"}], "system_prompt": "sp"},
    )
    assert resp.json() == {"response": "ok"}
    assert seen == {
        "messages": [{"role": "user", "content": "x"}],
        "system_prompt": "sp",
    }


def test_chat_path_matches_v1_chat_completions(chat_calls):
    """Both endpoints drive the same coroutine and see identical agent input."""
    app = FastAPI()
    agent_module.add_chat_completions_endpoint(app)
    register_agentcore_routes(app, handler=agent_module._agentcore_chat)
    client = TestClient(app)
    msgs = [
        {"role": "user", "content": "a"},
        {"role": "assistant", "content": "b"},
        {"role": "user", "content": "c"},
    ]

    oai = client.post("/v1/chat/completions", json={"messages": msgs}).json()
    ac = client.post("/invocations", json={"messages": msgs}).json()

    assert oai["choices"][0]["message"]["content"] == ac["response"] == "stub travel reply"
    assert len(chat_calls) == 2
    assert chat_calls[0] == chat_calls[1]


def test_v1_chat_completions_without_user_message_still_400(chat_calls):
    app = FastAPI()
    agent_module.add_chat_completions_endpoint(app)
    resp = TestClient(app).post(
        "/v1/chat/completions",
        json={"messages": [{"role": "assistant", "content": "hi"}]},
    )
    assert resp.status_code == 400
    assert resp.json() == {"error": "No user message found"}
    assert chat_calls == []


def test_agent_failure_returns_error_message_as_response(monkeypatch):
    def boom(messages=None):
        raise RuntimeError("llm down")

    monkeypatch.setattr(agent_module, "create_agent", boom)
    resp = _client().post(
        "/invocations", json={"messages": [{"role": "user", "content": "hi"}]}
    )
    assert resp.status_code == 200
    assert resp.json() == {"response": agent_module.ConcurrentA2AExecutor.ERROR_MESSAGE}


# --- JSON-RPC / A2A --------------------------------------------------------

@pytest.mark.parametrize("path", ["/invocations", "/"])
def test_jsonrpc_body_reaches_a2a_and_not_chat(chat_calls, path):
    a2a = _RecordingA2A()
    body = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "message/send",
        "params": {
            "message": {
                "role": "user",
                "parts": [{"kind": "text", "text": "hello"}],
                "messageId": "m1",
            }
        },
    }
    resp = _client(a2a).post(path, json=body)
    assert resp.status_code == 200
    assert resp.json()["result"] == "from-a2a"
    assert a2a.requests == [body]
    assert chat_calls == []


def test_json_array_routes_to_a2a_when_present(chat_calls):
    a2a = _RecordingA2A()
    batch = [{"jsonrpc": "2.0", "id": 1, "method": "message/send", "params": {}}]
    resp = _client(a2a).post("/invocations", json=batch)
    assert resp.status_code == 200
    assert a2a.requests == [batch]
    assert chat_calls == []


def test_json_array_without_a2a_is_422(chat_calls):
    resp = _client(None).post("/invocations", json=[{"role": "user", "content": "x"}])
    assert resp.status_code == 422
    assert resp.json() == {"error": "Invalid request payload."}
    assert chat_calls == []


@pytest.mark.parametrize("raw", [b'"a string"', b"42", b"null", b"true"])
def test_non_object_json_is_422(chat_calls, raw):
    resp = _client(_RecordingA2A()).post(
        "/invocations", content=raw, headers={"content-type": "application/json"}
    )
    assert resp.status_code == 422
    assert chat_calls == []


def test_jsonrpc_without_a2a_is_422_not_chat(chat_calls):
    resp = _client(None).post(
        "/invocations", json={"jsonrpc": "2.0", "id": 1, "method": "message/send"}
    )
    assert resp.status_code == 422
    assert chat_calls == []


def test_real_a2a_application_is_wired_through_agent_app(chat_calls):
    """create_concurrent_a2a_app + add_agentcore_endpoints reach the real A2A
    request handler (the executor's agent factory is invoked), not the chat path."""
    factory_calls = []

    def factory():
        factory_calls.append(1)
        return object()  # not a Strands Agent -> executor reports ERROR_MESSAGE

    app = agent_module.create_concurrent_a2a_app(factory)
    assert hasattr(app.state.a2a_application, "_handle_requests")
    agent_module.add_agentcore_endpoints(app)

    resp = TestClient(app).post(
        "/invocations",
        json={
            "jsonrpc": "2.0",
            "id": "r1",
            "method": "message/send",
            "params": {
                "message": {
                    "role": "user",
                    "parts": [{"kind": "text", "text": "hello"}],
                    "messageId": "m1",
                }
            },
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["jsonrpc"] == "2.0" and body["id"] == "r1"
    assert "error" not in body
    assert factory_calls  # real A2A executor ran
    assert agent_module.ConcurrentA2AExecutor.ERROR_MESSAGE in resp.text
    assert chat_calls == []

    # POST / is shadowed by the A2A route unless ours is first: chat body works.
    chat = TestClient(app).post("/", json={"messages": [{"role": "user", "content": "q"}]})
    assert chat.json() == {"response": "stub travel reply"}


# --- invalid input ---------------------------------------------------------

@pytest.mark.parametrize("path", ["/invocations", "/"])
def test_malformed_json_is_400(chat_calls, path):
    resp = _client(_RecordingA2A()).post(
        path, content=b"{not json", headers={"content-type": "application/json"}
    )
    assert resp.status_code == 400
    assert resp.json() == {"error": "Invalid JSON."}
    assert chat_calls == []


def test_empty_body_is_400(chat_calls):
    resp = _client().post("/invocations", content=b"")
    assert resp.status_code == 400


@pytest.mark.parametrize(
    "payload",
    [
        {"messages": [{"role": "assistant", "content": "only assistant"}]},
        {"messages": [{"role": "system", "content": "only system"}]},
        {"messages": []},
        {"messages": "not a list"},
        {"messages": [{"role": "user"}]},
        {"system_prompt": "no messages"},
        {},
    ],
)
def test_body_without_user_message_is_422(chat_calls, payload):
    resp = _client(_RecordingA2A()).post("/invocations", json=payload)
    assert resp.status_code == 422
    assert resp.json() == {"error": "Invalid request payload."}
    assert chat_calls == []


# --- /ping -----------------------------------------------------------------

def test_ping():
    resp = _client().get("/ping")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


# --- env defaults ----------------------------------------------------------

def test_db_path_default_unchanged_and_override(monkeypatch):
    import db.connection as conn

    original = conn.DB_PATH
    try:
        monkeypatch.delenv("TRAVEL_AGENT_DB_PATH", raising=False)
        importlib.reload(conn)
        assert conn.DB_PATH == Path(conn.__file__).parent.parent / "travel_agent.db"

        monkeypatch.setenv("TRAVEL_AGENT_DB_PATH", "/tmp/custom-ta.db")
        importlib.reload(conn)
        assert conn.DB_PATH == Path("/tmp/custom-ta.db")
    finally:
        conn.DB_PATH = original


def _run_main_capturing_port(monkeypatch) -> int:
    captured = {}

    async def noop():
        return None

    import db.seed_data as seed_module

    monkeypatch.setattr(agent_module, "init_db", noop)
    monkeypatch.setattr(seed_module, "seed_data", noop)
    monkeypatch.setattr(
        agent_module.uvicorn, "run", lambda app, host, port: captured.update(host=host, port=port, app=app)
    )
    monkeypatch.delenv("OTEL_EXPORTER_OTLP_ENDPOINT", raising=False)
    monkeypatch.delenv("GENOME_PATH", raising=False)
    monkeypatch.setattr(agent_module, "DOME_ENABLED", False)
    agent_module.main()
    assert captured["host"] == os.environ.get("HOST", "0.0.0.0")
    # main() mounts the AgentCore routes on the served app.
    paths = {getattr(r, "path", None) for r in captured["app"].router.routes}
    assert {"/invocations", "/ping"} <= paths
    return captured["port"]


def test_main_port_defaults_to_9000(monkeypatch):
    monkeypatch.delenv("PORT", raising=False)
    assert _run_main_capturing_port(monkeypatch) == 9000


def test_main_port_reads_PORT(monkeypatch):
    monkeypatch.setenv("PORT", "8080")
    assert _run_main_capturing_port(monkeypatch) == 8080


def test_main_host_defaults_to_all_interfaces(monkeypatch):
    monkeypatch.delenv("HOST", raising=False)
    monkeypatch.delenv("PORT", raising=False)
    _run_main_capturing_port(monkeypatch)


def test_main_host_reads_HOST(monkeypatch):
    """A local evaluation binds to loopback so the agent is not exposed."""
    monkeypatch.setenv("HOST", "127.0.0.1")
    monkeypatch.delenv("PORT", raising=False)
    assert _run_main_capturing_port(monkeypatch) == 9000
