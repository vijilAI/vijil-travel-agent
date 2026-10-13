"""Bedrock AgentCore HTTP-protocol routes for the travel agent.

AgentCore code-mode deployments speak the HTTP protocol contract: the process
listens on ``0.0.0.0:$PORT`` and serves ``POST /invocations`` and ``GET /ping``.
Different callers send different bodies to the invocation endpoint, so a single
dispatcher serves ``POST /invocations`` and ``POST /``:

* a JSON-RPC 2.0 object, or a JSON array (an A2A batch), goes to the A2A
  application's request handler;
* a ``{"messages": [{"role", "content"}, ...], "system_prompt": str | None}``
  body goes to the agent's chat handler and returns ``{"response": "<text>"}``.

The dispatch logic is adapted from
vijilAI/vijil-sample-agents@fcc8ab7 shell/dome_agent_runtime.py:292-359
(``register_agentcore_invoke_routes``) and the ``GET /ping`` route from
shell/server.py:45-47. The Dome singleton and OTEL flush from that source are
deliberately not carried over; Dome guarding in this agent happens inside the
Strands Agent via hooks.
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from typing import Any

from fastapi import FastAPI, Request
from pydantic import BaseModel, ValidationError, model_validator
from starlette.responses import JSONResponse, Response

logger = logging.getLogger(__name__)

# handler(messages=[{"role", "content"}, ...], system_prompt=str | None) -> text
ChatHandler = Callable[..., Awaitable[str]]


class _InvokeMessage(BaseModel):
    role: str
    content: str


class _InvokeRequest(BaseModel):
    messages: list[_InvokeMessage]
    system_prompt: str | None = None

    @model_validator(mode="after")
    def _require_user_message(self) -> _InvokeRequest:
        if not any(m.role == "user" for m in self.messages):
            raise ValueError("at least one message with role 'user' is required")
        return self


def register_agentcore_routes(
    app: FastAPI,
    handler: ChatHandler,
    a2a_app: Any | None = None,
) -> None:
    """Register ``POST /invocations``, ``POST /`` and ``GET /ping`` on ``app``.

    Args:
        app: FastAPI application to extend.
        handler: Async chat callable, invoked as
            ``handler(messages=..., system_prompt=...)`` and returning text.
        a2a_app: The object that owns the A2A ``_handle_requests(request)``
            coroutine (an ``A2AFastAPIApplication`` instance, not the FastAPI
            app its ``build()`` returns). When None, JSON-RPC bodies and
            JSON arrays cannot be served and are rejected with 422.
    """

    async def _dispatch(request: Request) -> Response:
        try:
            payload = await request.json()
        except ValueError:  # JSONDecodeError and UnicodeDecodeError
            return JSONResponse(status_code=400, content={"error": "Invalid JSON."})

        if isinstance(payload, list):
            if a2a_app is not None:
                return await a2a_app._handle_requests(request)
            return JSONResponse(
                status_code=422, content={"error": "Invalid request payload."}
            )

        if not isinstance(payload, dict):
            return JSONResponse(
                status_code=422, content={"error": "Invalid request payload."}
            )

        if payload.get("jsonrpc") == "2.0" and a2a_app is not None:
            return await a2a_app._handle_requests(request)

        try:
            invoke = _InvokeRequest.model_validate(payload)
        except ValidationError:
            return JSONResponse(
                status_code=422, content={"error": "Invalid request payload."}
            )

        text = await handler(
            messages=[m.model_dump() for m in invoke.messages],
            system_prompt=invoke.system_prompt,
        )
        return JSONResponse({"response": text})

    async def _ping() -> dict[str, str]:
        return {"status": "ok"}

    # A2AFastAPIApplication.build() already owns POST "/" for JSON-RPC only.
    # Starlette matches routes in order, so ours must come first for POST "/"
    # to accept chat bodies as well.
    start = len(app.router.routes)
    app.add_api_route("/invocations", _dispatch, methods=["POST"])
    app.add_api_route("/", _dispatch, methods=["POST"])
    app.add_api_route("/ping", _ping, methods=["GET"])
    added = app.router.routes[start:]
    del app.router.routes[start:]
    app.router.routes[0:0] = added

    logger.info("AgentCore routes registered: POST /invocations, POST /, GET /ping")
