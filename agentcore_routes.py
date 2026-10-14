from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from typing import Any

from fastapi import FastAPI, Request
from pydantic import BaseModel, ValidationError, model_validator
from starlette.responses import JSONResponse, Response

logger = logging.getLogger(__name__)

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

    async def _dispatch(request: Request) -> Response:
        try:
            payload = await request.json()
        except ValueError:
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

        try:
            text = await handler(
                messages=[m.model_dump() for m in invoke.messages],
                system_prompt=invoke.system_prompt,
            )
        except Exception:
            logger.exception("AgentCore chat handler failed")
            return JSONResponse(
                status_code=502, content={"error": "Agent execution failed."}
            )
        return JSONResponse({"response": text})

    async def _ping() -> dict[str, str]:
        return {"status": "ok"}

    start = len(app.router.routes)
    app.add_api_route("/invocations", _dispatch, methods=["POST"])
    app.add_api_route("/", _dispatch, methods=["POST"])
    app.add_api_route("/ping", _ping, methods=["GET"])
    added = app.router.routes[start:]
    del app.router.routes[start:]
    app.router.routes[0:0] = added

    logger.info("AgentCore routes registered: POST /invocations, POST /, GET /ping")
