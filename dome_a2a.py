"""Dome A2A Integration — Starlette/FastAPI middleware for A2A JSON-RPC.

Temporary home: alongside agent.py in vijil-travel-agent.
Future home: vijil_dome/integrations/a2a/middleware.py

When moved, only the import path changes:
    # Before (local):
    from dome_a2a import DomeA2AMiddleware, DEFAULT_BLOCKED_MESSAGE
    # After (vijil-dome package):
    from vijil_dome.integrations.a2a import DomeA2AMiddleware, DEFAULT_BLOCKED_MESSAGE
"""

import json
import logging
from typing import Optional

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

logger = logging.getLogger(__name__)

# A2A JSON-RPC methods that carry user messages
_A2A_MESSAGE_METHODS = frozenset({
    "message/send",
    "tasks/send",
    "messages/send",
    "tasks/sendSubscribe",
})

# Crafted to match Diamond's RefusalDetector patterns for accurate security scoring
DEFAULT_BLOCKED_MESSAGE = (
    "I'm sorry, but I can't help with that request. "
    "It appears to contain content that violates my usage policies. "
    "I'd be happy to assist you with legitimate travel-related questions instead."
)


def extract_a2a_message(body: dict) -> str | None:
    """Extract user text from an A2A JSON-RPC request body."""
    method = body.get("method", "")
    if method not in _A2A_MESSAGE_METHODS:
        return None

    message = body.get("params", {}).get("message", {})
    if isinstance(message, dict):
        parts = message.get("parts", [])
        texts = [p.get("text", "") for p in parts if isinstance(p, dict) and p.get("text")]
        return " ".join(texts) if texts else None
    return None


def a2a_blocked_response(request_id: str | None, message: str = DEFAULT_BLOCKED_MESSAGE) -> dict:
    """Build an A2A JSON-RPC response for a blocked request."""
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "result": {
            "status": {
                "state": "completed",
                "message": {
                    "role": "agent",
                    "parts": [{"type": "text", "text": message}],
                },
            }
        },
    }


class DomeA2AMiddleware(BaseHTTPMiddleware):
    """Starlette middleware that applies Dome input guardrails to A2A requests.

    Scans user messages extracted from A2A JSON-RPC envelopes. Blocked requests
    receive a valid A2A JSON-RPC refusal response.

    Telemetry (split metrics + Darwin spans) is handled upstream by
    instrument_dome() — this middleware only orchestrates the scan.

    Usage:
        from vijil_dome import Dome
        dome = Dome(config)
        app.add_middleware(DomeA2AMiddleware, dome=dome, agent_id="...", team_id="...")
    """

    def __init__(
        self,
        app,
        dome,
        agent_id: str = "",
        team_id: str = "",
        blocked_message: str = DEFAULT_BLOCKED_MESSAGE,
    ):
        super().__init__(app)
        self.dome = dome
        self.agent_id = agent_id
        self.team_id = team_id
        self.blocked_message = blocked_message

    async def dispatch(self, request: Request, call_next):
        if request.method != "POST":
            return await call_next(request)

        content_type = request.headers.get("content-type", "")
        if "application/json" not in content_type:
            return await call_next(request)

        try:
            body_bytes = await request.body()
            body = json.loads(body_bytes)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return await call_next(request)

        user_message = extract_a2a_message(body)
        if user_message:
            scan = await self.dome.input_guardrail.async_scan(
                user_message,
                agent_id=self.agent_id,
                team_id=self.team_id,
            )
            if scan.flagged:
                logger.warning("Dome blocked A2A request: %s...", user_message[:80])
                return JSONResponse(
                    content=a2a_blocked_response(body.get("id"), self.blocked_message)
                )

        # Replay consumed body bytes for downstream handlers
        async def receive():
            return {"type": "http.request", "body": body_bytes}
        request._receive = receive

        return await call_next(request)
