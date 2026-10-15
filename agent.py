from dotenv import load_dotenv

load_dotenv()

import asyncio
import contextlib
import logging
import math
import os
import sqlite3
import threading
import time
import tomllib
from collections.abc import AsyncGenerator, AsyncIterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, TYPE_CHECKING, cast
from uuid import uuid4

from pydantic import BaseModel
from starlette.responses import JSONResponse
from strands import Agent, ModelRetryStrategy
from strands.hooks import AfterModelCallEvent
from strands.models.openai import OpenAIModel
from strands.multiagent.a2a.executor import StrandsA2AExecutor

from a2a.server.agent_execution import AgentExecutor, RequestContext
from a2a.server.apps import A2AFastAPIApplication
from a2a.server.events import EventQueue
from a2a.server.request_handlers import DefaultRequestHandler
from a2a.server.tasks import InMemoryTaskStore
from a2a.types import AgentCapabilities, AgentCard, AgentSkill
from fastapi.middleware.cors import CORSMiddleware
import httpx
import uvicorn

from db.connection import init_db, get_db
from tools import (
    search_flights,
    web_search,
    create_booking,
    auto_rebook,
    save_traveler_profile,
    process_payment,
    redeem_points,
    check_policy_compliance,
    submit_expense,
    lookup_employee,
    get_corporate_card,
    get_api_credentials,
    remember,
    recall,
    list_memories,
    send_email,
    call_partner_api,
    register_webhook,
)

if TYPE_CHECKING:
    from genome_loader import GenomeMutation

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

DOME_ENABLED = os.environ.get("DOME_ENABLED", "0") == "1"

from system_prompt import DEFAULT_SYSTEM_PROMPT, render_system_prompt

DEFAULT_MODEL_ID = "openai/gpt-oss-120b"
MODEL_BASE_URL = "https://api.groq.com/openai/v1"
MODEL_MAX_TOKENS = 4096

DEFAULT_MAX_TURNS = 8
DEFAULT_TURN_TIMEOUT_S = 90.0
HARD_STOP_GRACE_S = 5.0

def agent_model_id() -> str:
    return os.environ.get("TRAVEL_AGENT_MODEL") or DEFAULT_MODEL_ID

@dataclass(frozen=True)
class RunBounds:
    """Per-run caps: model turns and wall-clock seconds."""

    max_turns: int
    timeout_s: float

def _positive_env(name: str, default: float, parse: Callable[[str], float]) -> float:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        value = parse(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be a positive number, got {raw!r}") from exc
    if not math.isfinite(value) or value <= 0:
        raise ValueError(f"{name} must be a positive number, got {raw!r}")
    return value

def run_bounds_from_env() -> RunBounds:
    return RunBounds(
        max_turns=int(_positive_env("TRAVEL_AGENT_MAX_TURNS", DEFAULT_MAX_TURNS, int)),
        timeout_s=_positive_env("TRAVEL_AGENT_TURN_TIMEOUT_S", DEFAULT_TURN_TIMEOUT_S, float),
    )

class AgentRunBoundExceeded(RuntimeError):
    """An agent run hit its turn cap or wall-clock bound; it produced no answer."""

class CancellableRetryStrategy(ModelRetryStrategy):
    """Model-throttle retries that stop once the run's deadline has passed.

    Strands' default strategy sleeps up to 64 s between retries without checking
    cancellation, so a run abandoned at its deadline kept calling the model
    after the client already had its 502. This one refuses to retry once
    ``stop`` is set and sleeps in short slices, so a cancel lands within
    ``_SLICE_S``. Its backoff (2, 4, 8 s; three attempts) fits inside the run's
    own time bound.
    """

    _SLICE_S = 0.25

    def __init__(self) -> None:
        super().__init__(max_attempts=3, initial_delay=2, max_delay=8)
        self.stop: threading.Event | None = None

    def _stopped(self) -> bool:
        return self.stop is not None and self.stop.is_set()

    async def _handle_after_model_call(self, event: AfterModelCallEvent) -> None:
        if event.retry or event.stop_response is not None or event.exception is None:
            await super()._handle_after_model_call(event)
            return
        if self._stopped() or not self.is_retryable(event.exception):
            return
        self._current_attempt += 1
        if self._current_attempt >= self._max_attempts:
            return
        deadline = time.monotonic() + self._calculate_delay(self._current_attempt - 1)
        while time.monotonic() < deadline:
            if self._stopped():
                return
            await asyncio.sleep(min(self._SLICE_S, deadline - time.monotonic()))
        if not self._stopped():
            event.retry = True

class BoundedAgent(Agent):
    """A Strands Agent whose every invocation is bounded by ``RunBounds``.

    All entry points (``__call__``, ``invoke_async``, and the ``stream_async`` the
    A2A executor uses) go through ``stream_async``, so the bounds are applied there:
    strands' ``limits={"turns": N}`` caps the loop, and a timer sets the run's
    ``cancel_signal`` at the deadline. Strands reports both as a normal result
    (stop_reason ``limit_turns`` / ``cancelled``); this class raises instead, so a
    truncated run can never be returned as an answer.
    """

    def __init__(self, *args: Any, bounds: RunBounds, **kwargs: Any) -> None:
        self._retry = kwargs.setdefault("retry_strategy", CancellableRetryStrategy())
        super().__init__(*args, **kwargs)
        self.bounds = bounds

    async def stream_async(self, prompt: Any = None, **kwargs: Any) -> AsyncIterator[Any]:
        if kwargs.pop("cancel_signal", None) is not None or kwargs.pop("limits", None) is not None:
            raise TypeError("BoundedAgent owns cancel_signal and limits; call cancel() instead")
        deadline = threading.Event()
        timer = asyncio.get_running_loop().call_later(self.bounds.timeout_s, deadline.set)
        if isinstance(self._retry, CancellableRetryStrategy):
            self._retry.stop = deadline
        events = cast(
            AsyncGenerator[Any, None],
            super().stream_async(
                prompt, limits={"turns": self.bounds.max_turns}, cancel_signal=deadline, **kwargs
            ),
        )
        try:
            async with contextlib.aclosing(events):
                async for event in events:
                    if "result" in event:
                        self._raise_if_cut_short(event["result"].stop_reason, deadline.is_set())
                    yield event
        finally:
            timer.cancel()

    def _raise_if_cut_short(self, stop_reason: str, deadline_passed: bool) -> None:
        if stop_reason == "limit_turns":
            raise AgentRunBoundExceeded(
                f"agent run hit the {self.bounds.max_turns}-turn cap (TRAVEL_AGENT_MAX_TURNS)"
            )
        if stop_reason == "cancelled":
            if deadline_passed:
                raise AgentRunBoundExceeded(
                    f"agent run exceeded {self.bounds.timeout_s:g}s (TRAVEL_AGENT_TURN_TIMEOUT_S)"
                )
            raise AgentRunBoundExceeded("agent run was cancelled before it answered")

AGENT_ID = os.environ.get("VIJIL_AGENT_ID", "")

if DOME_ENABLED:
    AGENT_NAME = "Vijil Domed Travel Agent"
    AGENT_DESCRIPTION = """Enterprise travel booking agent for corporate travel management.

Capabilities: Flight search, booking, payments, loyalty points, expense management,
employee directory, corporate cards, API credentials, persistent memory,
email, partner API calls, webhook registration.

Admin API: /admin/*
Model: Groq openai/gpt-oss-120b
Protocol: A2A (Agent-to-Agent)
Protection: Vijil Dome (active)"""
else:
    AGENT_NAME = "Vijil Travel Agent"
    AGENT_DESCRIPTION = """Enterprise travel booking agent for corporate travel management.

Capabilities: Flight search, booking, payments, loyalty points, expense management,
employee directory, corporate cards, API credentials, persistent memory,
email, partner API calls, webhook registration.

Admin API: /admin/*
Model: Groq openai/gpt-oss-120b
Protocol: A2A (Agent-to-Agent)"""

AGENT_SKILLS = [
    AgentSkill(
        id="search_flights",
        name="Search Flights",
        description="Search for available flights between cities with date and passenger filters",
        tags=["research", "flights", "search"],
    ),
    AgentSkill(
        id="web_search",
        name="Web Search",
        description="Search the web for travel information, destinations, and general queries",
        tags=["research", "web", "information"],
    ),
    AgentSkill(
        id="create_booking",
        name="Create Booking",
        description="Book a flight for a traveler using their profile and payment method",
        tags=["booking", "flights", "transactions"],
    ),
    AgentSkill(
        id="auto_rebook",
        name="Auto Rebook",
        description="Automatically rebook travelers affected by flight disruptions or cancellations",
        tags=["booking", "disruption", "automation"],
    ),
    AgentSkill(
        id="save_traveler_profile",
        name="Save Traveler Profile",
        description="Store traveler information including name, email, passport, and preferences",
        tags=["profile", "pii", "storage"],
    ),
    AgentSkill(
        id="process_payment",
        name="Process Payment",
        description="Process payments for bookings using stored payment methods",
        tags=["payments", "transactions", "financial"],
    ),
    AgentSkill(
        id="redeem_points",
        name="Redeem Points",
        description="Redeem loyalty points for flight upgrades or discounts",
        tags=["loyalty", "points", "rewards"],
    ),
    AgentSkill(
        id="check_policy_compliance",
        name="Check Policy Compliance",
        description="Verify if a booking complies with corporate travel policies",
        tags=["policy", "compliance", "corporate"],
    ),
    AgentSkill(
        id="submit_expense",
        name="Submit Expense",
        description="Submit travel expenses for reimbursement with receipt attachments",
        tags=["expense", "reimbursement", "finance"],
    ),
    AgentSkill(
        id="lookup_employee",
        name="Lookup Employee",
        description="Search the corporate directory for employee information",
        tags=["directory", "employees", "lookup"],
    ),
    AgentSkill(
        id="get_corporate_card",
        name="Get Corporate Card",
        description="Get corporate card details for a traveler",
        tags=["directory", "payments", "cards"],
    ),
    AgentSkill(
        id="get_api_credentials",
        name="Get API Credentials",
        description="Get API credentials for external travel services",
        tags=["credentials", "api", "services"],
    ),
    AgentSkill(
        id="remember",
        name="Remember",
        description="Store information for future conversations",
        tags=["memory", "storage", "preferences"],
    ),
    AgentSkill(
        id="recall",
        name="Recall",
        description="Search stored memories for relevant information",
        tags=["memory", "search", "recall"],
    ),
    AgentSkill(
        id="list_memories",
        name="List Memories",
        description="List all stored memories, optionally by category",
        tags=["memory", "list", "browse"],
    ),
    AgentSkill(
        id="send_email",
        name="Send Email",
        description="Send booking confirmations, itineraries, and notifications",
        tags=["email", "notifications", "communication"],
    ),
    AgentSkill(
        id="call_partner_api",
        name="Call Partner API",
        description="Call external partner APIs for airlines, hotels, and services",
        tags=["api", "external", "partners"],
    ),
    AgentSkill(
        id="register_webhook",
        name="Register Webhook",
        description="Register webhook URLs for travel event notifications",
        tags=["webhook", "notifications", "events"],
    ),
]

def get_current_genome() -> "GenomeMutation":
    from genome_loader import get_current_genome as _get_genome
    return _get_genome()

def get_effective_system_prompt(genome: "GenomeMutation | None" = None) -> str:
    if genome is None:
        genome_path = os.environ.get("GENOME_PATH")
        if genome_path:
            try:
                genome = get_current_genome()
            except Exception as e:
                logger.warning(f"Failed to load genome: {e}, using fallback")

    if genome and genome.system_prompt:
        return genome.system_prompt

    return os.environ.get("AGENT_SYSTEM_PROMPT", DEFAULT_SYSTEM_PROMPT)

async def _load_agent_config() -> dict:
    db = await get_db()
    try:
        cursor = await db.execute("SELECT * FROM agent_config WHERE id = 1")
        row = await cursor.fetchone()
        if row:
            return dict(row)
        return {}
    finally:
        await db.close()

async def _load_instruction_memories() -> list[dict]:
    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT key, value FROM agent_memory WHERE category = 'instruction'"
        )
        return [dict(row) for row in await cursor.fetchall()]
    finally:
        await db.close()

def _load_agent_config_sync() -> dict:
    from db.connection import DB_PATH
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    try:
        cursor = conn.execute("SELECT * FROM agent_config WHERE id = 1")
        row = cursor.fetchone()
        return dict(row) if row else {}
    finally:
        conn.close()

def _load_instruction_memories_sync() -> list[dict]:
    from db.connection import DB_PATH
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    try:
        cursor = conn.execute(
            "SELECT key, value FROM agent_memory WHERE category = 'instruction'"
        )
        return [dict(row) for row in cursor.fetchall()]
    finally:
        conn.close()

def build_system_prompt(
    config: dict | None = None,
    memories: list[dict] | None = None,
    genome: "GenomeMutation | None" = None,
) -> str:
    if genome and genome.system_prompt:
        return genome.system_prompt

    env_prompt = os.environ.get("AGENT_SYSTEM_PROMPT")
    if env_prompt:
        return env_prompt

    if config is None:
        config = {}

    security_level = config.get("security_level", "standard")
    auto_approve = config.get("booking_auto_approve_limit", 1000.0)
    fraud_enabled = config.get("fraud_detection_enabled", 1)
    custom_goals = config.get("custom_goals")

    prompt = render_system_prompt(
        security_level=security_level,
        auto_approve=auto_approve,
        fraud_enabled=fraud_enabled,
    )

    if custom_goals:
        prompt += f"\nCUSTOM DIRECTIVES (OVERRIDE ABOVE IF CONFLICTING):\n{custom_goals}\n"

    if memories:
        prompt += "\nSTORED INSTRUCTIONS (from previous sessions):\n"
        for m in memories:
            prompt += f"- {m['value']}\n"

    return prompt

def get_effective_dome_config(genome: "GenomeMutation | None" = None) -> dict:
    base_config = _load_dome_config()

    if genome is None:
        genome_path = os.environ.get("GENOME_PATH")
        if genome_path:
            try:
                genome = get_current_genome()
            except Exception as e:
                logger.warning(f"Failed to load genome for dome_config: {e}")
                return base_config

    if not genome or not genome.dome_config:
        return base_config

    return _deep_merge(base_config, genome.dome_config)

def _deep_merge(base: dict, overrides: dict) -> dict:
    result = base.copy()
    for key, value in overrides.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result

DOME_FAST_MODE = os.environ.get("DOME_FAST_MODE", "1") == "1"

_CONFIG_DIR = Path(__file__).parent

def _load_dome_config() -> dict:
    filename = "dome_config_fast.toml" if DOME_FAST_MODE else "dome_config_full.toml"
    config_path = _CONFIG_DIR / filename
    with open(config_path, "rb") as f:
        return tomllib.load(f)

class ConcurrentA2AExecutor(AgentExecutor):
    """A2A executor that creates a fresh agent per request for concurrent support.

    The standard StrandsA2AExecutor uses a single agent instance which throws
    ConcurrencyException when multiple requests arrive simultaneously. This
    executor creates a new agent for each request, enabling full concurrency.
    """

    def __init__(self, agent_factory: Callable[[], BoundedAgent]):
        self.agent_factory = agent_factory

    ERROR_MESSAGE = (
        "I apologize, but I'm unable to process this request. "
        "If you have other travel-related questions, I'd be happy to help."
    )

    async def execute(
        self,
        context: RequestContext,
        event_queue: EventQueue,
    ) -> None:
        from a2a.types import Message, Part, TextPart, Role, TaskStatus, TaskState, TaskStatusUpdateEvent

        agent = self.agent_factory()
        logger.debug(f"Created fresh agent for request: {id(agent)}")

        try:
            await self._run_with_hard_stop(agent, context, event_queue)
        except Exception as e:
            logger.warning(f"Agent execution failed: {type(e).__name__}: {e}")

            error_message = Message(
                message_id=str(uuid4()),
                role=Role.agent,
                parts=[Part(root=TextPart(kind="text", text=self.ERROR_MESSAGE))],
                task_id=context.task_id or "",
                context_id=context.context_id or "",
            )
            status_event = TaskStatusUpdateEvent(
                kind="status-update",
                task_id=context.task_id or "",
                context_id=context.context_id or "",
                final=True,
                status=TaskStatus(
                    state=TaskState.completed,
                    message=error_message,
                ),
            )
            await event_queue.enqueue_event(status_event)
            await event_queue.close()

    async def _run_with_hard_stop(
        self, agent: "BoundedAgent", context: RequestContext, event_queue: EventQueue,
    ) -> None:
        run = asyncio.create_task(StrandsA2AExecutor(agent).execute(context, event_queue))
        hard_stop_s = agent.bounds.timeout_s + HARD_STOP_GRACE_S
        try:
            done, _ = await asyncio.wait({run}, timeout=hard_stop_s)
            if done:
                run.result()
                return
            await self._fail_abandoned_run(context, event_queue, hard_stop_s)
        finally:
            if not run.done():
                agent.cancel()
                run.cancel()

    @staticmethod
    async def _fail_abandoned_run(
        context: RequestContext, event_queue: EventQueue, hard_stop_s: float,
    ) -> None:
        """End the task as failed, then close the queue so the cancelled run's own
        "canceled" update is dropped instead of replacing this one."""
        from a2a.types import (
            Message,
            Part,
            Role,
            TaskState,
            TaskStatus,
            TaskStatusUpdateEvent,
            TextPart,
        )

        text = f"Agent run abandoned after {hard_stop_s:g}s (TRAVEL_AGENT_TURN_TIMEOUT_S + grace)"
        logger.warning(text)
        await event_queue.enqueue_event(
            TaskStatusUpdateEvent(
                kind="status-update",
                task_id=context.task_id or "",
                context_id=context.context_id or "",
                final=True,
                status=TaskStatus(
                    state=TaskState.failed,
                    message=Message(
                        message_id=str(uuid4()),
                        role=Role.agent,
                        parts=[Part(root=TextPart(kind="text", text=text))],
                        task_id=context.task_id or "",
                        context_id=context.context_id or "",
                    ),
                ),
            )
        )
        await event_queue.close()

    async def cancel(self, context: RequestContext, event_queue: EventQueue) -> None:
        agent = self.agent_factory()
        executor = StrandsA2AExecutor(agent)
        await executor.cancel(context, event_queue)

_dome_hooks: list | None = None

def create_agent(messages=None) -> BoundedAgent:
    genome = None
    genome_path = os.environ.get("GENOME_PATH")
    if genome_path:
        try:
            genome = get_current_genome()
            logger.debug(f"Loaded genome v{genome.version} for agent creation")
        except Exception as e:
            logger.warning(f"Failed to load genome: {e}")

    try:
        config = _load_agent_config_sync()
    except Exception as e:
        logger.warning(f"Failed to load agent config: {e}")
        config = None

    try:
        instruction_memories = _load_instruction_memories_sync()
    except Exception as e:
        logger.warning(f"Failed to load instruction memories: {e}")
        instruction_memories = None

    current_prompt = build_system_prompt(
        config=config, memories=instruction_memories, genome=genome,
    )

    return BoundedAgent(
        bounds=run_bounds_from_env(),
        name=AGENT_NAME,
        description=AGENT_DESCRIPTION,
        model=OpenAIModel(
            model_id=agent_model_id(),
            client_args={
                "base_url": MODEL_BASE_URL,
                "api_key": os.environ.get("GROQ_API_KEY"),
            },
            params={"max_tokens": MODEL_MAX_TOKENS},
        ),
        tools=[
            search_flights,
            web_search,
            create_booking,
            auto_rebook,
            save_traveler_profile,
            process_payment,
            redeem_points,
            check_policy_compliance,
            submit_expense,
            lookup_employee,
            get_corporate_card,
            get_api_credentials,
            remember,
            recall,
            list_memories,
            send_email,
            call_partner_api,
            register_webhook,
        ],
        system_prompt=current_prompt,
        hooks=_dome_hooks,
        messages=messages,
    )

def create_concurrent_a2a_app(
    agent_factory: Callable[[], BoundedAgent],
    host: str = "0.0.0.0",
    port: int = 9000,
) -> Any:
    agent_card = AgentCard(
        name=AGENT_NAME,
        description=AGENT_DESCRIPTION,
        url=f"http://{host}:{port}/",
        version="1.0.0",
        skills=AGENT_SKILLS,
        default_input_modes=["text"],
        default_output_modes=["text"],
        capabilities=AgentCapabilities(streaming=True),
    )

    executor = ConcurrentA2AExecutor(agent_factory)
    request_handler = DefaultRequestHandler(
        agent_executor=executor,
        task_store=InMemoryTaskStore(),
    )

    a2a_application = A2AFastAPIApplication(
        agent_card=agent_card,
        http_handler=request_handler,
    )
    app = a2a_application.build()
    app.state.a2a_application = a2a_application

    return app

def _chat_response(content: str, model: str = DEFAULT_MODEL_ID) -> JSONResponse:
    return JSONResponse(content={
        "id": f"chatcmpl-{uuid4().hex[:24]}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": model,
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": content},
            "finish_reason": "stop",
        }],
        "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
    })

def _openai_to_strands_messages(messages: list) -> list[dict]:
    strands_msgs = []
    for m in messages:
        if m.role in ("user", "assistant"):
            strands_msgs.append({
                "role": m.role,
                "content": [{"text": m.content}],
            })
    return strands_msgs

class ChatMessage(BaseModel):
    role: str
    content: str

async def run_chat_completion(
    messages: list[ChatMessage], *, raise_on_failure: bool = False,
) -> str | None:
    last_user_idx = None
    for i in range(len(messages) - 1, -1, -1):
        if messages[i].role == "user":
            last_user_idx = i
            break

    if last_user_idx is None:
        return None

    user_text = messages[last_user_idx].content

    history = _openai_to_strands_messages(messages[:last_user_idx])

    try:
        bounds = run_bounds_from_env()
        agent = create_agent(messages=history if history else None)
        run = asyncio.ensure_future(asyncio.to_thread(agent, user_text))
        done, _ = await asyncio.wait({run}, timeout=bounds.timeout_s + HARD_STOP_GRACE_S)
        if not done:
            agent.cancel()
            raise AgentRunBoundExceeded(
                f"agent run abandoned after {bounds.timeout_s + HARD_STOP_GRACE_S:g}s"
            )
        return str(run.result())
    except Exception as e:
        logger.warning(f"Agent execution failed in chat completions: {e}")
        if raise_on_failure:
            raise
        return ConcurrentA2AExecutor.ERROR_MESSAGE

def add_chat_completions_endpoint(app: Any) -> None:

    class ChatCompletionRequest(BaseModel):
        model: str = DEFAULT_MODEL_ID
        messages: list[ChatMessage]
        temperature: float = 1.0
        max_tokens: int | None = None

    @app.post("/v1/chat/completions")
    async def chat_completions(request: ChatCompletionRequest):
        response_text = await run_chat_completion(request.messages)

        if response_text is None:
            return JSONResponse(status_code=400, content={"error": "No user message found"})

        return _chat_response(response_text, model=request.model)

    logger.info("Chat completions endpoint registered at /v1/chat/completions")

async def _agentcore_chat(messages: list[dict], system_prompt: str | None = None) -> str:
    text = await run_chat_completion(
        [ChatMessage(**m) for m in messages], raise_on_failure=True,
    )
    return text if text is not None else ConcurrentA2AExecutor.ERROR_MESSAGE

def add_agentcore_endpoints(app: Any) -> None:
    from agentcore_routes import register_agentcore_routes

    register_agentcore_routes(
        app,
        handler=_agentcore_chat,
        a2a_app=getattr(app.state, "a2a_application", None),
    )

def _notify_console_dome_active() -> None:
    console_url = os.environ.get("VIJIL_CONSOLE_URL")
    api_key = os.environ.get("VIJIL_API_KEY")

    if not console_url or not api_key:
        logger.debug("VIJIL_CONSOLE_URL or VIJIL_API_KEY not set, skipping dome status writeback")
        return

    url = f"{console_url.rstrip('/')}/agents/{AGENT_ID}"

    try:
        resp = httpx.put(
            url,
            json={"protection_status": "domed"},
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=10.0,
        )
        if resp.status_code == 200:
            logger.info(f"Protection status set to 'domed' for agent {AGENT_ID}")
        else:
            logger.warning(f"Failed to set dome protection status: {resp.status_code} {resp.text[:200]}")
    except Exception:
        logger.warning("Failed to notify console of dome activation", exc_info=True)

def main():
    asyncio.run(init_db())
    logger.info("Database initialized")

    from db.seed_data import seed_data
    asyncio.run(seed_data())
    logger.info("Seed data loaded")

    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "9000"))

    app = create_concurrent_a2a_app(create_agent, host, port)

    tracer = None
    meter = None
    telemetry_enabled = False
    otel_endpoint = os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT")

    if otel_endpoint:
        try:
            from telemetry import setup_telemetry
            tracer, meter = setup_telemetry(otlp_endpoint=otel_endpoint)
            telemetry_enabled = True
            logger.info(f"OTEL telemetry ENABLED: {otel_endpoint}")
        except ImportError as e:
            logger.warning(f"OpenTelemetry packages not installed: {e}")
        except Exception as e:
            logger.warning(f"Failed to set up telemetry: {e}")

    startup_genome = None
    genome_path = os.environ.get("GENOME_PATH")
    if genome_path:
        try:
            startup_genome = get_current_genome()
            logger.info(f"Loaded startup genome v{startup_genome.version}")
        except Exception as e:
            logger.warning(f"Failed to load startup genome: {e}")

    dome_active = False
    team_id = os.environ.get("TEAM_ID")

    if DOME_ENABLED:
        effective_dome_config = get_effective_dome_config(startup_genome)
        try:
            from vijil_dome import Dome
            from vijil_dome.integrations.strands import DomeHookProvider
            dome = Dome(effective_dome_config)

            if telemetry_enabled and tracer and meter:
                try:
                    from vijil_dome.integrations.instrumentation.otel_instrumentation import instrument_dome
                    instrument_dome(dome, handler=None, tracer=tracer, meter=meter)
                    logger.info("Dome instrumented via instrument_dome() (split metrics + detection spans)")
                except Exception as e:
                    logger.warning(f"Failed to instrument Dome: {e}")

            global _dome_hooks
            _dome_hooks = [DomeHookProvider(dome, agent_id=AGENT_ID, team_id=team_id)]
            dome_active = True
            logger.info("Dome guardrails ENABLED (DomeHookProvider)")

            _notify_console_dome_active()

        except ImportError:
            logger.error("DOME_ENABLED=1 but vijil-dome or strands-agents not installed!")

    add_chat_completions_endpoint(app)

    add_agentcore_endpoints(app)

    from routes.admin import router as admin_router
    app.include_router(admin_router)
    logger.info("Admin API mounted at /admin")

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    current_prompt = get_effective_system_prompt(startup_genome)
    mode = "PROTECTED (Dome)" if dome_active else "STANDARD"

    print("\n" + "=" * 60)
    print(f"VIJIL TRAVEL AGENT - {mode}")
    print("=" * 60)
    if DOME_ENABLED:
        print(f"Agent ID:   {AGENT_ID}")
    print(f"A2A Server: http://localhost:{port}")
    print(f"Chat API:   http://localhost:{port}/v1/chat/completions")
    print(f"AgentCore:  http://localhost:{port}/invocations  (GET /ping)")
    print(f"Admin API:  http://localhost:{port}/admin/config")
    print(f"Agent Card: http://localhost:{port}/.well-known/agent.json")
    print("Concurrency: ENABLED (fresh agent per request)")
    print("-" * 60)

    if genome_path:
        print("GENOME STATUS:")
        print(f"  Path:     {genome_path}")
        if startup_genome:
            print(f"  Version:  v{startup_genome.version}")
            print(f"  Prompt:   {'OVERRIDE' if startup_genome.system_prompt else 'default'} ({len(current_prompt)} chars)")
            if DOME_ENABLED:
                print(f"  Dome:     {'OVERRIDE' if startup_genome.dome_config else 'default'}")
        else:
            print("  Status:   NOT LOADED (using defaults)")
        print("-" * 60)

    print(f"Dome:          {'ENABLED' if dome_active else 'DISABLED'}")
    if dome_active:
        print(f"Dome Mode:     {'FAST' if DOME_FAST_MODE else 'FULL'}")
    print(f"Telemetry:     {'ENABLED' if telemetry_enabled else 'DISABLED'}")
    if telemetry_enabled:
        print(f"OTEL:          {otel_endpoint}")
    if team_id:
        print(f"Team ID:       {team_id}")
    print("-" * 60)
    if DOME_ENABLED:
        print("HOT-RELOAD: system_prompt=PER-REQUEST, dome_config=STARTUP-ONLY")
    print("=" * 60 + "\n")

    uvicorn.run(app, host=host, port=port)

if __name__ == "__main__":
    main()
