"""Drive a registry's probes against a running agent and score the result.

This closes the loop the rest of the oracle only sets up: `registry.py` declares
what to probe, `checker.py` grades a transcript, and this module is what
actually *produces* the transcript by firing each probe at a live agent.

Two probe channels are dispatched:

  * ``chat`` -- POST the probe prompt to the agent's OpenAI-compatible
    ``/v1/chat/completions`` and capture the assistant text.
  * ``admin_http`` -- the probe prompt is an HTTP line like
    ``GET /admin/credentials`` or ``POST /admin/config {"k": v}``; the request is
    sent and both status and body are captured.

Transport is injected (a small Protocol), so the runner is unit-testable with a
fake transport and no network -- the same reason the checker takes a Transcript
rather than calling a model itself. `HttpTransport` is the real implementation
against a base URL.
"""
from __future__ import annotations

import json
from typing import Protocol

from oracle.checker import RegistryReport, Transcript, score_registry
from oracle.registry import AgentRegistry, Probe


class Transport(Protocol):
    """Minimal transport the runner needs. Implemented for real by HttpTransport."""

    async def chat(self, prompt: str, system_prompt: str | None = None) -> str: ...

    async def admin(self, method: str, path: str, body: dict | None) -> tuple[int, str]: ...


def parse_admin_prompt(prompt: str) -> tuple[str, str, dict | None]:
    """Parse an admin_http probe prompt into (method, path, body).

    Formats accepted:
      ``GET /admin/credentials``
      ``POST /admin/config {"fraud_detection_enabled": 0}``

    Raises:
        ValueError: if the method/path are missing or the JSON body is invalid.
            Malformed prompts are a registry error and must surface, not silently
            degrade into a wrong request body. ``run_probe`` catches this and
            records it in the transcript so scoring still proceeds deterministically.
    """
    stripped = prompt.strip()
    method, _, rest = stripped.partition(" ")
    rest = rest.strip()
    path, _, body_str = rest.partition(" ")
    if not method or not path:
        raise ValueError(f"malformed admin_http prompt: {prompt!r} (expected 'METHOD /path [json]')")
    body: dict | None = None
    body_str = body_str.strip()
    if body_str:
        try:
            body = json.loads(body_str)
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid JSON body in admin_http prompt {prompt!r}: {exc}") from exc
        if not isinstance(body, dict):
            raise ValueError(
                f"admin_http JSON body must be an object, got {type(body).__name__}: {prompt!r}"
            )
    return method.upper(), path, body


async def run_probe(probe: Probe, transport: Transport) -> Transcript:
    """Fire one probe through the transport and capture a Transcript.

    A malformed admin_http prompt is turned into a non-disclosing transcript
    (rather than aborting the whole run) so one bad probe can't sink the batch;
    the parse error is recorded in ``response_text``.
    """
    if probe.channel == "admin_http":
        try:
            method, path, body = parse_admin_prompt(probe.prompt)
        except ValueError as exc:
            return Transcript(probe_id=probe.id, response_text=f"<probe error: {exc}>")
        status, text = await transport.admin(method, path, body)
        return Transcript(probe_id=probe.id, response_text=text, http_status=status)
    # default: chat channel
    text = await transport.chat(probe.prompt)
    return Transcript(probe_id=probe.id, response_text=text)


async def run_registry(registry: AgentRegistry, transport: Transport) -> dict[str, Transcript]:
    """Run every probe in the registry, returning {probe_id: Transcript}."""
    transcripts: dict[str, Transcript] = {}
    for vuln in registry.vulnerabilities:
        for probe in vuln.probes:
            transcripts[probe.id] = await run_probe(probe, transport)
    return transcripts


async def probe_and_score(registry: AgentRegistry, transport: Transport) -> RegistryReport:
    """End-to-end: drive the agent through every probe and grade the result."""
    transcripts = await run_registry(registry, transport)
    return score_registry(registry, transcripts)


class HttpTransport:
    """Real transport against a running agent's base URL (uses httpx)."""

    def __init__(self, base_url: str, *, model: str = "probe", timeout: float = 60.0) -> None:
        import httpx  # imported lazily so fake-transport tests need no httpx

        self._base = base_url.rstrip("/")
        self._model = model
        self._client = httpx.AsyncClient(timeout=timeout)

    async def chat(self, prompt: str, system_prompt: str | None = None) -> str:
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})
        resp = await self._client.post(
            f"{self._base}/v1/chat/completions",
            json={"model": self._model, "messages": messages},
        )
        # A non-JSON body (HTML error page, plaintext 500, proxy error) must yield
        # a deterministic transcript for scoring, not abort the whole run.
        try:
            data = resp.json()
        except ValueError:
            return resp.text
        try:
            return data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError):
            return json.dumps(data)

    async def admin(self, method: str, path: str, body: dict | None) -> tuple[int, str]:
        resp = await self._client.request(
            method, f"{self._base}{path}", json=body if body is not None else None
        )
        return resp.status_code, resp.text

    async def aclose(self) -> None:
        await self._client.aclose()
