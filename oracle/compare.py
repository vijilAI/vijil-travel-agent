"""A/B comparison of two live agents (baseline vs variant) with repeated trials.

For each side and each trial, every probe in the registry is fired as an
independent request set (a fresh transport per trial, and ``HttpTransport``
sends a single-message conversation per call, so no conversation state carries
over) and graded with the existing deterministic checker
(:func:`oracle.checker.evaluate_probe`). Probing is delegated to
:func:`oracle.probe_runner.run_probe`; verdict semantics are unchanged.

Fail closed: a transport exception, timeout, or HTTP 5xx is recorded as an
``error`` and is never counted as ``not_exploited``. A vulnerability trial is

  * ``exploited``     -- any of its probes disclosed the weakness (positive
                         evidence stands even if another probe errored);
  * ``errors``        -- else, if any probe errored (absence of a leak cannot be
                         asserted when a probe did not complete);
  * ``not_exploited`` -- else (every probe completed and none disclosed).

So ``exploited + not_exploited + errors == trials`` for every vulnerability.
"""
from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from oracle.canary import token as canary_token
from oracle.checker import evaluate_probe
from oracle.probe_runner import HttpTransport, Transport, run_probe
from oracle.registry import AgentRegistry

EXPLOITED = "exploited"
NOT_EXPLOITED = "not_exploited"
ERROR = "error"

TransportFactory = Callable[[], Transport]


class TransportError(Exception):
    """Raised for an HTTP 5xx response so it cannot be mistaken for a clean miss."""


async def _raise_on_5xx(response: Any) -> None:
    if response.status_code >= 500:
        raise TransportError(
            f"HTTP {response.status_code} from {response.request.method} {response.request.url}"
        )


class FailClosedHttpTransport(HttpTransport):
    """``HttpTransport`` that turns any 5xx response into a ``TransportError``.

    ``HttpTransport.chat`` deliberately swallows non-JSON error bodies into a
    transcript; for a comparison that would turn a server failure into a
    not-exploited verdict, so a response hook raises instead. Timeouts and
    connection errors already propagate as httpx exceptions.
    """

    def __init__(self, base_url: str, *, model: str = "probe", timeout: float = 60.0) -> None:
        super().__init__(base_url, model=model, timeout=timeout)
        self._client.event_hooks = {"request": [], "response": [_raise_on_5xx]}


def _now() -> str:
    return datetime.now(UTC).isoformat()


def registry_digest(path: str | Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class CanaryMapError(ValueError):
    """The canary map file is malformed or names a token the registry does not declare."""


def registry_canary_tokens(registry: AgentRegistry) -> set[str]:
    return {
        canary_token(registry.agent, v.id, c.slot)
        for v in registry.vulnerabilities
        for c in v.canaries
    }


def validate_canary_map(registry: AgentRegistry, canary_map: Any) -> dict[str, str]:
    """Check ``{original_token: blind_value}`` against the registry's canaries."""
    if not isinstance(canary_map, dict):
        raise CanaryMapError("canary map must be a JSON object {original_token: blind_value}")
    known = registry_canary_tokens(registry)
    seen: dict[str, str] = {}
    for original, blind in canary_map.items():
        if not isinstance(original, str) or not isinstance(blind, str):
            raise CanaryMapError(f"canary map entries must be strings: {original!r}: {blind!r}")
        if original not in known:
            raise CanaryMapError(
                f"canary map key {original!r} is not a canary token declared by registry "
                f"agent {registry.agent!r}"
            )
        if not blind:
            raise CanaryMapError(f"canary map value for {original!r} is empty")
        if blind in seen and seen[blind] != original:
            raise CanaryMapError(
                f"blind value {blind!r} maps to both {seen[blind]!r} and {original!r}"
            )
        seen[blind] = original
    return dict(canary_map)


def load_canary_map(path: str | Path, registry: AgentRegistry) -> tuple[dict[str, str], str]:
    """Load and validate a canary map file; returns (map, sha256 of the file bytes)."""
    raw = Path(path).read_bytes()
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise CanaryMapError(f"canary map {path} is not valid JSON: {exc}") from exc
    return validate_canary_map(registry, data), hashlib.sha256(raw).hexdigest()


def make_translator(canary_map: dict[str, str] | None) -> Callable[[str], str]:
    """Return a function replacing each blind value with its original token.

    Single pass over a longest-first alternation, so a replacement is never
    itself re-scanned for further blind values.
    """
    if not canary_map:
        return lambda text: text
    reverse = {blind: original for original, blind in canary_map.items()}
    pattern = re.compile(
        "|".join(re.escape(b) for b in sorted(reverse, key=len, reverse=True))
    )
    return lambda text: pattern.sub(lambda m: reverse[m.group(0)], text)


async def _run_side_trial(
    registry: AgentRegistry,
    transport: Transport,
    translate: Callable[[str], str] = lambda text: text,
) -> dict[str, tuple[str, str]]:
    """One trial on one side: {probe_id: (verdict, detail)}."""
    out: dict[str, tuple[str, str]] = {}
    for vuln in registry.vulnerabilities:
        for probe in vuln.probes:
            try:
                transcript = await run_probe(probe, transport)
            except Exception as exc:  # noqa: BLE001 - every failure is an error verdict
                out[probe.id] = (ERROR, f"{type(exc).__name__}: {exc}")
                continue
            transcript = transcript.model_copy(
                update={"response_text": translate(transcript.response_text or "")}
            )
            result = evaluate_probe(
                probe, transcript, namespace=registry.agent, vuln_id=vuln.id
            )
            out[probe.id] = (EXPLOITED if result.disclosed else NOT_EXPLOITED, "")
    return out


async def run_side(
    registry: AgentRegistry,
    factory: TransportFactory,
    trials: int,
    *,
    url: str = "",
    canary_map: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Run ``trials`` independent trials against one side and aggregate."""
    started = _now()
    translate = make_translator(canary_map)
    probe_verdicts: dict[str, list[str]] = {}
    probe_errors: dict[str, list[str]] = {}
    for _ in range(trials):
        transport = factory()  # fresh transport (client, cookies) per trial
        try:
            trial = await _run_side_trial(registry, transport, translate)
        finally:
            aclose = getattr(transport, "aclose", None)
            if aclose is not None:
                await aclose()
        for pid, (verdict, detail) in trial.items():
            probe_verdicts.setdefault(pid, []).append(verdict)
            if verdict == ERROR:
                probe_errors.setdefault(pid, []).append(detail)

    vulns: dict[str, Any] = {}
    for vuln in registry.vulnerabilities:
        counts = {EXPLOITED: 0, NOT_EXPLOITED: 0, "errors": 0}
        for t in range(trials):
            verdicts = [probe_verdicts[p.id][t] for p in vuln.probes]
            if EXPLOITED in verdicts:
                counts[EXPLOITED] += 1
            elif ERROR in verdicts:
                counts["errors"] += 1
            else:
                counts[NOT_EXPLOITED] += 1
        vulns[vuln.id] = {
            "exploited": counts[EXPLOITED],
            "not_exploited": counts[NOT_EXPLOITED],
            "errors": counts["errors"],
            "trials": trials,
            "probes": {
                p.id: {
                    "verdicts": probe_verdicts[p.id],
                    "error_details": probe_errors.get(p.id, []),
                }
                for p in vuln.probes
            },
        }
    return {"url": url, "started_at": started, "finished_at": _now(), "vulnerabilities": vulns}


def probes_all_errored(side: dict[str, Any]) -> list[str]:
    """Probe ids whose every trial on this side was an error."""
    bad: list[str] = []
    for vuln in side["vulnerabilities"].values():
        for pid, pdata in vuln["probes"].items():
            verdicts = pdata["verdicts"]
            if verdicts and all(v == ERROR for v in verdicts):
                bad.append(pid)
    return bad


async def run_compare(
    registry_path: str | Path,
    baseline_factory: TransportFactory,
    variant_factory: TransportFactory,
    trials: int,
    *,
    baseline_url: str = "",
    variant_url: str = "",
    canary_map: dict[str, str] | None = None,
    canary_map_sha256: str | None = None,
) -> dict[str, Any]:
    """Run the comparison. ``canary_map`` ({original_token: blind_value}) is
    applied to both sides' responses before grading; only its sha256 is recorded."""
    if trials < 1:
        raise ValueError("trials must be >= 1")
    registry = AgentRegistry.from_yaml(registry_path)
    if canary_map is not None:
        canary_map = validate_canary_map(registry, canary_map)
        if canary_map_sha256 is None:
            canonical = json.dumps(canary_map, sort_keys=True).encode()
            canary_map_sha256 = hashlib.sha256(canonical).hexdigest()
    else:
        canary_map_sha256 = None
    started = _now()
    baseline = await run_side(
        registry, baseline_factory, trials, url=baseline_url, canary_map=canary_map
    )
    variant = await run_side(
        registry, variant_factory, trials, url=variant_url, canary_map=canary_map
    )
    return {
        "registry": {
            "path": str(registry_path),
            "sha256": registry_digest(registry_path),
            "agent": registry.agent,
        },
        "canary_map_sha256": canary_map_sha256,
        "trials": trials,
        "started_at": started,
        "finished_at": _now(),
        "vulnerabilities": {
            v.id: {
                "title": v.title,
                "dimension": v.dimension.value,
                "severity": v.severity.value,
                "location": v.location,
            }
            for v in registry.vulnerabilities
        },
        "baseline": baseline,
        "variant": variant,
        "all_error_probes": {
            "baseline": probes_all_errored(baseline),
            "variant": probes_all_errored(variant),
        },
    }


def _cell(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def render_markdown(result: dict[str, Any]) -> str:
    k = result["trials"]
    reg = result["registry"]
    lines = [
        f"# Oracle comparison: {reg['agent']}",
        "",
        f"Registry `{reg['path']}` sha256 `{reg['sha256']}`; {k} trial(s) per side.",
        "",
        (
            "| Vuln | Dimension | Severity | Location | Baseline exploited | "
            "Variant exploited | Errors (b/v) |"
        ),
        "|---|---|---|---|---|---|---|",
    ]
    for vid, meta in result["vulnerabilities"].items():
        b = result["baseline"]["vulnerabilities"][vid]
        v = result["variant"]["vulnerabilities"][vid]
        lines.append(
            f"| {_cell(vid)} | {_cell(meta['dimension'])} | {_cell(meta['severity'])} | "
            f"{_cell(meta['location'])} | {b['exploited']}/{k} | {v['exploited']}/{k} | "
            f"{b['errors']}/{v['errors']} |"
        )
    bad = result["all_error_probes"]
    if bad["baseline"] or bad["variant"]:
        lines += [
            "",
            (
                "**Probes that errored on every trial:** "
                f"baseline: {', '.join(bad['baseline']) or 'none'}; "
                f"variant: {', '.join(bad['variant']) or 'none'}"
            ),
        ]
    return "\n".join(lines) + "\n"


def make_http_transport(url: str, model: str) -> TransportFactory:
    def _factory() -> Transport:
        return FailClosedHttpTransport(url, model=model)

    return _factory


def cmd_compare(
    registry: str,
    baseline_url: str,
    variant_url: str,
    trials: int,
    out: str,
    markdown: str | None,
    model: str = "probe",
    canary_map_path: str | None = None,
) -> int:
    """CLI body. Exit 1 if any side errored on every trial of some probe;
    exit 2 if the canary map is invalid."""
    import asyncio
    import sys

    canary_map: dict[str, str] | None = None
    canary_sha: str | None = None
    if canary_map_path:
        try:
            canary_map, canary_sha = load_canary_map(
                canary_map_path, AgentRegistry.from_yaml(registry)
            )
        except (CanaryMapError, OSError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    result = asyncio.run(
        run_compare(
            registry,
            make_http_transport(baseline_url, model),
            make_http_transport(variant_url, model),
            trials,
            baseline_url=baseline_url,
            variant_url=variant_url,
            canary_map=canary_map,
            canary_map_sha256=canary_sha,
        )
    )
    Path(out).write_text(json.dumps(result, indent=2) + "\n")
    md = render_markdown(result)
    if markdown:
        Path(markdown).write_text(md)
    print(md)
    bad = result["all_error_probes"]
    if bad["baseline"] or bad["variant"]:
        print(
            f"FAIL: probes errored on every trial -- baseline={bad['baseline']} "
            f"variant={bad['variant']}"
        )
        return 1
    return 0
