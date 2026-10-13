"""A/B comparison of two live agents (baseline vs variant) with repeated trials.

Every probe in the registry is fired K times against each side (a fresh
transport per trial and phase; ``chat`` sends a single-message conversation per
call, so no conversation state carries over) and graded with the existing
deterministic checker (:func:`oracle.checker.evaluate_probe`). Probing is
delegated to :func:`oracle.probe_runner.run_probe`; verdict semantics are
unchanged.

Fail closed. These numbers are shown to prospects, so anything that is not a
genuine measurement of the agent's answer is an ``error`` and is never counted
as ``exploited`` or ``not_exploited``:

  * transport exceptions and timeouts;
  * chat: any status other than 200, a non-JSON body, a top-level ``error``
    key, missing/empty ``choices[0].message.content``, or the agent's generic
    failure reply (the ``--error-sentinel`` text);
  * admin_http: 3xx, 404, 405, 422, 429, 5xx and any other status outside
    2xx/401/403 (401/403 are legitimate measured responses -- an auth fix
    produces them);
  * a transcript whose text starts with ``<probe error:`` (a malformed
    ``admin_http`` probe prompt that never reached the agent).

A vulnerability trial is

  * ``exploited``     -- any of its probes disclosed the weakness (positive
                         evidence stands even if another probe errored);
  * ``errors``        -- else, if any probe errored (absence of a leak cannot be
                         asserted when a probe did not complete);
  * ``not_exploited`` -- else (every probe completed and none disclosed).

So ``exploited + not_exploited + errors == trials`` for every vulnerability.

Execution order: for each side, all chat probes for all trials run first, then
the admin_http probes, because a mutating admin probe (e.g. ``POST
/admin/goals``) changes the agent's behaviour for every later request. The
mutating probes that ran are listed under ``mutating_probes_run``; restart the
agent (fresh DB) between compare runs.

``canary_map_sha256`` is the sha256 of the canonical map JSON
(``json.dumps(map, sort_keys=True, separators=(",", ":"))``), identical for the
CLI and API paths.
"""
from __future__ import annotations

import ast
import hashlib
import json
import re
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from oracle.canary import token as canary_token
from oracle.checker import evaluate_probe
from oracle.probe_runner import HttpTransport, Transport, parse_admin_prompt, run_probe
from oracle.registry import AgentRegistry

EXPLOITED = "exploited"
NOT_EXPLOITED = "not_exploited"
ERROR = "error"

PROBE_ERROR_PREFIX = "<probe error:"
MIN_BLIND_LEN = 12
_DIGITS_AND_SEPARATORS = re.compile(r"[0-9 -]+")
MIN_BLIND_ALNUM = 8
IDENTICAL_REASON = "identical response to every probe — agent not answering"
# Chat probes whose tools write to the agent's DB (payments / bookings). Together
# with the mutating admin probes they make a second run on the same DB unreliable.
STATEFUL_CHAT_VULN_IDS = ("TA-REL-01", "TA-REL-02")

TransportFactory = Callable[[], Transport]


class TransportError(Exception):
    """A response that is not a genuine measurement of the agent's answer."""


class SentinelError(Exception):
    """The agent's generic failure reply could not be determined."""


# --------------------------------------------------------------------------
# Fail-closed HTTP transport
# --------------------------------------------------------------------------

_ADMIN_MEASURED_STATUSES = frozenset({401, 403})


def default_error_sentinel(agent_py: str | Path | None = None) -> str:
    """The agent's generic failure reply: ``ERROR_MESSAGE`` in ``agent.py``.

    Read statically (``ast``) so no agent dependencies are imported.
    """
    path = Path(agent_py) if agent_py else Path(__file__).resolve().parent.parent / "agent.py"
    try:
        tree = ast.parse(path.read_text())
    except (OSError, SyntaxError) as exc:
        raise SentinelError(
            f"cannot read ERROR_MESSAGE from {path} ({exc}); pass --error-sentinel"
        ) from exc
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id == "ERROR_MESSAGE" for t in node.targets
        ):
            try:
                value = ast.literal_eval(node.value)
            except ValueError:
                continue
            if isinstance(value, str) and value:
                return value
    raise SentinelError(f"no ERROR_MESSAGE string constant in {path}; pass --error-sentinel")


class FailClosedHttpTransport(HttpTransport):
    """``HttpTransport`` where only genuine measurements are returned.

    ``HttpTransport.chat`` turns 4xx pages, ``{"error": ...}`` bodies and empty
    completions into text that would be graded as a clean miss (or even a hit),
    so ``chat`` and ``admin`` are re-implemented here to raise
    :class:`TransportError` for anything that is not a real answer.
    """

    def __init__(
        self,
        base_url: str,
        *,
        model: str = "probe",
        timeout: float = 60.0,
        error_sentinel: str | None = None,
        httpx_transport: Any = None,
    ) -> None:
        import httpx

        self._base = base_url.rstrip("/")
        self._model = model
        self._error_sentinel = error_sentinel.strip() if error_sentinel else None
        self._client = httpx.AsyncClient(timeout=timeout, transport=httpx_transport)

    async def chat(self, prompt: str, system_prompt: str | None = None) -> str:
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})
        resp = await self._client.post(
            f"{self._base}/v1/chat/completions",
            json={"model": self._model, "messages": messages},
        )
        if resp.status_code != 200:
            raise TransportError(f"chat HTTP {resp.status_code}")
        try:
            data = resp.json()
        except ValueError as exc:
            raise TransportError("chat: 200 response is not JSON") from exc
        if not isinstance(data, dict):
            raise TransportError("chat: JSON body is not an object")
        if "error" in data:
            raise TransportError("chat: response carries a top-level 'error'")
        try:
            content = data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise TransportError("chat: no choices[0].message.content") from exc
        if not isinstance(content, str) or not content.strip():
            raise TransportError("chat: empty or non-string completion content")
        if self._error_sentinel is not None and content.strip() == self._error_sentinel:
            raise TransportError("chat: agent returned its generic failure reply")
        return content

    async def admin(self, method: str, path: str, body: dict | None) -> tuple[int, str]:
        resp = await self._client.request(
            method, f"{self._base}{path}", json=body if body is not None else None
        )
        code = resp.status_code
        if not (200 <= code < 300 or code in _ADMIN_MEASURED_STATUSES):
            raise TransportError(f"admin {method} {path}: HTTP {code} is not a measurement")
        return code, resp.text


def _now() -> str:
    return datetime.now(UTC).isoformat()


def registry_digest(path: str | Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


# --------------------------------------------------------------------------
# Canary map (blind deployments)
# --------------------------------------------------------------------------


class CanaryMapError(ValueError):
    """The canary map is malformed or unsafe for this registry."""


def registry_canary_tokens(registry: AgentRegistry) -> set[str]:
    return {
        canary_token(registry.agent, v.id, c.slot)
        for v in registry.vulnerabilities
        for c in v.canaries
    }


def canary_map_digest(canary_map: dict[str, str]) -> str:
    """sha256 of the canonical (sorted, compact) JSON of the map."""
    canonical = json.dumps(canary_map, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def validate_canary_map(registry: AgentRegistry, canary_map: Any) -> dict[str, str]:
    """Check ``{original_token: blind_value}`` against the registry.

    Every registry canary must be mapped, and every blind value must be long,
    unambiguous, and unable to collide with registry text or another value.
    """
    if not isinstance(canary_map, dict):
        raise CanaryMapError("canary map must be a JSON object {original_token: blind_value}")
    known = registry_canary_tokens(registry)
    texts: list[str] = []
    for v in registry.vulnerabilities:
        for p in v.probes:
            texts.append(p.prompt.lower())
            texts.extend(c.value.lower() for c in p.oracle if c.value)

    seen: dict[str, str] = {}
    seen_digits: dict[str, str] = {}
    for original, blind in canary_map.items():
        if not isinstance(original, str) or not isinstance(blind, str):
            raise CanaryMapError(f"canary map entries must be strings: {original!r}: {blind!r}")
        if original not in known:
            raise CanaryMapError(
                f"canary map key {original!r} is not a canary token declared by registry "
                f"agent {registry.agent!r}"
            )
        digits = _digit_sequence(blind)
        if digits is not None:
            # Number-shaped value (digits with space/dash separators): the minimum
            # length is counted in digits, not raw characters.
            if len(digits) < MIN_BLIND_LEN:
                raise CanaryMapError(
                    f"blind value for {original!r} has fewer than {MIN_BLIND_LEN} digits"
                )
            if digits in seen_digits and seen_digits[digits] != original:
                raise CanaryMapError(
                    f"blind value for {original!r} has the same digits as the value for "
                    f"{seen_digits[digits]!r}"
                )
            seen_digits[digits] = original
        else:
            if len(blind) < MIN_BLIND_LEN:
                raise CanaryMapError(
                    f"blind value for {original!r} is shorter than {MIN_BLIND_LEN} characters"
                )
            if sum(ch.isalnum() for ch in blind) < MIN_BLIND_ALNUM:
                raise CanaryMapError(
                    f"blind value for {original!r} has fewer than {MIN_BLIND_ALNUM} "
                    "alphanumeric characters"
                )
        if blind in known:
            raise CanaryMapError(f"blind value for {original!r} is itself a registry token")
        low = blind.lower()
        if any(low in t for t in texts):
            raise CanaryMapError(
                f"blind value for {original!r} occurs in a probe prompt or registry oracle value"
            )
        if blind in seen and seen[blind] != original:
            raise CanaryMapError(
                f"blind value {blind!r} maps to both {seen[blind]!r} and {original!r}"
            )
        seen[blind] = original
    blinds = list(seen)
    for a in blinds:
        for b in blinds:
            if a is b or a == b:
                continue
            da, db = _digit_sequence(a), _digit_sequence(b)
            digit_overlap = da is not None and db is not None and da in db
            if digit_overlap or a.lower() in b.lower():
                raise CanaryMapError(
                    f"blind value {a!r} (for {seen[a]!r}) is a substring of another blind "
                    f"value ({b!r} for {seen[b]!r})"
                )
    missing = sorted(known - set(canary_map))
    if missing:
        raise CanaryMapError("canary map is missing registry canary token(s): " + ", ".join(missing))
    return dict(canary_map)


def load_canary_map(path: str | Path, registry: AgentRegistry) -> dict[str, str]:
    """Load and validate a canary map file."""
    try:
        data = json.loads(Path(path).read_bytes())
    except json.JSONDecodeError as exc:
        raise CanaryMapError(f"canary map {path} is not valid JSON: {exc}") from exc
    return validate_canary_map(registry, data)


def _digit_sequence(blind: str) -> str | None:
    """The digits of a number-shaped blind value (only digits, spaces, dashes), else None."""
    if _DIGITS_AND_SEPARATORS.fullmatch(blind) and any(ch.isdigit() for ch in blind):
        return re.sub(r"[ -]", "", blind)
    return None


def _blind_pattern(blind: str) -> str:
    """Regex for one blind value, tolerant of common reformatting by the model.

    * Number-shaped values (digits with optional space/dash separators, e.g. a
      card): matched as their digit sequence with an optional space or dash
      between digits, so ``4532983955806951``, ``4532 9839 5580 6951`` and
      ``4532-9839-5580-6951`` all match -- but never inside a longer digit run
      (that would manufacture a leak).
    * Everything else (credentials like ``sp-sk-ib46...``): case-insensitive.
    """
    digits = _digit_sequence(blind)
    if digits is not None:
        return "(?<![0-9])" + "[ -]?".join(digits) + "(?![0-9])"
    return f"(?i:{re.escape(blind)})"


def make_translator(canary_map: dict[str, str] | None) -> Callable[[str], str]:
    """Return a function replacing each blind value with its original token.

    Single pass over a longest-first alternation, so a replacement is never
    itself re-scanned for further blind values.
    """
    if not canary_map:
        return lambda text: text
    by_group: dict[str, str] = {}
    parts: list[str] = []
    for i, (blind, original) in enumerate(
        sorted(((b, o) for o, b in canary_map.items()), key=lambda bo: len(bo[0]), reverse=True)
    ):
        by_group[f"g{i}"] = original
        parts.append(f"(?P<g{i}>{_blind_pattern(blind)})")
    pattern = re.compile("|".join(parts))
    return lambda text: pattern.sub(lambda m: by_group[m.lastgroup or ""], text)


# --------------------------------------------------------------------------
# Running
# --------------------------------------------------------------------------


def _is_mutating(probe: Any) -> bool:
    if probe.channel != "admin_http":
        return False
    try:
        method, _, _ = parse_admin_prompt(probe.prompt)
    except ValueError:
        return False  # never sent
    return method not in ("GET", "HEAD", "OPTIONS")


async def _measure(
    registry: AgentRegistry,
    vuln_id: str,
    probe: Any,
    transport: Transport,
    translate: Callable[[str], str],
) -> tuple[str, str, str]:
    """(verdict, error detail, raw response text)."""
    try:
        transcript = await run_probe(probe, transport)
    except Exception as exc:  # noqa: BLE001 - every failure is an error verdict
        return ERROR, f"{type(exc).__name__}: {exc}", ""
    text = transcript.response_text or ""
    if text.startswith(PROBE_ERROR_PREFIX):
        return ERROR, text, text
    transcript = transcript.model_copy(update={"response_text": translate(text)})
    result = evaluate_probe(probe, transcript, namespace=registry.agent, vuln_id=vuln_id)
    return (EXPLOITED if result.disclosed else NOT_EXPLOITED), "", text


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
    pairs = [(v.id, p) for v in registry.vulnerabilities for p in v.probes]
    chat_pairs = [(vid, p) for vid, p in pairs if p.channel != "admin_http"]
    admin_pairs = [(vid, p) for vid, p in pairs if p.channel == "admin_http"]

    probe_verdicts: dict[str, list[str]] = {p.id: [] for _, p in pairs}
    probe_errors: dict[str, list[str]] = {}
    chat_texts: list[str] = []
    # Chat first, for every trial; mutating admin probes only afterwards.
    for phase in (chat_pairs, admin_pairs):
        if not phase:
            continue
        for _ in range(trials):
            transport = factory()  # fresh transport (client, cookies) per trial
            try:
                for vid, probe in phase:
                    verdict, detail, text = await _measure(
                        registry, vid, probe, transport, translate
                    )
                    probe_verdicts[probe.id].append(verdict)
                    if verdict == ERROR:
                        probe_errors.setdefault(probe.id, []).append(detail)
                    elif probe.channel != "admin_http":
                        chat_texts.append(text.strip())
            finally:
                aclose = getattr(transport, "aclose", None)
                if aclose is not None:
                    await aclose()

    # Sameness guard: distinct probes must not all get the byte-identical reply. A
    # fixed canned answer (e.g. a rewritten failure message) is not a measurement.
    identical_guard = len(chat_texts) >= 2 and len(set(chat_texts)) == 1
    if identical_guard:
        for _, probe in chat_pairs:
            probe_verdicts[probe.id] = [ERROR] * trials
            probe_errors[probe.id] = [IDENTICAL_REASON] * trials

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
    return {
        "url": url,
        "started_at": started,
        "finished_at": _now(),
        "mutating_probes_run": [p.id for _, p in admin_pairs if _is_mutating(p)],
        "stateful_probes_run": [
            p.id for vid, p in chat_pairs if vid in STATEFUL_CHAT_VULN_IDS
        ],
        "identical_response_guard_tripped": identical_guard,
        "probe_error_count": sum(len(d) for d in probe_errors.values()),
        "vulnerabilities": vulns,
    }


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
    baseline_sentinel: str | None = None,
    variant_sentinel: str | None = None,
    warnings: list[str] | None = None,
) -> dict[str, Any]:
    """Run the comparison.

    ``canary_map`` ({original_token: blind_value}) is applied to both sides'
    responses before grading; only its canonical sha256 is recorded.
    The per-side error sentinels are recorded (they are enforced by the transport
    factories). ``warnings`` (plus a same-URL warning) are recorded in the JSON.
    """
    if trials < 1:
        raise ValueError("trials must be >= 1")
    registry = AgentRegistry.from_yaml(registry_path)
    map_sha: str | None = None
    if canary_map is not None:
        canary_map = validate_canary_map(registry, canary_map)
        map_sha = canary_map_digest(canary_map)
    all_warnings = list(warnings or [])
    if baseline_url and baseline_url == variant_url:
        all_warnings.append(
            "baseline and variant URLs are identical -- this compares an agent with itself"
        )
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
        "canary_map_sha256": map_sha,
        "error_sentinel": {"baseline": baseline_sentinel, "variant": variant_sentinel},
        "warnings": all_warnings,
        "trials": trials,
        "started_at": started,
        "finished_at": _now(),
        "mutating_probes_run": sorted(
            set(baseline["mutating_probes_run"]) | set(variant["mutating_probes_run"])
        ),
        "stateful_probes_run": sorted(
            set(baseline["stateful_probes_run"]) | set(variant["stateful_probes_run"])
        ),
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
        "measurement_errors": {
            "baseline": baseline["probe_error_count"],
            "variant": variant["probe_error_count"],
            "total": baseline["probe_error_count"] + variant["probe_error_count"],
        },
        "all_error_probes": {
            "baseline": probes_all_errored(baseline),
            "variant": probes_all_errored(variant),
        },
    }


def error_banners(result: dict[str, Any]) -> list[str]:
    lines: list[str] = []
    n = result["measurement_errors"]["total"]
    if n:
        lines.append(f"WARNING: {n} measurement errors — counts exclude them")
    for side in ("baseline", "variant"):
        if result[side]["identical_response_guard_tripped"]:
            lines.append(
                f"WARNING: {side}: {IDENTICAL_REASON} "
                "(all its chat probes are counted as errors)"
            )
    return lines


def _cell(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def _exploited_cell(vuln: dict[str, Any], k: int) -> str:
    e = vuln["errors"]
    if e:
        return f"{vuln['exploited']}/{k - e} ({e} err)"
    return f"{vuln['exploited']}/{k}"


def render_markdown(result: dict[str, Any]) -> str:
    k = result["trials"]
    reg = result["registry"]
    lines = [
        f"# Oracle comparison: {reg['agent']}",
        "",
        f"Registry `{reg['path']}` sha256 `{reg['sha256']}`; {k} trial(s) per side.",
        "",
    ]
    banners = error_banners(result)
    if banners:
        lines += [f"**{b}**  " for b in banners] + [""]
    lines += [
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
            f"{_cell(meta['location'])} | {_exploited_cell(b, k)} | {_exploited_cell(v, k)} | "
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
    state = sorted(set(result["mutating_probes_run"]) | set(result["stateful_probes_run"]))
    if state:
        lines += [
            "",
            "State-changing probes run: " + ", ".join(state)
            + ". Restart the agents with a fresh DB before the next compare run.",
        ]
    return "\n".join(lines) + "\n"


def make_http_transport(
    url: str, model: str, error_sentinel: str | None = None
) -> TransportFactory:
    def _factory() -> Transport:
        return FailClosedHttpTransport(url, model=model, error_sentinel=error_sentinel)

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
    error_sentinel: str | None = None,
    allow_errors: bool = False,
    baseline_agent_py: str | None = None,
    variant_agent_py: str | None = None,
) -> int:
    """CLI body.

    Exit 2: invalid canary map / unreadable sentinel. Exit 1: any measurement
    error (unless ``allow_errors``), or -- always -- a probe that errored on
    every trial of either side.
    """
    import asyncio
    import sys

    warnings: list[str] = []
    sentinels: dict[str, str] = {}
    try:
        for side, agent_py in (("baseline", baseline_agent_py), ("variant", variant_agent_py)):
            if error_sentinel is not None:
                sentinels[side] = error_sentinel
            elif agent_py:
                sentinels[side] = default_error_sentinel(agent_py)
            else:
                sentinels[side] = default_error_sentinel()
                warnings.append(
                    f"{side}: neither --{side}-agent-py nor --error-sentinel given; using the "
                    "registry tree's agent.py ERROR_MESSAGE, which may differ from the served agent"
                )
        canary_map = (
            load_canary_map(canary_map_path, AgentRegistry.from_yaml(registry))
            if canary_map_path
            else None
        )
    except (CanaryMapError, SentinelError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    result = asyncio.run(
        run_compare(
            registry,
            make_http_transport(baseline_url, model, sentinels["baseline"]),
            make_http_transport(variant_url, model, sentinels["variant"]),
            trials,
            baseline_url=baseline_url,
            variant_url=variant_url,
            canary_map=canary_map,
            baseline_sentinel=sentinels["baseline"],
            variant_sentinel=sentinels["variant"],
            warnings=warnings,
        )
    )
    Path(out).write_text(json.dumps(result, indent=2) + "\n")
    md = render_markdown(result)
    if markdown:
        Path(markdown).write_text(md)
    print(md)
    for w in result["warnings"]:
        print(f"WARNING: {w}", file=sys.stderr)
    banners = error_banners(result)
    for line in banners:
        print(line, file=sys.stderr)
    bad = result["all_error_probes"]
    if bad["baseline"] or bad["variant"]:
        print(
            f"FAIL: probes errored on every trial -- baseline={bad['baseline']} "
            f"variant={bad['variant']}",
            file=sys.stderr,
        )
        return 1
    if result["measurement_errors"]["total"] and not allow_errors:
        print("FAIL: measurement errors present (use --allow-errors to accept)", file=sys.stderr)
        return 1
    return 0
