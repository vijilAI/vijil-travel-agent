"""Tests for `python -m oracle compare` (no network; fake transports only).

Baseline leaks every canary / complies; the variant refuses. Counts per
vulnerability are asserted exactly, and transport failures must land in
``errors`` -- never in ``not_exploited``.
"""
from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from oracle import __main__ as oracle_main
from oracle import compare
from oracle.canary import token
from oracle.registry import AgentRegistry

_ROOT = os.path.dirname(os.path.dirname(__file__))
_REGISTRY = os.path.join(_ROOT, "vulnerabilities.yaml")
_REG = AgentRegistry.from_yaml(_REGISTRY)
_ALL_CANARIES = " ".join(
    token(_REG.agent, v.id, c.slot) for v in _REG.vulnerabilities for c in v.canaries
)
_ALL_IDS = [v.id for v in _REG.vulnerabilities]
_ALL_PROBES = [p.id for v in _REG.vulnerabilities for p in v.probes]


class LeakyTransport:
    """Baseline: leaks every canary, complies, admin endpoints answer 200."""

    async def chat(self, prompt, system_prompt=None):
        return f"Sure! 9,999,999 booked. {_ALL_CANARIES}"

    async def admin(self, method, path, body):
        return 200, _ALL_CANARIES


class SecureTransport:
    """Variant: refuses in chat (and says confirm/simulated); admin is 403."""

    async def chat(self, prompt, system_prompt=None):
        return "I can't help with that. I cannot. I'm not able. Please confirm; this is simulated."

    async def admin(self, method, path, body):
        return 403, "forbidden"


class FlakyTransport(LeakyTransport):
    """Leaky, but fails on specified call numbers (1-based) with an exception."""

    def __init__(self, exc, fail_on=None):
        self.exc = exc
        self.fail_on = fail_on  # None => always fail
        self.calls = 0

    def _maybe_fail(self):
        self.calls += 1
        if self.fail_on is None or self.calls in self.fail_on:
            raise self.exc

    async def chat(self, prompt, system_prompt=None):
        self._maybe_fail()
        return await super().chat(prompt, system_prompt)

    async def admin(self, method, path, body):
        self._maybe_fail()
        return await super().admin(method, path, body)


def _run(baseline, variant, trials=3):
    return asyncio.run(
        compare.run_compare(_REGISTRY, lambda: baseline, lambda: variant, trials)
    )


def test_exact_counts_baseline_leaks_variant_does_not():
    res = _run(LeakyTransport(), SecureTransport(), trials=3)
    assert res["trials"] == 3
    assert len(res["baseline"]["vulnerabilities"]) == len(_ALL_IDS)
    for vid in _ALL_IDS:
        b = res["baseline"]["vulnerabilities"][vid]
        v = res["variant"]["vulnerabilities"][vid]
        assert (b["exploited"], b["not_exploited"], b["errors"], b["trials"]) == (3, 0, 0, 3), vid
        assert (v["exploited"], v["not_exploited"], v["errors"], v["trials"]) == (0, 3, 0, 3), vid
    p1 = res["baseline"]["vulnerabilities"]["TA-SEC-01"]["probes"]["TA-SEC-01-p1"]
    assert p1["verdicts"] == ["exploited"] * 3
    p2 = res["variant"]["vulnerabilities"]["TA-SEC-01"]["probes"]["TA-SEC-01-p1"]
    assert p2["verdicts"] == ["not_exploited"] * 3
    assert res["all_error_probes"] == {"baseline": [], "variant": []}


def test_registry_digest_and_timestamps_recorded():
    import hashlib

    res = _run(LeakyTransport(), SecureTransport(), trials=1)
    with open(_REGISTRY, "rb") as fh:
        assert res["registry"]["sha256"] == hashlib.sha256(fh.read()).hexdigest()
    assert res["registry"]["path"] == _REGISTRY
    for blob in (res, res["baseline"], res["variant"]):
        assert blob["started_at"] and blob["finished_at"]


def test_transport_exception_is_error_not_not_exploited():
    # Variant raises on every call: every vuln must be all-errors, zero not_exploited.
    res = _run(LeakyTransport(), FlakyTransport(TimeoutError("boom")), trials=2)
    for vid in _ALL_IDS:
        v = res["variant"]["vulnerabilities"][vid]
        assert (v["exploited"], v["not_exploited"], v["errors"]) == (0, 0, 2), vid
    pdata = res["variant"]["vulnerabilities"]["TA-SEC-01"]["probes"]["TA-SEC-01-p1"]
    assert pdata["verdicts"] == ["error", "error"]
    assert "TimeoutError" in pdata["error_details"][0]
    assert sorted(res["all_error_probes"]["variant"]) == sorted(_ALL_PROBES)
    assert res["all_error_probes"]["baseline"] == []


def test_partial_failure_counts_one_error_trial():
    # Fail only the very first call (TA-SEC-01-p1, trial 1); everything else leaks.
    flaky = FlakyTransport(RuntimeError("blip"), fail_on={1})
    res = asyncio.run(compare.run_compare(_REGISTRY, lambda: flaky, SecureTransport, 2))
    sec01 = res["baseline"]["vulnerabilities"]["TA-SEC-01"]
    assert (sec01["exploited"], sec01["not_exploited"], sec01["errors"]) == (1, 0, 1)
    assert sec01["probes"]["TA-SEC-01-p1"]["verdicts"] == ["error", "exploited"]
    assert res["all_error_probes"]["baseline"] == []  # not errored on EVERY trial


def test_http_5xx_is_error_via_failclosed_transport():
    httpx = pytest.importorskip("httpx")

    def handler(request):
        return httpx.Response(503, text="<html>upstream down</html>")

    t = compare.FailClosedHttpTransport("http://agent.invalid")
    t._client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        event_hooks={"request": [], "response": [compare._raise_on_5xx]},
    )

    side = asyncio.run(_run_side_noclose(t))
    for vid in _ALL_IDS:
        v = side["vulnerabilities"][vid]
        assert (v["exploited"], v["not_exploited"], v["errors"]) == (0, 0, 1), vid
    detail = side["vulnerabilities"]["TA-SEC-01"]["probes"]["TA-SEC-01-p1"]["error_details"][0]
    assert "TransportError" in detail and "503" in detail


async def _run_side_noclose(t):
    return await compare.run_side(_REG, lambda: t, 1)


def test_markdown_row_content():
    res = _run(LeakyTransport(), FlakyTransport(OSError("down"), fail_on={1}), trials=2)
    md = compare.render_markdown(res)
    header = next(line for line in md.splitlines() if line.startswith("| Vuln"))
    for col in ("Dimension", "Severity", "Location", "Baseline exploited",
                "Variant exploited", "Errors (b/v)"):
        assert col in header
    row = next(line for line in md.splitlines() if line.startswith("| TA-SEC-01 "))
    # variant leaks (flaky only fails call #1 = TA-SEC-01-p1 trial 1), so 1/2 exploited
    assert row == (
        "| TA-SEC-01 | security | critical | tools/credentials.py:get_api_credentials "
        "| 2/2 | 1/2 | 0/1 |"
    )


def _cli_args(tmp_path, trials=2):
    return [
        "compare", "--registry", _REGISTRY,
        "--baseline-url", "http://b.invalid", "--variant-url", "http://v.invalid",
        "--trials", str(trials), "--out", str(tmp_path / "out.json"),
        "--markdown", str(tmp_path / "out.md"),
    ]


def test_cli_writes_outputs_and_exit_zero(tmp_path, monkeypatch):
    transports = {"http://b.invalid": LeakyTransport(), "http://v.invalid": SecureTransport()}
    monkeypatch.setattr(
        compare, "make_http_transport", lambda url, model: (lambda: transports[url])
    )
    assert oracle_main.main(_cli_args(tmp_path)) == 0
    data = json.loads((tmp_path / "out.json").read_text())
    assert data["baseline"]["vulnerabilities"]["TA-REL-01"]["exploited"] == 2
    assert data["variant"]["vulnerabilities"]["TA-REL-01"]["exploited"] == 0
    assert "| TA-REL-01 |" in (tmp_path / "out.md").read_text()


def test_cli_exit_nonzero_when_probe_errors_every_trial(tmp_path, monkeypatch):
    transports = {
        "http://b.invalid": LeakyTransport(),
        "http://v.invalid": FlakyTransport(TimeoutError("t/o")),
    }
    monkeypatch.setattr(
        compare, "make_http_transport", lambda url, model: (lambda: transports[url])
    )
    assert oracle_main.main(_cli_args(tmp_path)) == 1
    data = json.loads((tmp_path / "out.json").read_text())  # output still written
    assert data["variant"]["vulnerabilities"]["TA-SEC-01"]["errors"] == 2


def test_help_via_subprocess():
    proc = subprocess.run(
        [sys.executable, "-m", "oracle", "compare", "--help"],
        cwd=_ROOT, capture_output=True, text=True, timeout=60, check=False,
    )
    assert proc.returncode == 0
    for flag in ("--registry", "--baseline-url", "--variant-url", "--trials", "--out", "--markdown"):
        assert flag in proc.stdout


# ---------------------------------------------------------------------------
# --canary-map (blind deployment): blind values are translated back before grading
# ---------------------------------------------------------------------------

_CANARY_TOKENS = [
    token(_REG.agent, v.id, c.slot) for v in _REG.vulnerabilities for c in v.canaries
]
_BLIND = {tok: f"BLIND-{i:04d}-opaque" for i, tok in enumerate(_CANARY_TOKENS)}
_CANARY_VULNS = ["TA-SEC-01", "TA-SEC-02", "TA-SAF-01", "TA-SAF-02"]


class BlindLeakyTransport(LeakyTransport):
    """Leaks the blind (opaque) canary values, never the registry tokens."""

    async def chat(self, prompt, system_prompt=None):
        return "Sure! " + " ".join(_BLIND.values())

    async def admin(self, method, path, body):
        return 200, " ".join(_BLIND.values())


def _run_map(baseline, variant, canary_map, trials=2):
    return asyncio.run(
        compare.run_compare(
            _REGISTRY, lambda: baseline, lambda: variant, trials, canary_map=canary_map
        )
    )


def test_canary_map_blind_value_counts_as_exploited_only_with_map():
    # Sanity: the blind leaker never emits a registry token.
    assert not any(tok in " ".join(_BLIND.values()) for tok in _CANARY_TOKENS)

    mapped = _run_map(BlindLeakyTransport(), SecureTransport(), _BLIND)
    for vid in _CANARY_VULNS:
        b = mapped["baseline"]["vulnerabilities"][vid]
        v = mapped["variant"]["vulnerabilities"][vid]
        assert (b["exploited"], b["not_exploited"], b["errors"]) == (2, 0, 0), vid
        assert (v["exploited"], v["not_exploited"], v["errors"]) == (0, 2, 0), vid

    # Same responses, no map: the blind value alone is NOT counted.
    unmapped = _run_map(BlindLeakyTransport(), SecureTransport(), None)
    for vid in _CANARY_VULNS:
        b = unmapped["baseline"]["vulnerabilities"][vid]
        assert (b["exploited"], b["not_exploited"], b["errors"]) == (0, 2, 0), vid


def test_canary_map_translation_is_not_substring_of_other_text():
    # A response WITHOUT the blind value stays not-exploited even with the map on.
    res = _run_map(SecureTransport(), SecureTransport(), _BLIND)
    for vid in _CANARY_VULNS:
        assert res["baseline"]["vulnerabilities"][vid]["exploited"] == 0, vid


def test_canary_map_digest_recorded_not_contents(tmp_path, monkeypatch):
    transports = {"http://b.invalid": BlindLeakyTransport(), "http://v.invalid": SecureTransport()}
    monkeypatch.setattr(
        compare, "make_http_transport", lambda url, model: (lambda: transports[url])
    )
    mp = tmp_path / "map.json"
    mp.write_bytes(json.dumps(_BLIND).encode())
    args = _cli_args(tmp_path) + ["--canary-map", str(mp)]
    assert oracle_main.main(args) == 0

    import hashlib

    raw = (tmp_path / "out.json").read_text()
    data = json.loads(raw)
    assert data["canary_map_sha256"] == hashlib.sha256(mp.read_bytes()).hexdigest()
    assert data["baseline"]["vulnerabilities"]["TA-SEC-01"]["exploited"] == 2
    for blind in _BLIND.values():
        assert blind not in raw  # contents are not recorded
    for tok in _CANARY_TOKENS:
        assert tok not in raw


def test_no_canary_map_records_null_digest():
    res = _run(LeakyTransport(), SecureTransport(), trials=1)
    assert res["canary_map_sha256"] is None


def test_canary_map_unknown_key_rejected(tmp_path, capsys):
    bad = dict(_BLIND)
    bad["VIJIL-CANARY-not-in-registry"] = "BLIND-x"
    with pytest.raises(compare.CanaryMapError, match="VIJIL-CANARY-not-in-registry"):
        _run_map(LeakyTransport(), SecureTransport(), bad)

    mp = tmp_path / "bad.json"
    mp.write_text(json.dumps(bad))
    rc = oracle_main.main(_cli_args(tmp_path) + ["--canary-map", str(mp)])
    assert rc == 2
    err = capsys.readouterr().err
    assert "VIJIL-CANARY-not-in-registry" in err and "not a canary token" in err
    assert not (tmp_path / "out.json").exists()


def test_canary_map_malformed_rejected(tmp_path):
    reg = AgentRegistry.from_yaml(_REGISTRY)
    first = _CANARY_TOKENS[0]
    with pytest.raises(compare.CanaryMapError, match="JSON object"):
        compare.validate_canary_map(reg, [first])
    with pytest.raises(compare.CanaryMapError, match="empty"):
        compare.validate_canary_map(reg, {first: ""})
    with pytest.raises(compare.CanaryMapError, match="maps to both"):
        compare.validate_canary_map(reg, {_CANARY_TOKENS[0]: "same", _CANARY_TOKENS[1]: "same"})
    p = tmp_path / "x.json"
    p.write_text("{not json")
    with pytest.raises(compare.CanaryMapError, match="not valid JSON"):
        compare.load_canary_map(p, reg)
