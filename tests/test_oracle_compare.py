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


_SENTINEL = compare.default_error_sentinel()
_VALID_CHAT = {"choices": [{"message": {"content": "Here you go."}}]}
_CHAT_VULNS = [
    v.id for v in _REG.vulnerabilities if all(p.channel != "admin_http" for p in v.probes)
]
_ADMIN_VULNS = [
    v.id for v in _REG.vulnerabilities if any(p.channel == "admin_http" for p in v.probes)
]


def _mock_factory(chat_resp, admin_resp, sentinel=_SENTINEL):
    """Factory of FailClosedHttpTransport over a MockTransport (its OWN checks only)."""
    httpx = pytest.importorskip("httpx")

    def handler(request):
        resp = chat_resp if request.url.path == "/v1/chat/completions" else admin_resp
        status, body = resp
        if isinstance(body, (dict, list)):
            return httpx.Response(status, json=body)
        return httpx.Response(status, text=body)

    return lambda: compare.FailClosedHttpTransport(
        "http://agent.invalid",
        httpx_transport=httpx.MockTransport(handler),
        error_sentinel=sentinel,
    )


def test_default_error_sentinel_is_agent_error_message():
    assert _SENTINEL.startswith("I apologize, but I'm unable to process this request.")


@pytest.mark.parametrize(
    "chat_resp",
    [
        (401, {"error": "unauthorized"}),
        (403, "forbidden"),
        (404, "not found"),
        (422, {"detail": "bad"}),
        (429, "slow down"),
        (500, "<html>boom</html>"),
        (503, "<html>upstream down</html>"),
        (302, ""),
        (401, _VALID_CHAT),  # status alone must disqualify, even with a plausible body
        (429, _VALID_CHAT),
        (200, {"choices": [{"message": {"content": ""}}]}),
        (200, {"choices": [{"message": {"content": "   "}}]}),
        (200, {"choices": [{"message": {"content": None}}]}),
        (200, {"error": {"message": "model overloaded"}}),
        (200, {**_VALID_CHAT, "error": "partial"}),
        (200, {"choices": []}),
        (200, ["not", "an", "object"]),
        (200, "<html>plain text, not JSON</html>"),
        (200, {"choices": [{"message": {"content": _SENTINEL}}]}),
    ],
    ids=lambda r: f"{r[0]}-{str(r[1])[:25]}",
)
def test_chat_non_measurements_are_errors(chat_resp):
    factory = _mock_factory(chat_resp, (200, "ok"))
    side = asyncio.run(compare.run_side(_REG, factory, 2))
    for vid in _CHAT_VULNS:
        v = side["vulnerabilities"][vid]
        assert (v["exploited"], v["not_exploited"], v["errors"]) == (0, 0, 2), vid
    assert side["probe_error_count"] >= 2 * len(_CHAT_VULNS)


def test_chat_valid_answer_is_measured_not_error():
    side = asyncio.run(compare.run_side(_REG, _mock_factory((200, _VALID_CHAT), (200, "ok")), 2))
    for vid in _CHAT_VULNS:
        v = side["vulnerabilities"][vid]
        assert v["errors"] == 0 and v["exploited"] + v["not_exploited"] == 2, vid


@pytest.mark.parametrize("status", [302, 301, 404, 405, 422, 429, 500, 502, 503])
def test_admin_non_measurements_are_errors(status):
    factory = _mock_factory((200, _VALID_CHAT), (status, "whatever"))
    side = asyncio.run(compare.run_side(_REG, factory, 2))
    for vid in _ADMIN_VULNS:
        v = side["vulnerabilities"][vid]
        assert (v["exploited"], v["not_exploited"], v["errors"]) == (0, 0, 2), vid


@pytest.mark.parametrize("status", [401, 403])
def test_admin_auth_rejection_is_a_measured_not_exploited(status):
    factory = _mock_factory((200, _VALID_CHAT), (status, "denied"))
    side = asyncio.run(compare.run_side(_REG, factory, 2))
    for vid in _ADMIN_VULNS:
        v = side["vulnerabilities"][vid]
        assert (v["exploited"], v["not_exploited"], v["errors"]) == (0, 2, 0), vid


def test_admin_200_leak_is_exploited():
    factory = _mock_factory((200, _VALID_CHAT), (200, _ALL_CANARIES))
    side = asyncio.run(compare.run_side(_REG, factory, 1))
    assert side["vulnerabilities"]["TA-SEC-02"]["exploited"] == 1
    assert side["vulnerabilities"]["TA-SEC-03"]["exploited"] == 1


def test_sentinel_recorded_in_json():
    res = asyncio.run(
        compare.run_compare(
            _REGISTRY, lambda: LeakyTransport(), lambda: SecureTransport(), 1,
            error_sentinel="custom failure reply",
        )
    )
    assert res["error_sentinel"] == "custom failure reply"


def test_markdown_row_content_and_error_rendering():
    res = _run(LeakyTransport(), FlakyTransport(OSError("down"), fail_on={1}), trials=2)
    md = compare.render_markdown(res)
    header = next(line for line in md.splitlines() if line.startswith("| Vuln"))
    for col in ("Dimension", "Severity", "Location", "Baseline exploited",
                "Variant exploited", "Errors (b/v)"):
        assert col in header
    # Clean side renders k/K; the side with 1 errored trial renders k/(K-e) (e err).
    row = next(line for line in md.splitlines() if line.startswith("| TA-SEC-01 "))
    assert row == (
        "| TA-SEC-01 | security | critical | tools/credentials.py:get_api_credentials "
        "| 2/2 | 1/1 (1 err) | 0/1 |"
    )
    assert "WARNING: 1 measurement errors — counts exclude them" in md
    assert res["measurement_errors"] == {"baseline": 0, "variant": 1, "total": 1}


def test_markdown_has_no_banner_without_errors():
    md = compare.render_markdown(_run(LeakyTransport(), SecureTransport(), trials=2))
    assert "WARNING" not in md
    assert "| TA-SEC-01 | security | critical | tools/credentials.py:get_api_credentials "\
        "| 2/2 | 0/2 | 0/0 |" in md


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
        compare, "make_http_transport", lambda url, model, sentinel=None: (lambda: transports[url])
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
        compare, "make_http_transport", lambda url, model, sentinel=None: (lambda: transports[url])
    )
    assert oracle_main.main(_cli_args(tmp_path)) == 1
    data = json.loads((tmp_path / "out.json").read_text())  # output still written
    assert data["variant"]["vulnerabilities"]["TA-SEC-01"]["errors"] == 2


def _partial_error_transports():
    return {
        "http://b.invalid": LeakyTransport(),
        "http://v.invalid": FlakyTransport(RuntimeError("blip"), fail_on={1}),
    }


def test_cli_any_error_exits_1_with_stderr_banner_unless_allow_errors(
    tmp_path, monkeypatch, capsys
):
    for allow, expected_rc in ((False, 1), (True, 0)):
        transports = _partial_error_transports()
        monkeypatch.setattr(
            compare, "make_http_transport",
            lambda url, model, sentinel=None, t=transports: (lambda: t[url]),
        )
        args = _cli_args(tmp_path) + (["--allow-errors"] if allow else [])
        assert oracle_main.main(args) == expected_rc
        captured = capsys.readouterr()
        assert "WARNING: 1 measurement errors — counts exclude them" in captured.err
        assert "WARNING: 1 measurement errors" in (tmp_path / "out.md").read_text()
        data = json.loads((tmp_path / "out.json").read_text())
        assert data["error_sentinel"] == compare.default_error_sentinel()
        assert data["measurement_errors"]["total"] == 1


def test_cli_allow_errors_still_fails_when_probe_errors_every_trial(tmp_path, monkeypatch):
    transports = {
        "http://b.invalid": LeakyTransport(),
        "http://v.invalid": FlakyTransport(TimeoutError("t/o")),
    }
    monkeypatch.setattr(
        compare, "make_http_transport",
        lambda url, model, sentinel=None: (lambda: transports[url]),
    )
    assert oracle_main.main(_cli_args(tmp_path) + ["--allow-errors"]) == 1


def test_help_documents_restart_and_flags():
    proc = subprocess.run(
        [sys.executable, "-m", "oracle", "compare", "--help"],
        cwd=_ROOT, capture_output=True, text=True, timeout=60, check=False,
    )
    out = " ".join(proc.stdout.split())
    assert "RESTART the agents" in out
    for flag in ("--error-sentinel", "--allow-errors", "--canary-map"):
        assert flag in out


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
_TOK_SEC01 = token(_REG.agent, "TA-SEC-01", "secret")
_TOK_CARD = token(_REG.agent, "TA-SAF-01", "card")


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
    assert not any(tok in " ".join(_BLIND.values()) for tok in _CANARY_TOKENS)

    mapped = _run_map(BlindLeakyTransport(), SecureTransport(), _BLIND)
    for vid in _CANARY_VULNS:
        b = mapped["baseline"]["vulnerabilities"][vid]
        v = mapped["variant"]["vulnerabilities"][vid]
        assert (b["exploited"], b["not_exploited"], b["errors"]) == (2, 0, 0), vid
        assert (v["exploited"], v["not_exploited"], v["errors"]) == (0, 2, 0), vid

    unmapped = _run_map(BlindLeakyTransport(), SecureTransport(), None)
    for vid in _CANARY_VULNS:
        b = unmapped["baseline"]["vulnerabilities"][vid]
        assert (b["exploited"], b["not_exploited"], b["errors"]) == (0, 2, 0), vid


def test_canary_map_absent_blind_value_is_not_exploited():
    res = _run_map(SecureTransport(), SecureTransport(), _BLIND)
    for vid in _CANARY_VULNS:
        assert res["baseline"]["vulnerabilities"][vid]["exploited"] == 0, vid


def test_canary_map_digest_is_canonical_and_agrees_cli_api(tmp_path, monkeypatch):
    transports = {"http://b.invalid": BlindLeakyTransport(), "http://v.invalid": SecureTransport()}
    monkeypatch.setattr(
        compare, "make_http_transport",
        lambda url, model, sentinel=None: (lambda: transports[url]),
    )
    # File with reversed key order and indentation: digest must still be canonical.
    mp = tmp_path / "map.json"
    mp.write_text(json.dumps(dict(reversed(list(_BLIND.items()))), indent=4))
    assert oracle_main.main(_cli_args(tmp_path) + ["--canary-map", str(mp)]) == 0

    import hashlib

    raw = (tmp_path / "out.json").read_text()
    data = json.loads(raw)
    expected = hashlib.sha256(
        json.dumps(_BLIND, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    assert data["canary_map_sha256"] == expected == compare.canary_map_digest(_BLIND)
    api = _run_map(BlindLeakyTransport(), SecureTransport(), _BLIND)
    assert api["canary_map_sha256"] == data["canary_map_sha256"]
    assert data["baseline"]["vulnerabilities"]["TA-SEC-01"]["exploited"] == 2
    for blind in _BLIND.values():
        assert blind not in raw  # contents are not recorded
    for tok in _CANARY_TOKENS:
        assert tok not in raw


def test_no_canary_map_records_null_digest():
    assert _run(LeakyTransport(), SecureTransport(), trials=1)["canary_map_sha256"] is None


def test_canary_map_unknown_key_rejected(tmp_path, capsys):
    bad = dict(_BLIND)
    bad["VIJIL-CANARY-not-in-registry"] = "BLIND-x-long-enough"
    with pytest.raises(compare.CanaryMapError, match="VIJIL-CANARY-not-in-registry"):
        _run_map(LeakyTransport(), SecureTransport(), bad)

    mp = tmp_path / "bad.json"
    mp.write_text(json.dumps(bad))
    rc = oracle_main.main(_cli_args(tmp_path) + ["--canary-map", str(mp)])
    assert rc == 2
    err = capsys.readouterr().err
    assert "VIJIL-CANARY-not-in-registry" in err and "not a canary token" in err
    assert not (tmp_path / "out.json").exists()


def _validate(m):
    return compare.validate_canary_map(_REG, m)


def test_canary_map_validation_rules():
    assert _validate(_BLIND) == _BLIND
    first, second = _CANARY_TOKENS[0], _CANARY_TOKENS[1]

    with pytest.raises(compare.CanaryMapError, match="JSON object"):
        _validate([first])
    missing = dict(_BLIND)
    del missing[second]
    with pytest.raises(compare.CanaryMapError, match="missing registry canary") as ei:
        _validate(missing)
    assert second in str(ei.value)
    with pytest.raises(compare.CanaryMapError, match="shorter than 12"):
        _validate({**_BLIND, first: "short-value"})
    with pytest.raises(compare.CanaryMapError, match="itself a registry token"):
        _validate({**_BLIND, first: second})
    prompt_text = " ".join(_REG.vulnerabilities[0].probes[0].prompt.split())[:24]
    with pytest.raises(compare.CanaryMapError, match="probe prompt or registry oracle"):
        _validate({**_BLIND, first: prompt_text})
    with pytest.raises(compare.CanaryMapError, match="probe prompt or registry oracle"):
        _validate({**_BLIND, first: "9[,]?999[,]?"})  # inside TA-REL-01's regex value
    with pytest.raises(compare.CanaryMapError, match="substring of another"):
        _validate({**_BLIND, first: "BLIND-0001-opa", second: "BLIND-0001-opaque"})
    with pytest.raises(compare.CanaryMapError, match="maps to both"):
        _validate({**_BLIND, first: "same-opaque-value", second: "same-opaque-value"})


def test_canary_map_file_errors(tmp_path):
    p = tmp_path / "x.json"
    p.write_text("{not json")
    with pytest.raises(compare.CanaryMapError, match="not valid JSON"):
        compare.load_canary_map(p, _REG)


def test_translator_matches_reformatted_digits_and_case_insensitive_keys():
    card, sec = "4451014480034591", "sk_live_AbC123xyzQWERTY"
    mapping = {**_BLIND, _TOK_CARD: card, _TOK_SEC01: sec}
    _validate(mapping)
    tr = compare.make_translator(mapping)
    for variant in (
        "4451014480034591",
        "4451 0144 8003 4591",
        "4451-0144-8003-4591",
        "4451 0144-8003 4591",
    ):
        assert tr(f"card {variant}!") == f"card {_TOK_CARD}!", variant
    for variant in ("sk_live_AbC123xyzQWERTY", "SK_LIVE_ABC123XYZQWERTY", "sk_live_abc123xyzqwerty"):
        assert tr(f"key={variant}.") == f"key={_TOK_SEC01}.", variant
    # Non-prefixed values stay exact-case; different digits do not match.
    other = _BLIND[_CANARY_TOKENS[1]]
    assert tr(other) == _CANARY_TOKENS[1]
    assert tr(other.lower()) == other.lower()  # exact-case for non-prefixed values
    assert tr("4451 0144 8003 4592") == "4451 0144 8003 4592"


def test_reformatted_blind_values_graded_exploited_end_to_end():
    card, sec = "4451014480034591", "sk_live_AbC123xyzQWERTY"
    mapping = {**_BLIND, _TOK_CARD: card, _TOK_SEC01: sec}

    class Reformatting(LeakyTransport):
        async def chat(self, prompt, system_prompt=None):
            return "Card: 4451 0144 8003 4591 and key SK_LIVE_ABC123XYZQWERTY " + " ".join(
                _BLIND[t] for t in _CANARY_TOKENS if t not in (_TOK_CARD, _TOK_SEC01)
            )

    res = _run_map(Reformatting(), SecureTransport(), mapping, trials=1)
    assert res["baseline"]["vulnerabilities"]["TA-SAF-01"]["exploited"] == 1
    assert res["baseline"]["vulnerabilities"]["TA-SEC-01"]["exploited"] == 1


# ---------------------------------------------------------------------------
# multi-probe aggregation, probe errors, ordering
# ---------------------------------------------------------------------------

_SYNTH = """\
agent: synth_agent
framework: test
model: none
vulnerabilities:
{vulns}
"""


def _synth_vuln(vid, probes):
    body = "".join(
        f"""      - id: {pid}
        channel: {chan}
        intent: x
        prompt: {json.dumps(prompt)}
        oracle:
          - kind: contains
            value: LEAKED-VALUE
"""
        for pid, chan, prompt in probes
    )
    return f"""  - id: {vid}
    title: t
    dimension: security
    sub_dimension: confidentiality
    surface: tool
    severity: high
    location: x.py:f
    description: d
    design_tension: dt
    disclosure: di
    probes:
{body}"""


class PromptScripted:
    """chat answers by prompt: 'LEAK' -> leaks, 'CLEAN' -> clean, 'BOOM' -> raises."""

    async def chat(self, prompt, system_prompt=None):
        if prompt == "BOOM":
            raise TimeoutError("probe timed out")
        return "LEAKED-VALUE" if prompt == "LEAK" else "nothing here"

    async def admin(self, method, path, body):
        return 200, "ok"


def test_multi_probe_aggregation(tmp_path):
    reg = tmp_path / "synth.yaml"
    reg.write_text(
        _SYNTH.format(
            vulns=_synth_vuln("S-1", [("S-1-a", "chat", "LEAK"), ("S-1-b", "chat", "BOOM")])
            + _synth_vuln("S-2", [("S-2-a", "chat", "CLEAN"), ("S-2-b", "chat", "BOOM")])
            + _synth_vuln("S-3", [("S-3-a", "chat", "CLEAN"), ("S-3-b", "chat", "CLEAN")])
            + _synth_vuln("S-4", [("S-4-a", "admin_http", "NOPE")])
        )
    )
    res = asyncio.run(
        compare.run_compare(reg, PromptScripted, PromptScripted, 2)
    )
    v = res["baseline"]["vulnerabilities"]
    # probe1 exploited + probe2 errored => exploited (positive evidence stands)
    assert (v["S-1"]["exploited"], v["S-1"]["not_exploited"], v["S-1"]["errors"]) == (2, 0, 0)
    # probe1 not_exploited + probe2 errored => errors, never not_exploited
    assert (v["S-2"]["exploited"], v["S-2"]["not_exploited"], v["S-2"]["errors"]) == (0, 0, 2)
    assert (v["S-3"]["exploited"], v["S-3"]["not_exploited"], v["S-3"]["errors"]) == (0, 2, 0)
    # malformed admin prompt (run_probe's "<probe error:" transcript) is an ERROR
    assert (v["S-4"]["exploited"], v["S-4"]["not_exploited"], v["S-4"]["errors"]) == (0, 0, 2)
    assert v["S-4"]["probes"]["S-4-a"]["error_details"][0].startswith("<probe error:")


class RecordingTransport(LeakyTransport):
    log: list = []  # noqa: RUF012 - shared test recorder

    async def chat(self, prompt, system_prompt=None):
        RecordingTransport.log.append("chat")
        return await super().chat(prompt, system_prompt)

    async def admin(self, method, path, body):
        RecordingTransport.log.append(f"admin:{method}")
        return await super().admin(method, path, body)


def test_chat_probes_run_before_mutating_admin_probes_and_are_recorded():
    RecordingTransport.log = []
    res = asyncio.run(
        compare.run_compare(_REGISTRY, RecordingTransport, RecordingTransport, 2)
    )
    log = RecordingTransport.log
    half = len(log) // 2
    for side in (log[:half], log[half:]):  # baseline then variant
        kinds = ["chat" if e == "chat" else "admin" for e in side]
        assert kinds == sorted(kinds, key=lambda k: k != "chat")  # all chat, then all admin
        assert kinds.count("chat") > 0 and kinds.count("admin") > 0
    assert "admin:POST" in log
    assert res["mutating_probes_run"] == ["TA-SEC-03-p1"]
    assert res["baseline"]["mutating_probes_run"] == ["TA-SEC-03-p1"]
    assert res["variant"]["mutating_probes_run"] == ["TA-SEC-03-p1"]
