"""Oracle CI gate for the travel agent's vulnerability registry.

Asserts the registry is well-formed, covers all three trust pillars, and that
every declared canary is actually planted (DB seed values + system prompt) so
the oracle can fire on it. Deterministic; no model or network.
"""
from __future__ import annotations

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from oracle.registry import AgentRegistry  # noqa: E402
from oracle.validate import self_check, verify_canaries_planted  # noqa: E402

_REGISTRY = os.path.join(os.path.dirname(os.path.dirname(__file__)), "vulnerabilities.yaml")


def test_registry_valid_and_covers_all_pillars():
    reg = AgentRegistry.from_yaml(_REGISTRY)
    assert self_check(reg) == []
    for pillar, count in reg.coverage().items():
        assert count > 0, f"no seeded weakness for pillar '{pillar}'"


def test_db_canaries_planted():
    import db.seed_data as sd

    reg = AgentRegistry.from_yaml(_REGISTRY)
    blob = (
        json.dumps(sd.CORPORATE_CARDS)
        + json.dumps(sd.API_CREDENTIALS)
        + sd._CRED_SECRET
        + sd._ADMIN_KEY
        + sd._CARD_CANARY
    )
    db_reg = reg.model_copy(
        update={
            "vulnerabilities": [
                v for v in reg.vulnerabilities if v.id in ("TA-SEC-01", "TA-SEC-02", "TA-SAF-01")
            ]
        }
    )
    assert verify_canaries_planted(db_reg, {"seed": blob}) == []


def test_prompt_canary_planted():
    """The registry-declared prompt canary must appear in the source AND, at
    runtime, in the effective system prompt the agent actually sends -- so a
    drifted vuln_id/slot can't slip past the gate."""
    from oracle.canary import token

    # The token the registry declares for the prompt-secret canary.
    reg = AgentRegistry.from_yaml(_REGISTRY)
    vuln = next(v for v in reg.vulnerabilities if v.id == "TA-SAF-02")
    slot = next(c.slot for c in vuln.canaries)
    expected = token(reg.agent, "TA-SAF-02", slot)
    assert expected  # deterministic, non-empty

    # Structural check (runs everywhere, no heavy deps).
    src = open(os.path.join(os.path.dirname(os.path.dirname(__file__)), "agent.py")).read()
    assert "_PROMPT_CANARY = _canary_token(" in src
    assert "finance override code {_PROMPT_CANARY}" in src

    # Runtime check: import the agent and assert the computed canary is actually
    # present in the rendered system prompt. Skipped only where the agent's heavy
    # deps aren't installed (they are in CI, which is where this gate matters).
    pytest.importorskip("strands")
    pytest.importorskip("a2a")
    agent = pytest.importorskip("agent")

    prompt = agent.build_system_prompt()
    assert expected in prompt, "prompt canary missing from the effective system prompt"
    assert expected in agent.DEFAULT_SYSTEM_PROMPT
