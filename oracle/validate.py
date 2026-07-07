"""Internal-consistency checks for registries and their planted canaries.

Two independent guarantees:

  * :func:`self_check` -- a registry is *well-formed*: every probe has an oracle,
    every canary an oracle references is declared, taxonomy tags are coherent.
    (Most of this is enforced by the pydantic validators at load time; this adds
    the cross-cutting checks and produces a human-readable issue list rather
    than raising on the first problem.)

  * :func:`verify_canaries_planted` -- every canary the registry *declares* is
    actually present in the agent's seed material (DB seed SQL, system prompt,
    config). This is what stops the registry and the code from drifting apart:
    if a canary is declared but never planted, the oracle can never fire on it,
    and this check fails loudly.
"""
from __future__ import annotations

from oracle.canary import token as canary_token
from oracle.registry import AgentRegistry, OracleCheckKind


def self_check(registry: AgentRegistry) -> list[str]:
    """Return a list of consistency issues; empty list == clean."""
    issues: list[str] = []
    for vuln in registry.vulnerabilities:
        if not vuln.location.strip():
            issues.append(f"{vuln.id}: empty location")
        if not vuln.design_tension.strip():
            issues.append(f"{vuln.id}: missing design_tension (realism rationale)")
        canary_slots = {c.slot for c in vuln.canaries}
        used_slots: set[str] = set()
        for probe in vuln.probes:
            for check in probe.oracle:
                if check.kind is OracleCheckKind.CANARY_LEAKED and check.canary_slot:
                    used_slots.add(check.canary_slot)
        orphan = canary_slots - used_slots
        if orphan:
            issues.append(
                f"{vuln.id}: canary slots {sorted(orphan)} declared but no probe checks them"
            )
    return issues


def verify_canaries_planted(registry: AgentRegistry, materials: dict[str, str]) -> list[str]:
    """Check every declared canary token appears in some seed material.

    Args:
        registry: the agent's ground truth.
        materials: name -> text blobs of everything the agent seeds/embeds
            (e.g. ``{"seed_sql": ..., "system_prompt": ..., "config": ...}``).

    Returns:
        A list of "unplanted canary" issues; empty list == every declared canary
        is actually reachable by the agent.
    """
    blob = "\n".join(materials.values())
    issues: list[str] = []
    for vuln in registry.vulnerabilities:
        for canary in vuln.canaries:
            expected = canary_token(registry.agent, vuln.id, canary.slot)
            if expected not in blob:
                issues.append(
                    f"{vuln.id}/{canary.slot}: canary {expected!r} declared "
                    f"(planted_in={canary.planted_in!r}) but absent from seed materials"
                )
    return issues
