"""Trust taxonomy for seeded weaknesses.

Maps every seeded weakness onto Vijil's trust utility function (Reliability,
Security, Safety -- R/S/Sa, three sub-dimensions each = nine cells) and onto the
two external frameworks the red-team system reasons in (OWASP Agentic Security
Initiative categories and MITRE ATT&CK-for-agentic tactics).

The point of a shared taxonomy is *coverage accounting*: a registry that only
tags Security leaves the Reliability and Safety cells provably empty, and the
``coverage`` helpers make that gap visible instead of silent.

Pure data + stdlib only -- importable by the deterministic checker without
pulling in any agent-framework dependency.
"""
from __future__ import annotations

from enum import Enum


class TrustDimension(str, Enum):
    """The three pillars of the Vijil trust utility function."""

    RELIABILITY = "reliability"
    SECURITY = "security"
    SAFETY = "safety"


class SubDimension(str, Enum):
    """Nine sub-dimensions, three per pillar.

    Reliability triad mirrors the loop-cycle reliability rubric families
    (Correctness / Consistency / Robustness). Security and Safety triads name
    the failure axes the security and safety sweeps already probe.
    """

    # Reliability
    CORRECTNESS = "correctness"
    CONSISTENCY = "consistency"
    ROBUSTNESS = "robustness"
    # Security
    CONFIDENTIALITY = "confidentiality"
    INTEGRITY = "integrity"
    AUTHORIZATION = "authorization"
    # Safety
    CONTENT_SAFETY = "content_safety"
    PRIVACY = "privacy"
    REFUSAL_ROBUSTNESS = "refusal_robustness"


SUBDIMENSIONS_BY_PILLAR: dict[TrustDimension, tuple[SubDimension, ...]] = {
    TrustDimension.RELIABILITY: (
        SubDimension.CORRECTNESS,
        SubDimension.CONSISTENCY,
        SubDimension.ROBUSTNESS,
    ),
    TrustDimension.SECURITY: (
        SubDimension.CONFIDENTIALITY,
        SubDimension.INTEGRITY,
        SubDimension.AUTHORIZATION,
    ),
    TrustDimension.SAFETY: (
        SubDimension.CONTENT_SAFETY,
        SubDimension.PRIVACY,
        SubDimension.REFUSAL_ROBUSTNESS,
    ),
}


def pillar_of(sub: SubDimension) -> TrustDimension:
    """Return the pillar a sub-dimension belongs to."""
    for pillar, subs in SUBDIMENSIONS_BY_PILLAR.items():
        if sub in subs:
            return pillar
    raise ValueError(f"orphan sub-dimension: {sub}")  # pragma: no cover


class Surface(str, Enum):
    """Where the weakness lives.

    The user's distinction between "harness" and "model" weaknesses: HARNESS /
    TOOL / CONFIG / DATA defects live in code the agent runs; MODEL / PROMPT
    defects live in the instruction and model choice the agent reasons with.
    A realistic enterprise agent harbours both.
    """

    HARNESS = "harness"  # server, routing, db access wiring
    TOOL = "tool"  # a tool function's behaviour
    CONFIG = "config"  # runtime config / thresholds
    DATA = "data"  # seed data / stored records
    PROMPT = "prompt"  # system prompt / instructions
    MODEL = "model"  # model choice / decoding params


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class OwaspAsi(str, Enum):
    """OWASP Agentic Security Initiative top-10 categories."""

    ASI01_GOAL_HIJACK = "ASI-01"  # Agent goal / instruction manipulation
    ASI02_TOOL_MISUSE = "ASI-02"
    ASI03_PRIVILEGE_ABUSE = "ASI-03"  # Identity / privilege abuse
    ASI04_SUPPLY_CHAIN = "ASI-04"
    ASI05_UNEXPECTED_EXECUTION = "ASI-05"
    ASI06_MEMORY_POISONING = "ASI-06"  # Memory / context poisoning
    ASI07_INTER_AGENT_COMMS = "ASI-07"
    ASI08_CASCADING_FAILURES = "ASI-08"
    ASI09_HUMAN_AGENT_TRUST = "ASI-09"
    ASI10_ROGUE_AGENTS = "ASI-10"


class MitreAttack(str, Enum):
    """MITRE ATT&CK tactics, agentic adaptation (14)."""

    RECONNAISSANCE = "reconnaissance"
    RESOURCE_DEVELOPMENT = "resource_development"
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    COMMAND_AND_CONTROL = "command_and_control"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"


ALL_SUBDIMENSIONS: tuple[SubDimension, ...] = tuple(SubDimension)
