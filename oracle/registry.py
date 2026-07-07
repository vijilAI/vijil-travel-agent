"""The ground-truth registry: what is seeded, how it discloses, how to verify.

This is the oracle's source of truth. Each agent ships a ``vulnerabilities.yaml``
that deserialises into an :class:`AgentRegistry`. Every seeded weakness names:

  * where it lives (surface + file:line/endpoint/tool) and what it maps to in
    the R/S/Sa taxonomy and the OWASP-ASI / MITRE frameworks;
  * the *design tension* that makes a real enterprise build it this way (so the
    weakness reads as realistic, not contrived);
  * one or more **probes** -- concrete red-team inputs -- each paired with a
    deterministic **oracle** (a list of checks that ALL must hold for the probe
    to count as having disclosed the weakness).

The registry is the contract between the seeded agents and any red-team system:
the red-teamer discovers weaknesses; the oracle says, deterministically, which
seeded weaknesses were actually disclosed and which were missed.
"""
from __future__ import annotations

from enum import Enum
from pathlib import Path

import yaml
from pydantic import BaseModel, Field, model_validator

from oracle.taxonomy import (
    MitreAttack,
    OwaspAsi,
    Severity,
    SubDimension,
    Surface,
    TrustDimension,
    pillar_of,
)


class OracleCheckKind(str, Enum):
    """The deterministic predicates the checker can evaluate.

    None of these consult a model. Each is a pure function of the probe
    transcript (and, for canaries, the registry).
    """

    CONTAINS = "contains"  # response contains a literal substring
    NOT_CONTAINS = "not_contains"  # response must NOT contain it (e.g. no refusal)
    REGEX = "regex"  # response matches a regex
    CANARY_LEAKED = "canary_leaked"  # a named canary token appears in response
    DB_ROW_PRESENT = "db_row_present"  # a row matching a predicate exists post-probe
    HTTP_STATUS = "http_status"  # an admin/tool HTTP call returned this status
    TOOL_CALLED = "tool_called"  # the agent invoked a named tool


class OracleCheckTarget(str, Enum):
    RESPONSE_TEXT = "response_text"
    DB = "db"
    HTTP = "http"
    TOOL_TRACE = "tool_trace"


class OracleCheck(BaseModel):
    """One deterministic predicate over a probe transcript."""

    kind: OracleCheckKind
    target: OracleCheckTarget = OracleCheckTarget.RESPONSE_TEXT
    value: str = ""  # substring / regex / tool name / status code / row-predicate
    canary_slot: str | None = None  # for CANARY_LEAKED: which canary slot to expect
    description: str = ""

    @model_validator(mode="after")
    def _require_value_where_needed(self) -> "OracleCheck":
        needs_value = {
            OracleCheckKind.CONTAINS,
            OracleCheckKind.NOT_CONTAINS,
            OracleCheckKind.REGEX,
            OracleCheckKind.HTTP_STATUS,
            OracleCheckKind.TOOL_CALLED,
            OracleCheckKind.DB_ROW_PRESENT,
        }
        if self.kind in needs_value and not self.value:
            raise ValueError(f"check {self.kind} requires a non-empty value")
        if self.kind is OracleCheckKind.CANARY_LEAKED and not self.canary_slot:
            raise ValueError("canary_leaked check requires canary_slot")
        return self


class Canary(BaseModel):
    """A sentinel planted for one vulnerability. ``slot`` is unique per vuln."""

    slot: str
    kind: str  # taxonomy.CanaryKind value; kept as str for forward-compat
    planted_in: str  # human note: 'db:api_credentials.api_secret', 'prompt', ...
    note: str = ""


class Probe(BaseModel):
    """A red-team input plus the oracle that confirms disclosure."""

    id: str
    channel: str = "chat"  # chat | admin_http | tool
    intent: str  # what the attacker is trying to elicit
    prompt: str  # the concrete input (or HTTP path/body for admin_http)
    attack_types: list[MitreAttack] = Field(default_factory=list)
    oracle: list[OracleCheck]  # ALL must hold => probe disclosed the weakness

    @model_validator(mode="after")
    def _nonempty_oracle(self) -> "Probe":
        if not self.oracle:
            raise ValueError(f"probe {self.id} has an empty oracle (nothing to verify)")
        return self


class SeededVulnerability(BaseModel):
    """One intentional weakness, fully specified for red-team + oracle use."""

    id: str
    title: str
    dimension: TrustDimension
    sub_dimension: SubDimension
    surface: Surface
    severity: Severity
    location: str  # file:line, /admin/endpoint, or tool:name
    owasp_asi: list[OwaspAsi] = Field(default_factory=list)
    mitre_attack: list[MitreAttack] = Field(default_factory=list)
    description: str
    design_tension: str  # why a real enterprise would ship this
    disclosure: str  # how the weakness manifests when probed
    canaries: list[Canary] = Field(default_factory=list)
    probes: list[Probe]

    @model_validator(mode="after")
    def _consistency(self) -> "SeededVulnerability":
        if pillar_of(self.sub_dimension) is not self.dimension:
            raise ValueError(
                f"{self.id}: sub_dimension {self.sub_dimension} not under {self.dimension}"
            )
        if not self.probes:
            raise ValueError(f"{self.id}: at least one probe is required")
        slots = {c.slot for c in self.canaries}
        for probe in self.probes:
            for check in probe.oracle:
                if check.canary_slot is not None and check.canary_slot not in slots:
                    raise ValueError(
                        f"{self.id}/{probe.id}: oracle references canary slot "
                        f"'{check.canary_slot}' not declared in canaries"
                    )
        return self


class AgentRegistry(BaseModel):
    """All seeded weaknesses for one agent."""

    agent: str
    framework: str
    model: str
    vulnerabilities: list[SeededVulnerability]

    @model_validator(mode="after")
    def _unique_ids(self) -> "AgentRegistry":
        ids = [v.id for v in self.vulnerabilities]
        dupes = {i for i in ids if ids.count(i) > 1}
        if dupes:
            raise ValueError(f"{self.agent}: duplicate vulnerability ids {sorted(dupes)}")
        return self

    @classmethod
    def from_yaml(cls, path: str | Path) -> "AgentRegistry":
        data = yaml.safe_load(Path(path).read_text())
        return cls.model_validate(data)

    def coverage(self) -> dict[str, int]:
        """Count seeded weaknesses per trust pillar -- makes empty cells visible."""
        counts = {d.value: 0 for d in TrustDimension}
        for vuln in self.vulnerabilities:
            counts[vuln.dimension.value] += 1
        return counts
