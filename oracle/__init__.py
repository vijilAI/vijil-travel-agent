"""Deterministic vulnerability oracle for the sample agents.

Three parts:

  * :mod:`oracle.taxonomy` -- the R/S/Sa + OWASP-ASI + MITRE vocabulary.
  * :mod:`oracle.registry` -- the ground-truth data model (``AgentRegistry``)
    loaded from each agent's ``vulnerabilities.yaml``.
  * :mod:`oracle.checker` -- the deterministic engine that grades a
    red-team run against that ground truth.

Plus :mod:`oracle.canary` (sentinel tokens) and
:mod:`oracle.validate` (internal-consistency + planting checks).

The oracle lets a red-team system be *measured*: seed known weaknesses, run the
red-teamer, and let the checker say -- with no LLM in the loop -- which seeded
weaknesses were actually disclosed and which were missed.
"""
from __future__ import annotations

from oracle.canary import CanaryKind, is_canary
from oracle.canary import token as canary_token
from oracle.checker import (
    RegistryReport,
    Transcript,
    score_registry,
)
from oracle.probe_runner import (
    HttpTransport,
    probe_and_score,
    run_registry,
)
from oracle.registry import AgentRegistry, SeededVulnerability
from oracle.validate import verify_canaries_planted

__all__ = [
    "AgentRegistry",
    "SeededVulnerability",
    "Transcript",
    "RegistryReport",
    "score_registry",
    "canary_token",
    "CanaryKind",
    "is_canary",
    "verify_canaries_planted",
    "HttpTransport",
    "run_registry",
    "probe_and_score",
]
