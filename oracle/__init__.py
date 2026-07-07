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

from typing import TYPE_CHECKING

# Re-exports are resolved lazily (PEP 562) so that importing a lightweight
# submodule -- e.g. `from oracle.canary import token` from an agent's
# domain_tables at startup -- does NOT pull in pydantic/yaml via checker/registry.
# Each name is fetched from its module only when first accessed.
_EXPORTS = {
    "canary_token": ("oracle.canary", "token"),
    "CanaryKind": ("oracle.canary", "CanaryKind"),
    "is_canary": ("oracle.canary", "is_canary"),
    "Transcript": ("oracle.checker", "Transcript"),
    "RegistryReport": ("oracle.checker", "RegistryReport"),
    "score_registry": ("oracle.checker", "score_registry"),
    "HttpTransport": ("oracle.probe_runner", "HttpTransport"),
    "run_registry": ("oracle.probe_runner", "run_registry"),
    "probe_and_score": ("oracle.probe_runner", "probe_and_score"),
    "AgentRegistry": ("oracle.registry", "AgentRegistry"),
    "SeededVulnerability": ("oracle.registry", "SeededVulnerability"),
    "verify_canaries_planted": ("oracle.validate", "verify_canaries_planted"),
}

__all__ = list(_EXPORTS)


def __getattr__(name: str):  # PEP 562 module-level lazy attribute access
    target = _EXPORTS.get(name)
    if target is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    import importlib

    module, attr = target
    return getattr(importlib.import_module(module), attr)


def __dir__() -> list[str]:
    return sorted(__all__)


if TYPE_CHECKING:  # help type-checkers/IDEs resolve the lazy names  # noqa: F401
    from oracle.canary import CanaryKind, is_canary  # noqa: F401
    from oracle.canary import token as canary_token  # noqa: F401
    from oracle.checker import RegistryReport, Transcript, score_registry  # noqa: F401
    from oracle.probe_runner import HttpTransport, probe_and_score, run_registry  # noqa: F401
    from oracle.registry import AgentRegistry, SeededVulnerability  # noqa: F401
    from oracle.validate import verify_canaries_planted  # noqa: F401
