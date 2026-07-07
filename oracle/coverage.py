"""Population-level coverage accounting over a set of agent registries.

The plan's promise is that empty R/S/Sa cells are *visible*, not silent. This
module aggregates every agent's seeded weaknesses into per-pillar,
per-sub-dimension, and per-surface tallies, and flags any sub-dimension or
surface that the whole population leaves empty -- the signal that the seeding is
lopsided (e.g. all harness, no model weaknesses).

Pure data + stdlib; consumed by the `coverage` CLI and a test.
"""
from __future__ import annotations

from collections import Counter

from pydantic import BaseModel

from oracle.registry import AgentRegistry
from oracle.taxonomy import (
    SUBDIMENSIONS_BY_PILLAR,
    Surface,
    TrustDimension,
)


class PopulationCoverage(BaseModel):
    agents: int
    total: int
    by_pillar: dict[str, int]
    by_sub_dimension: dict[str, int]
    by_surface: dict[str, int]
    empty_sub_dimensions: list[str]
    empty_surfaces: list[str]


def population_coverage(registries: list[AgentRegistry]) -> PopulationCoverage:
    """Aggregate coverage across registries and flag empty cells."""
    pillar: Counter[str] = Counter()
    sub: Counter[str] = Counter()
    surf: Counter[str] = Counter()
    for registry in registries:
        for vuln in registry.vulnerabilities:
            pillar[vuln.dimension.value] += 1
            sub[vuln.sub_dimension.value] += 1
            surf[vuln.surface.value] += 1

    all_subs = [s.value for subs in SUBDIMENSIONS_BY_PILLAR.values() for s in subs]
    all_surfaces = [s.value for s in Surface]
    return PopulationCoverage(
        agents=len(registries),
        total=sum(pillar.values()),
        by_pillar={d.value: pillar.get(d.value, 0) for d in TrustDimension},
        by_sub_dimension={s: sub.get(s, 0) for s in all_subs},
        by_surface={s: surf.get(s, 0) for s in all_surfaces},
        empty_sub_dimensions=[s for s in all_subs if sub.get(s, 0) == 0],
        empty_surfaces=[s for s in all_surfaces if surf.get(s, 0) == 0],
    )
