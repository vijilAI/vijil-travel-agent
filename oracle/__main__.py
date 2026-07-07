"""CLI: validate registries and grade red-team transcripts.

Usage:

  # Validate every agent registry (schema + internal consistency):
  python -m oracle validate vulnerabilities.yaml

  # Grade a red-team run: transcripts.json is {probe_id: {response_text, ...}}
  python -m oracle score --registry vulnerabilities.yaml \
      --transcripts run.json

  # Drive probes against a running agent and grade live (needs the agent up):
  python -m oracle probe --registry vulnerabilities.yaml \
      --base-url http://localhost:8080

Exit code is non-zero when validation finds issues, so this is CI-usable.
"""
from __future__ import annotations

import argparse
import asyncio
import glob
import json
import sys

from oracle.checker import Transcript, score_registry
from oracle.registry import AgentRegistry
from oracle.validate import self_check


def _cmd_validate(patterns: list[str]) -> int:
    paths: list[str] = []
    for pat in patterns:
        paths.extend(sorted(glob.glob(pat)))
    if not paths:
        print("no registry files matched", file=sys.stderr)
        return 2
    failures = 0
    for path in paths:
        try:
            registry = AgentRegistry.from_yaml(path)
        except Exception as exc:  # noqa: BLE001 - report, don't crash the batch
            print(f"FAIL  {path}\n      load error: {exc}")
            failures += 1
            continue
        issues = self_check(registry)
        cov = registry.coverage()
        cov_str = " ".join(f"{k}={v}" for k, v in cov.items())
        if issues:
            print(f"FAIL  {path}  ({len(registry.vulnerabilities)} vulns; {cov_str})")
            for issue in issues:
                print(f"      - {issue}")
            failures += 1
        else:
            print(f"OK    {path}  ({len(registry.vulnerabilities)} vulns; {cov_str})")
    print(f"\n{len(paths) - failures}/{len(paths)} registries clean")
    return 1 if failures else 0


def _cmd_score(registry_path: str, transcripts_path: str) -> int:
    registry = AgentRegistry.from_yaml(registry_path)
    with open(transcripts_path) as fh:
        raw = json.load(fh)
    transcripts = {pid: Transcript(probe_id=pid, **fields) for pid, fields in raw.items()}
    report = score_registry(registry, transcripts)
    print(f"agent={report.agent}  disclosed={report.disclosed}/{report.total} "
          f"({report.disclosure_rate:.0%})")
    for pillar, cell in sorted(report.by_dimension.items()):
        print(f"  {pillar:12s} {cell['disclosed']}/{cell['total']}")
    if report.missed_ids:
        print("  missed: " + ", ".join(report.missed_ids))
    return 0


def _print_report(report) -> None:
    print(f"agent={report.agent}  disclosed={report.disclosed}/{report.total} "
          f"({report.disclosure_rate:.0%})")
    for pillar, cell in sorted(report.by_dimension.items()):
        print(f"  {pillar:12s} {cell['disclosed']}/{cell['total']}")
    if report.missed_ids:
        print("  missed: " + ", ".join(report.missed_ids))


def _cmd_probe(registry_path: str, base_url: str, model: str, out: str | None) -> int:
    from oracle.probe_runner import HttpTransport, run_registry

    registry = AgentRegistry.from_yaml(registry_path)

    async def _run():
        transport = HttpTransport(base_url, model=model)
        try:
            transcripts = await run_registry(registry, transport)
        finally:
            await transport.aclose()
        return transcripts

    transcripts = asyncio.run(_run())
    if out:
        with open(out, "w") as fh:
            json.dump({pid: t.model_dump() for pid, t in transcripts.items()}, fh, indent=2)
    report = score_registry(registry, transcripts)
    _print_report(report)
    return 0


def _cmd_coverage(patterns: list[str]) -> int:
    from oracle.coverage import population_coverage

    paths: list[str] = []
    for pat in patterns:
        paths.extend(sorted(glob.glob(pat)))
    registries = [AgentRegistry.from_yaml(p) for p in paths]
    cov = population_coverage(registries)
    print(f"agents={cov.agents}  seeded_weaknesses={cov.total}")
    print("by pillar:        " + "  ".join(f"{k}={v}" for k, v in cov.by_pillar.items()))
    print("by sub-dimension: " + "  ".join(f"{k}={v}" for k, v in cov.by_sub_dimension.items()))
    print("by surface:       " + "  ".join(f"{k}={v}" for k, v in cov.by_surface.items()))
    if cov.empty_sub_dimensions:
        print("EMPTY sub-dimensions: " + ", ".join(cov.empty_sub_dimensions))
    if cov.empty_surfaces:
        print("EMPTY surfaces: " + ", ".join(cov.empty_surfaces))
    # Empty sub-dimensions are a real gap (a whole R/S/Sa cell unseeded); empty
    # surfaces are informational. Non-zero exit only on the former.
    return 1 if cov.empty_sub_dimensions else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="oracle")
    sub = parser.add_subparsers(dest="cmd", required=True)
    v = sub.add_parser("validate", help="validate registry YAML files")
    v.add_argument("patterns", nargs="+")
    c = sub.add_parser("coverage", help="population coverage report over registries")
    c.add_argument("patterns", nargs="+")
    s = sub.add_parser("score", help="grade red-team transcripts against a registry")
    s.add_argument("--registry", required=True)
    s.add_argument("--transcripts", required=True)
    p = sub.add_parser("probe", help="drive probes against a running agent and grade live")
    p.add_argument("--registry", required=True)
    p.add_argument("--base-url", required=True)
    p.add_argument("--model", default="probe")
    p.add_argument("--out", default=None, help="optional path to write transcripts JSON")
    args = parser.parse_args(argv)
    if args.cmd == "validate":
        return _cmd_validate(args.patterns)
    if args.cmd == "coverage":
        return _cmd_coverage(args.patterns)
    if args.cmd == "score":
        return _cmd_score(args.registry, args.transcripts)
    if args.cmd == "probe":
        return _cmd_probe(args.registry, args.base_url, args.model, args.out)
    return 2  # pragma: no cover


if __name__ == "__main__":
    raise SystemExit(main())
