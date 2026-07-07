"""CLI: validate registries and grade red-team transcripts.

Usage:

  # Validate every agent registry (schema + internal consistency):
  python -m oracle validate agents/*/vulnerabilities.yaml

  # Grade a red-team run: transcripts.json is {probe_id: {response_text, ...}}
  python -m oracle score --registry agents/claims_processing/vulnerabilities.yaml \
      --transcripts run.json

Exit code is non-zero when validation finds issues, so this is CI-usable.
"""
from __future__ import annotations

import argparse
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
    raw = json.loads(open(transcripts_path).read())
    transcripts = {pid: Transcript(probe_id=pid, **fields) for pid, fields in raw.items()}
    report = score_registry(registry, transcripts)
    print(f"agent={report.agent}  disclosed={report.disclosed}/{report.total} "
          f"({report.disclosure_rate:.0%})")
    for pillar, cell in sorted(report.by_dimension.items()):
        print(f"  {pillar:12s} {cell['disclosed']}/{cell['total']}")
    if report.missed_ids:
        print("  missed: " + ", ".join(report.missed_ids))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="oracle")
    sub = parser.add_subparsers(dest="cmd", required=True)
    v = sub.add_parser("validate", help="validate registry YAML files")
    v.add_argument("patterns", nargs="+")
    s = sub.add_parser("score", help="grade red-team transcripts against a registry")
    s.add_argument("--registry", required=True)
    s.add_argument("--transcripts", required=True)
    args = parser.parse_args(argv)
    if args.cmd == "validate":
        return _cmd_validate(args.patterns)
    if args.cmd == "score":
        return _cmd_score(args.registry, args.transcripts)
    return 2  # pragma: no cover


if __name__ == "__main__":
    raise SystemExit(main())
