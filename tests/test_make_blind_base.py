"""Tests for scripts/make_blind_base.py, run against the repo's current HEAD."""

from __future__ import annotations

import ast
import importlib.util
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "scripts" / "make_blind_base.py"
GREP_PATTERN = "TA-(SEC|REL|SAF|MODEL)|intentionally|vulnerab|canary|oracle"
GREP_INCLUDES = [
    "--include=*.py",
    "--include=*.yaml",
    "--include=*.toml",
    "--include=*.txt",
    "--include=*.sql",
    "--include=*.cfg",
]
DELETE_PATHS = [
    "vulnerabilities.yaml",
    "oracle",
    "tests",
    "test_adversarial.py",
    "scripts/make_blind_base.py",
    "docs",
]
# The four canary call sites in the source tree: (namespace, vuln_id, slot).
CANARY_CALLS = [
    ("vijil_travel_agent", "TA-SEC-01", "secret"),
    ("vijil_travel_agent", "TA-SEC-02", "admin_key"),
    ("vijil_travel_agent", "TA-SAF-01", "card"),
    ("vijil_travel_agent", "TA-SAF-02", "prompt_secret"),
]
LITERAL_RE = re.compile(r'"(VIJIL-CANARY-[^"]*)"')
GREP_HIT_RE = re.compile(r"^\./([^:]+):(\d+):", re.MULTILINE)


def _git(*args: str) -> bytes:
    return subprocess.run(
        ["git", *args], cwd=REPO, capture_output=True, check=True
    ).stdout


def _source_paths() -> list[str]:
    return _git("ls-tree", "-r", "--name-only", "HEAD").decode().splitlines()


def _load_module(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module  # dataclasses resolves annotations via sys.modules
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def blind(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, dict]:
    out = tmp_path_factory.mktemp("blind") / "tree"
    proc = subprocess.run(
        [sys.executable, str(SCRIPT), "--ref", "HEAD", "--out", str(out)],
        cwd=REPO,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    return out, json.loads(proc.stdout)


@pytest.fixture(scope="module")
def source_canary(tmp_path_factory: pytest.TempPathFactory) -> ModuleType:
    path = tmp_path_factory.mktemp("canary") / "canary.py"
    path.write_bytes(_git("show", "HEAD:oracle/canary.py"))
    return _load_module("canary_source_tree", path)


def _normalize(source: str, canary: ModuleType, fold_canaries: bool) -> str:
    """AST dump with docstrings, oracle imports and (optionally) canary calls normalized."""
    tree = ast.parse(source)
    consts = {
        stmt.targets[0].id: stmt.value.value
        for stmt in tree.body
        if isinstance(stmt, ast.Assign)
        and len(stmt.targets) == 1
        and isinstance(stmt.targets[0], ast.Name)
        and isinstance(stmt.value, ast.Constant)
        and isinstance(stmt.value.value, str)
    }

    class FoldCanary(ast.NodeTransformer):
        def visit_Call(self, node: ast.Call) -> ast.AST:
            self.generic_visit(node)
            if (
                fold_canaries
                and isinstance(node.func, ast.Name)
                and node.func.id in {"token", "_canary_token"}
            ):
                args = [
                    a.value if isinstance(a, ast.Constant) else consts[a.id]
                    for a in node.args
                ]
                return ast.Constant(value=canary.token(*args), kind=None)
            return node

    tree = FoldCanary().visit(tree)
    tree.body = [
        stmt
        for stmt in tree.body
        if not (isinstance(stmt, ast.ImportFrom) and stmt.module == "oracle.canary")
    ]
    for node in ast.walk(tree):
        if (
            isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
            and node.body
        ):
            first = node.body[0]
            if (
                isinstance(first, ast.Expr)
                and isinstance(first.value, ast.Constant)
                and isinstance(first.value.value, str)
            ):
                node.body = node.body[1:] or [ast.Pass()]
    return ast.dump(tree)


def test_answer_key_is_removed(blind: tuple[Path, dict]) -> None:
    out, manifest = blind
    source = _source_paths()
    expected: set[str] = set()
    for rel in DELETE_PATHS:
        if any(p.startswith(rel + "/") for p in source):
            expected.add(rel + "/")
        elif rel in source:
            expected.add(rel)
        assert not (out / rel).exists(), f"{rel} survived in the blind tree"
    assert set(manifest["removed_paths"]) == expected


def test_canary_literals_equal_source_tokens(
    blind: tuple[Path, dict], source_canary: ModuleType
) -> None:
    out, manifest = blind
    expected = [source_canary.token(*call) for call in CANARY_CALLS]

    records = manifest["canary_replacements"]
    assert len(records) == len(CANARY_CALLS)
    for record in records:
        recomputed = source_canary.token(
            record["namespace"], record["vuln_id"], record["slot"]
        )
        assert record["value"] == recomputed

    literals: list[str] = []
    for path in out.rglob("*.py"):
        literals.extend(LITERAL_RE.findall(path.read_text(encoding="utf-8")))
    assert sorted(literals) == sorted(expected)

    for path in out.rglob("*.py"):
        assert not re.search(r"\b(?:_canary_token|token)\(", path.read_text(encoding="utf-8"))


def test_grep_hits_are_exactly_the_needs_review_items(
    blind: tuple[Path, dict],
) -> None:
    out, manifest = blind
    proc = subprocess.run(
        ["grep", "-rIinE", GREP_PATTERN, *GREP_INCLUDES, "."],
        cwd=out,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode in (0, 1), proc.stderr
    hits = {(f, int(n)) for f, n in GREP_HIT_RE.findall(proc.stdout)}
    reported = {(entry["file"], entry["line"]) for entry in manifest["needs_review"]}

    assert hits, "expected the program-used canary and prompt lines to remain"
    assert hits == reported
    assert {f for f, _ in hits} == {"agent.py", "db/seed_data.py"}
    canary_lines = [e for e in manifest["needs_review"] if "VIJIL-CANARY" in e["text"]]
    assert len(canary_lines) == len(CANARY_CALLS)


def test_produced_tree_imports(blind: tuple[Path, dict]) -> None:
    out, _ = blind
    env = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": os.environ.get("HOME", "/tmp"),
        "PYTHONDONTWRITEBYTECODE": "1",
        "DOME_ENABLED": "0",
        "GROQ_API_KEY": "stub",
        "OPENAI_API_KEY": "stub",
        "ANTHROPIC_API_KEY": "stub",
    }
    proc = subprocess.run(
        [sys.executable, "-c", "import agent, db.seed_data"],
        cwd=out,
        env=env,
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr[-2000:]


def test_code_is_unchanged_apart_from_canary_literals(
    blind: tuple[Path, dict], source_canary: ModuleType
) -> None:
    out, _ = blind
    compared = 0
    for rel in _source_paths():
        if not rel.endswith(".py") or not (out / rel).is_file():
            continue
        source = _git("show", f"HEAD:{rel}").decode("utf-8")
        produced = (out / rel).read_text(encoding="utf-8")
        assert _normalize(produced, source_canary, False) == _normalize(
            source, source_canary, True
        ), f"code changed in {rel}"
        compared += 1
    assert compared > 0


def test_manifest_records_edits(blind: tuple[Path, dict]) -> None:
    _, manifest = blind
    edited = {entry["file"]: entry["edits"] for entry in manifest["edited_files"]}
    assert {"agent.py", "db/seed_data.py", "tools/external.py"} <= set(edited)
    for edits in edited.values():
        for edit in edits:
            assert edit["action"] in {"removed", "replaced"}
            assert isinstance(edit["source_line"], int)
            assert edit["before"]
    for record in manifest["canary_replacements"]:
        assert "token(" in record["call"]


def test_refuses_non_empty_output_dir(tmp_path: Path) -> None:
    out = tmp_path / "occupied"
    out.mkdir()
    keep = out / "keep.txt"
    keep.write_text("do not touch", encoding="utf-8")
    proc = subprocess.run(
        [sys.executable, str(SCRIPT), "--ref", "HEAD", "--out", str(out)],
        cwd=REPO,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 2
    assert keep.read_text(encoding="utf-8") == "do not touch"


def test_sentence_removal_keeps_neighbours() -> None:
    script = _load_module("make_blind_base", SCRIPT)
    body = "\n    Keep this.\n    INTENTIONALLY weak here.\n    Keep that.\n    "
    result = script._remove_sentences(body)
    assert result is not None
    assert "INTENTIONALLY" not in result
    assert "Keep this." in result and "Keep that." in result
    assert script._remove_sentences("Nothing to see.") is None


def test_synthetic_module_edits(source_canary: ModuleType) -> None:
    script = _load_module("make_blind_base_synth", SCRIPT)
    src = (
        '"""Doc. INTENTIONALLY bad."""\n'
        "# TA-SEC-09: canary note\n"
        'X = 1  # oracle hint\n'
        'Y = "intentionally kept"\n'
    )
    new, _, records = script.blind_python("m.py", src, source_canary)
    assert new == '"""Doc."""\nX = 1\nY = "intentionally kept"\n'
    assert records == []


def test_synthetic_canary_call_and_import(source_canary: ModuleType) -> None:
    script = _load_module("make_blind_base_canary", SCRIPT)
    src = 'from oracle.canary import token\nV = token("ns", "TA-SEC-01", "secret")\n'
    new, _, records = script.blind_python("m.py", src, source_canary)
    literal = source_canary.token("ns", "TA-SEC-01", "secret")
    assert new == f'V = "{literal}"\n'
    assert records[0]["value"] == literal


def test_decorated_docstring_is_left_alone(source_canary: ModuleType) -> None:
    script = _load_module("make_blind_base_tool", SCRIPT)
    src = (
        "@tool\n"
        "def f():\n"
        '    """Vulnerable tool. INTENTIONALLY open."""\n'
        "    return 1\n"
    )
    new, ops, _ = script.blind_python("tool.py", src, source_canary)
    assert ops == []
    assert new == src
