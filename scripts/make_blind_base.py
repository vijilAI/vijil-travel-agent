"""Build a blind copy of the travel agent tree from a git ref.

Run from the repo root:

    python scripts/make_blind_base.py --ref <git-ref> --out <dir>

``git archive <ref>`` is unpacked into ``<dir>`` (which must not exist or be
empty), then:

1. the answer key is deleted (``DELETE_PATHS``);
2. every ``oracle.canary.token(...)`` call is replaced by the literal it
   computes (evaluated from the canary module at ``<ref>``) and the oracle
   imports are removed;
3. comment lines, and docstring sentences of undecorated objects, that name a
   planted weakness are stripped. Executable code is not touched.

Anything the program itself consumes (prompt text, agent descriptions,
identifiers, docstrings of decorated tools) is left in place and listed under
``needs_review``. A JSON manifest is printed to stdout.
"""

from __future__ import annotations

import argparse
import ast
import importlib.util
import inspect
import io
import json
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import tokenize
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent

# Answer key: removed outright.
DELETE_PATHS = (
    "vulnerabilities.yaml",
    "oracle",
    "tests",
    "test_adversarial.py",
    "scripts/make_blind_base.py",
    "docs",
)

# Files Darwin reads; the acceptance grep covers GREP_SUFFIXES.
GREP_SUFFIXES = (".py", ".yaml", ".toml", ".txt", ".sql", ".cfg")
EDIT_SUFFIXES = GREP_SUFFIXES + (".yml",)

_TRIPWIRE = r"TA-(?:SEC|REL|SAF|MODEL)|intentionally|vulnerab|canary|oracle"
# Phrases stripped from comments and docstrings (the acceptance terms plus seeding).
EDIT_RE = re.compile(_TRIPWIRE + r"|seeded|seeding", re.IGNORECASE)
# Acceptance grep, run on the produced tree. Anything still matching is reported.
GREP_RE = re.compile(_TRIPWIRE, re.IGNORECASE)

# Sentence boundary: terminal punctuation before whitespace/end, or a blank line.
_BOUNDARY = re.compile(r"[.!?](?=\s|$)|\n[ \t]*\n")
_CANARY_VALUE = re.compile(r"[A-Za-z0-9._-]+")


class BlindError(Exception):
    """Raised when the tree cannot be blinded safely; the script then exits 2."""


@dataclass
class Op:
    """Replace text[start:end] with ``new``; ``line`` is the source line number."""

    start: int
    end: int
    new: str
    line: int
    action: str  # "removed" or "replaced"
    before: str
    after: str | None


class Doc:
    """Source text with (1-based line, utf-8 byte column) to offset mapping."""

    def __init__(self, text: str) -> None:
        self.text = text
        self.lines = text.split("\n")
        self.starts = [0] + [m.end() for m in re.finditer("\n", text)]

    def offset(self, lineno: int, col_bytes: int) -> int:
        prefix = self.lines[lineno - 1].encode("utf-8")[:col_bytes].decode("utf-8")
        return self.starts[lineno - 1] + len(prefix)

    def line_span(self, first: int, last: int) -> tuple[int, int]:
        """Offsets covering whole lines first..last, including the final newline."""
        end = self.starts[last] if last < len(self.starts) else len(self.text)
        return self.starts[first - 1], end


def git(args: list[str]) -> bytes:
    proc = subprocess.run(
        ["git", *args], cwd=REPO_ROOT, capture_output=True, check=False
    )
    if proc.returncode != 0:
        detail = proc.stderr.decode("utf-8", "replace").strip()
        raise BlindError(f"git {' '.join(args)} failed: {detail}")
    return proc.stdout


def load_canary(commit: str) -> ModuleType:
    """Import oracle/canary.py as it exists at ``commit`` (the source tree)."""
    source = git(["show", f"{commit}:oracle/canary.py"])
    with tempfile.TemporaryDirectory(prefix="blind-canary-") as tmp:
        path = Path(tmp) / "canary.py"
        path.write_bytes(source)
        spec = importlib.util.spec_from_file_location("canary_at_ref", path)
        if spec is None or spec.loader is None:
            raise BlindError("cannot load oracle/canary.py from the ref")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    return module


def prepare_out(out: Path) -> None:
    if out.exists():
        if not out.is_dir() or any(out.iterdir()):
            raise BlindError(f"--out must not exist or must be empty: {out}")
    else:
        out.mkdir(parents=True)


def delete_answer_key(out: Path) -> list[str]:
    removed: list[str] = []
    for rel in DELETE_PATHS:
        target = out / rel
        if target.is_symlink() or target.is_file():
            target.unlink()
            removed.append(rel)
        elif target.is_dir():
            shutil.rmtree(target)
            removed.append(rel + "/")
    scripts = out / "scripts"
    if scripts.is_dir() and not any(scripts.iterdir()):
        scripts.rmdir()
    return removed


def _read_text(path: Path) -> str | None:
    data = path.read_bytes()
    if b"\0" in data:
        return None  # binary; grep -I skips these too
    text = data.decode("utf-8")
    if "\r" in text:
        raise BlindError(f"{path}: CRLF line endings are not supported")
    return text


def apply_ops(text: str, ops: list[Op]) -> str:
    ordered = sorted(ops, key=lambda op: op.start)
    pieces: list[str] = []
    pos = 0
    for op in ordered:
        if op.start < pos:
            raise BlindError(f"overlapping edits at source line {op.line}")
        pieces.append(text[pos : op.start])
        pieces.append(op.new)
        pos = op.end
    pieces.append(text[pos:])
    return "".join(pieces)


def _runs(numbers: list[int]) -> list[tuple[int, int]]:
    """Group sorted ints into (first, last) inclusive runs."""
    runs: list[tuple[int, int]] = []
    for n in numbers:
        if runs and n == runs[-1][1] + 1:
            runs[-1] = (runs[-1][0], n)
        else:
            runs.append((n, n))
    return runs


def _remove_lines(doc: Doc, first: int, last: int) -> Op:
    start, end = doc.line_span(first, last)
    before = "\n".join(doc.lines[first - 1 : last])
    return Op(start, end, "", first, "removed", before, None)


def _block_ops(
    doc: Doc, comment_rows: set[int], matched: set[int]
) -> list[Op]:
    """Delete each contiguous run of comment-only lines that holds a match."""
    doomed: set[int] = set()
    for row in matched:
        lo = hi = row
        while lo - 1 in comment_rows:
            lo -= 1
        while hi + 1 in comment_rows:
            hi += 1
        doomed.update(range(lo, hi + 1))
    ops: list[Op] = []
    for lo, hi in _runs(sorted(doomed)):
        start, end = doc.line_span(lo, hi)
        before = "\n".join(doc.lines[lo - 1 : hi])
        ops.append(Op(start, end, "", lo, "removed", before, None))
    return ops


def _remove_sentences(body: str) -> str | None:
    """Drop each sentence containing a tripwire term; None if nothing matched."""
    spans: list[tuple[int, int]] = []
    for match in EDIT_RE.finditer(body):
        start = 0
        for boundary in _BOUNDARY.finditer(body, 0, match.start()):
            start = boundary.end()
        while start < match.start() and body[start] in " \t\n":
            start += 1
        following = _BOUNDARY.search(body, match.end())
        if following is None:
            end = len(body)
        elif body[following.start()] == "\n":
            end = following.start()  # stop before the paragraph break
        else:
            end = following.end()
        while end < len(body) and body[end] in " \t":
            end += 1
        spans.append((start, end))
    if not spans:
        return None
    merged: list[tuple[int, int]] = []
    for start, end in sorted(spans):
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(end, merged[-1][1]))
        else:
            merged.append((start, end))
    result = body
    for start, end in reversed(merged):
        result = result[:start] + result[end:]
    if "\n" not in result:
        return result.rstrip(" \t")
    # Trim trailing blanks on each line but keep the closing-quote indentation.
    result = re.sub(r"[ \t]+(?=\n)", "", result)
    return re.sub(r"\n{3,}", "\n\n", result)


def _docstring_ops(rel: str, text: str, tree: ast.Module, doc: Doc) -> list[Op]:
    ops: list[Op] = []
    for owner in ast.walk(tree):
        if not isinstance(
            owner, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)
        ) or not owner.body:
            continue
        first = owner.body[0]
        if not (
            isinstance(first, ast.Expr)
            and isinstance(first.value, ast.Constant)
            and isinstance(first.value.value, str)
            and EDIT_RE.search(first.value.value)
        ):
            continue
        # Decorated objects (strands @tool, FastAPI routes) and pydantic models
        # hand their docstrings to the runtime; those stay and are reported.
        if getattr(owner, "decorator_list", None) or (
            isinstance(owner, ast.ClassDef) and owner.bases
        ):
            continue
        literal = ast.get_source_segment(text, first.value) or ""
        quote = literal[:3]
        if (
            quote not in ('"""', "'''")
            or len(literal) < 6
            or not literal.endswith(quote)
            or "\\" in literal
        ):
            continue
        new_body = _remove_sentences(literal[3:-3])
        if new_body is None:
            continue
        if new_body.strip() == "":
            if len(owner.body) == 1:
                raise BlindError(f"{rel}:{first.lineno}: docstring is the whole body")
            op = _remove_lines(doc, first.lineno, first.end_lineno or first.lineno)
            ops.append(op)
            continue
        start = doc.offset(first.value.lineno, first.value.col_offset)
        end = doc.offset(first.value.end_lineno or first.lineno, first.value.end_col_offset or 0)
        new = quote + new_body + quote
        ops.append(Op(start, end, new, first.lineno, "replaced", literal, new))
    return ops


def _resolve(node: ast.expr, consts: dict[str, str], rel: str) -> Any:
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.Name) and node.id in consts:
        return consts[node.id]
    raise BlindError(f"{rel}:{node.lineno}: cannot evaluate canary argument")


def _is_token_call(call: ast.Call, token_names: set[str], module_names: set[str]) -> bool:
    func = call.func
    if isinstance(func, ast.Name):
        return func.id in token_names
    if isinstance(func, ast.Attribute) and func.attr == "token":
        base = func.value
        if isinstance(base, ast.Name) and base.id in module_names:
            return True
        if (
            isinstance(base, ast.Attribute)
            and base.attr == "canary"
            and isinstance(base.value, ast.Name)
            and base.value.id == "oracle"
        ):
            return True
    return False


def _oracle_residue(tree: ast.Module, names: set[str]) -> list[str]:
    found: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            if node.module.split(".")[0] == "oracle":
                found.append(f"import from {node.module}")
        elif isinstance(node, ast.Import):
            if any(a.name.split(".")[0] == "oracle" for a in node.names):
                found.append("import oracle")
        elif isinstance(node, ast.Name) and node.id == "oracle":
            found.append("name oracle")
        elif (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in names
        ):
            found.append(f"call to {node.func.id}")
    return found


def blind_python(
    rel: str, text: str, canary: ModuleType
) -> tuple[str, list[Op], list[dict[str, Any]]]:
    tree = ast.parse(text, filename=rel)
    doc = Doc(text)
    ops: list[Op] = []
    token_names: set[str] = set()
    module_names: set[str] = set()
    oracle_imports: list[ast.stmt] = []

    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            if node.module.split(".")[0] != "oracle":
                continue
            oracle_imports.append(node)
            for alias in node.names:
                bound = alias.asname or alias.name
                if (node.module == "oracle.canary" and alias.name == "token") or (
                    node.module == "oracle" and alias.name == "canary_token"
                ):
                    token_names.add(bound)
                elif node.module == "oracle" and alias.name == "canary":
                    module_names.add(bound)
                else:
                    raise BlindError(
                        f"{rel}:{node.lineno}: unhandled import {node.module}.{alias.name}"
                    )
        elif isinstance(node, ast.Import):
            if not any(a.name.split(".")[0] == "oracle" for a in node.names):
                continue
            oracle_imports.append(node)
            for alias in node.names:
                if alias.name != "oracle.canary":
                    raise BlindError(f"{rel}:{node.lineno}: unhandled import {alias.name}")
                if alias.asname:
                    module_names.add(alias.asname)

    for node in oracle_imports:
        prefix = doc.lines[node.lineno - 1][: node.col_offset]
        if prefix.strip():
            raise BlindError(f"{rel}:{node.lineno}: oracle import shares its line")
        ops.append(_remove_lines(doc, node.lineno, node.end_lineno or node.lineno))

    consts: dict[str, str] = {}
    for stmt in tree.body:
        if (
            isinstance(stmt, ast.Assign)
            and len(stmt.targets) == 1
            and isinstance(stmt.targets[0], ast.Name)
            and isinstance(stmt.value, ast.Constant)
            and isinstance(stmt.value.value, str)
        ):
            consts[stmt.targets[0].id] = stmt.value.value

    canary_records: list[dict[str, Any]] = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and _is_token_call(node, token_names, module_names)):
            continue
        if node.lineno != node.end_lineno:
            raise BlindError(f"{rel}:{node.lineno}: multi-line canary call")
        args = [_resolve(a, consts, rel) for a in node.args]
        kwargs: dict[str, Any] = {}
        for kw in node.keywords:
            if kw.arg is None:
                raise BlindError(f"{rel}:{node.lineno}: ** in canary call")
            kwargs[kw.arg] = _resolve(kw.value, consts, rel)
        bound = inspect.signature(canary.token).bind(*args, **kwargs)
        bound.apply_defaults()
        value = canary.token(*args, **kwargs)
        if not _CANARY_VALUE.fullmatch(value):
            raise BlindError(f"{rel}:{node.lineno}: canary value needs quoting: {value!r}")
        literal = f'"{value}"'
        line = doc.lines[node.lineno - 1]
        raw = line.encode("utf-8")
        after = (raw[: node.col_offset] + literal.encode() + raw[node.end_col_offset :]).decode()
        start = doc.offset(node.lineno, node.col_offset)
        end = doc.offset(node.end_lineno or node.lineno, node.end_col_offset or 0)
        ops.append(Op(start, end, literal, node.lineno, "replaced", line, after))
        canary_records.append(
            {
                "file": rel,
                "line": node.lineno,
                "call": ast.get_source_segment(text, node),
                "namespace": bound.arguments["namespace"],
                "vuln_id": bound.arguments["vuln_id"],
                "slot": bound.arguments["slot"],
                "value": value,
            }
        )

    comment_rows: set[int] = set()
    matched: set[int] = set()
    trailing: dict[int, int] = {}
    for tok in tokenize.generate_tokens(io.StringIO(text).readline):
        if tok.type != tokenize.COMMENT:
            continue
        row, col = tok.start
        hit = EDIT_RE.search(tok.string) is not None
        if doc.lines[row - 1][:col].strip() == "":
            comment_rows.add(row)
            if hit:
                matched.add(row)
        elif hit:
            trailing[row] = col
    ops.extend(_block_ops(doc, comment_rows, matched))
    for row, col in trailing.items():
        line = doc.lines[row - 1]
        code = line[:col].rstrip()
        start = doc.starts[row - 1] + len(code)
        end = doc.starts[row - 1] + len(line)
        ops.append(Op(start, end, "", row, "replaced", line, code))

    ops.extend(_docstring_ops(rel, text, tree, doc))

    new_text = apply_ops(text, ops)
    residue = _oracle_residue(ast.parse(new_text, filename=rel), token_names | module_names)
    if residue:
        raise BlindError(f"{rel}: oracle references survive the edit: {residue}")
    return new_text, ops, canary_records


def blind_text(rel: str, text: str) -> tuple[str, list[Op]]:
    """Strip full-line comments that name a weakness from non-Python text files."""
    doc = Doc(text)
    prefix = "--" if rel.endswith(".sql") else "#"
    comment_rows = {
        n for n, line in enumerate(doc.lines, 1) if line.lstrip().startswith(prefix)
    }
    matched = {n for n in comment_rows if EDIT_RE.search(doc.lines[n - 1])}
    ops = _block_ops(doc, comment_rows, matched)
    return apply_ops(text, ops), ops


def _review_reason(line: str) -> str:
    if "VIJIL-CANARY" in line:
        return (
            "canary literal from oracle.canary.token, kept byte-identical so the "
            "oracle still matches; the literal itself contains the canary prefix "
            "and the vulnerability id"
        )
    if line.lstrip().startswith("#"):
        return "comment not removed (unexpected)"
    return (
        "program-used string or identifier that names a weakness; not edited "
        "(outside the card's edit scope), needs human review"
    )


def scan(out: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    review: list[dict[str, Any]] = []
    outside: list[dict[str, Any]] = []
    for path in sorted(out.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        text = _read_text(path)
        if text is None:
            continue
        rel = path.relative_to(out).as_posix()
        in_scope = path.suffix in GREP_SUFFIXES
        for number, line in enumerate(text.split("\n"), 1):
            if not GREP_RE.search(line):
                continue
            entry: dict[str, Any] = {"file": rel, "line": number, "text": line.strip()}
            if in_scope:
                entry["reason"] = _review_reason(line)
                review.append(entry)
            else:
                outside.append(entry)
    return review, outside


def build(ref: str, out: Path) -> dict[str, Any]:
    commit = git(["rev-parse", "--verify", f"{ref}^{{commit}}"]).decode().strip()
    prepare_out(out)
    archive = git(["archive", "--format=tar", commit])
    with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
        tar.extractall(out, filter="data")
    removed = delete_answer_key(out)
    canary = load_canary(commit)

    edited: list[dict[str, Any]] = []
    canary_records: list[dict[str, Any]] = []
    for path in sorted(out.rglob("*")):
        if not path.is_file() or path.is_symlink() or path.suffix not in EDIT_SUFFIXES:
            continue
        text = _read_text(path)
        if text is None:
            continue
        rel = path.relative_to(out).as_posix()
        if path.suffix == ".py":
            new_text, ops, records = blind_python(rel, text, canary)
            canary_records.extend(records)
        else:
            new_text, ops = blind_text(rel, text)
        if ops:
            edits = sorted(ops, key=lambda op: op.line)
            edited.append(
                {
                    "file": rel,
                    "edits": [
                        {
                            "source_line": op.line,
                            "action": op.action,
                            "before": op.before,
                            "after": op.after,
                        }
                        for op in edits
                    ],
                }
            )
        if new_text != text:
            path.write_bytes(new_text.encode("utf-8"))

    review, outside = scan(out)
    return {
        "ref": ref,
        "commit": commit,
        "out": str(out),
        "removed_paths": removed,
        "canary_replacements": canary_records,
        "edited_files": edited,
        "needs_review": review,
        "outside_grep_scope_hits": outside,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--ref", required=True, help="git ref to export (e.g. HEAD)")
    parser.add_argument("--out", required=True, help="output directory (must be empty)")
    args = parser.parse_args(argv)
    try:
        manifest = build(args.ref, Path(args.out).resolve())
    except BlindError as exc:
        print(f"make_blind_base: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(manifest, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
