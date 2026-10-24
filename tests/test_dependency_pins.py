"""Dependency pins keep a fresh install on the a2a-sdk API that agent.py targets.

a2a-sdk 1.x restructures a2a.types and a2a.server, so an unbounded resolution
breaks the import of agent.py. The declared constraints are asserted in both
dependency files (the Dockerfile installs requirements.txt; pyproject.toml is the
package metadata), and the installed version is asserted against the same bound.
"""

import tomllib
from importlib.metadata import version
from pathlib import Path

from packaging.requirements import Requirement

ROOT = Path(__file__).resolve().parent.parent

# A release from the 1.x line that broke the import, and the floor we support.
A2A_SDK_1X_VERSION = "1.2.3"
A2A_SDK_FLOOR_VERSION = "0.3.24"


def _requirements_txt() -> dict[str, Requirement]:
    lines = (ROOT / "requirements.txt").read_text().splitlines()
    reqs = [Requirement(line) for line in lines if line.strip() and not line.startswith("#")]
    return {r.name: r for r in reqs}


def _pyproject_dependencies() -> dict[str, Requirement]:
    data = tomllib.loads((ROOT / "pyproject.toml").read_text())
    reqs = [Requirement(dep) for dep in data["project"]["dependencies"]]
    return {r.name: r for r in reqs}


def test_requirements_txt_bounds_a2a_sdk_below_1x():
    req = _requirements_txt().get("a2a-sdk")
    assert req is not None, "requirements.txt does not constrain a2a-sdk"
    assert not req.specifier.contains(A2A_SDK_1X_VERSION)
    assert req.specifier.contains(A2A_SDK_FLOOR_VERSION)


def test_pyproject_bounds_a2a_sdk_below_1x():
    req = _pyproject_dependencies().get("a2a-sdk")
    assert req is not None, "pyproject.toml does not constrain a2a-sdk"
    assert not req.specifier.contains(A2A_SDK_1X_VERSION)
    assert req.specifier.contains(A2A_SDK_FLOOR_VERSION)


def test_vijil_dome_constraint_is_the_same_in_both_files():
    from_requirements = _requirements_txt()["vijil-dome"]
    from_pyproject = _pyproject_dependencies()["vijil-dome"]
    assert str(from_requirements.specifier) == str(from_pyproject.specifier)


def test_installed_a2a_sdk_is_pre_1x_and_exposes_datapart():
    assert int(version("a2a-sdk").split(".")[0]) < 1

    from a2a.types import DataPart

    assert DataPart.__name__ == "DataPart"


def _dockerfile_install_lines() -> list[str]:
    """Return the Dockerfile text with line continuations joined and comments dropped."""
    joined = (ROOT / "Dockerfile").read_text().replace("\\\n", " ")
    return [ln.strip() for ln in joined.splitlines() if ln.strip() and not ln.strip().startswith("#")]


def test_vijil_dome_is_pinned_exactly():
    req = _requirements_txt()["vijil-dome"]
    specs = list(req.specifier)
    assert len(specs) == 1 and specs[0].operator == "==", f"vijil-dome must be an exact pin, got {req.specifier}"


def test_dockerfile_does_not_install_a_vendored_dome_wheel():
    """A wheel installed after requirements.txt silently replaces the pinned vijil-dome."""
    offending = [ln for ln in _dockerfile_install_lines() if ".whl" in ln or "vijil_dome-" in ln]
    assert offending == [], f"Dockerfile overrides the vijil-dome pin: {offending}"


def test_dockerfile_installs_requirements_txt_last_for_vijil_dome():
    """Nothing after the requirements install may pip-install vijil-dome again."""
    lines = _dockerfile_install_lines()
    first = next(i for i, ln in enumerate(lines) if "pip install" in ln and "-r requirements.txt" in ln)
    later = [ln for ln in lines[first + 1 :] if "pip install" in ln and "vijil" in ln.lower()]
    assert later == [], f"vijil package installed after requirements.txt: {later}"


def test_no_vendored_dome_wheel_in_repo_root():
    assert list(ROOT.glob("vijil_dome-*.whl")) == []


def test_instrument_dome_runtime_dependencies_are_declared():
    """The deleted wheel step also installed these; instrument_dome imports them."""
    names = set(_requirements_txt())
    for pkg in (
        "opentelemetry-instrumentation-asyncio",
        "opentelemetry-instrumentation-threading",
        "opentelemetry-instrumentation-logging",
    ):
        assert pkg in names, f"{pkg} missing from requirements.txt"


def test_installed_vijil_dome_satisfies_the_pin():
    req = _requirements_txt()["vijil-dome"]
    assert req.specifier.contains(version("vijil-dome"))
