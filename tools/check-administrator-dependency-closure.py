#!/usr/bin/env python3
"""Fail-closed exact installed dependency check for administrator FD source tests.

The historical host-discover 0.4.13 -> host-install 0.14.3 dependency
conflicted with the selected administrator FD installer 0.14.9. There is
NO allowance for this or any other pip-check mismatch. This check runs
against actual installed distribution metadata, not a simulated resolver.
Native authority/release rights are separate from source dependency closure.
"""

import importlib.metadata as metadata
import subprocess
import sys
from pathlib import Path

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name


EXPECTED = {
    "host-identify": "0.3.5",
    "host-discover": "0.4.14",
    "host-install": "0.14.9",
}
DISCOVER_REQUIRES = {
    "host-identify": "==0.3.5",
    "host-install": "==0.14.9",
}
OLD_INSTALL = "0.14.3"
OLD_DISCOVER = "0.4.13"
ACCEPTED_BASELINE_BLOB = "db53b4f56aa26581673dbacb3f4d8ee545a673da"


def pinned_requirements():
    """Return exact requirements from the *installed* 0.4.14 wheel metadata."""
    distribution = metadata.distribution("host-discover")
    requirements = {}
    for value in distribution.requires or ():
        requirement = Requirement(value)
        key = canonicalize_name(requirement.name)
        if key in DISCOVER_REQUIRES:
            if key in requirements:
                raise RuntimeError(f"Duplicate selected dependency requirement: {key}")
            requirements[key] = requirement
    if set(requirements) != set(DISCOVER_REQUIRES):
        raise RuntimeError(f"Missing installer/identity dependency: {set(DISCOVER_REQUIRES) - set(requirements)}")
    for name, exact in DISCOVER_REQUIRES.items():
        requirement = requirements[name]
        if str(requirement.specifier) != exact or requirement.marker is not None:
            raise RuntimeError(f"Nonexact or conditional {name} dependency: {requirement}")
    return requirements


def assert_accepted(name, version, requirements):
    dependency = requirements[name]
    if not dependency.specifier.contains(version, prereleases=True):
        raise RuntimeError(f"{name} {version} does not satisfy host-discover 0.4.14: {dependency}")


def check():
    actual = {name: metadata.version(name) for name in EXPECTED}
    if actual != EXPECTED:
        raise RuntimeError(f"Administrator FD source dependency version mismatch: {actual!r}")
    requirements = pinned_requirements()
    for name in DISCOVER_REQUIRES:
        assert_accepted(name, actual[name], requirements)

    # The historical 0.14.3 installer must NOT be admitted to the 0.4.14
    # candidate, even if a test runner installs all editable wheels --no-deps.
    try:
        assert_accepted("host-install", OLD_INSTALL, requirements)
    except RuntimeError as exc:
        if "does not satisfy" not in str(exc):
            raise
    else:
        raise RuntimeError("Regression: 0.14.3 installer incorrectly accepted")

    # Conversely the historical 0.4.13 metadata required the old 0.14.3
    # version, which is incompatible with the *current* installer 0.14.9.
    historical = Requirement("host-install==" + OLD_INSTALL)
    if historical.specifier.contains(actual["host-install"]):
        raise RuntimeError("Regression: old host-discover 0.4.13 requirement accepted")

    pins = Path("public-companion-pins.json")
    if not pins.is_file():
        raise RuntimeError("Accepted production pin manifest is missing")
    blob = subprocess.run(["git", "hash-object", str(pins)], capture_output=True,
                          text=True, check=True).stdout.strip()
    if blob != ACCEPTED_BASELINE_BLOB:
        raise RuntimeError("Accepted production pins changed")

    # NO || true, grep whitelist, tolerated status, or dependency exception.
    # Run against the same Python used by the actual Django receiver tests.
    process = subprocess.run([sys.executable, "-m", "pip", "check"],
                             text=True, capture_output=True)
    if process.returncode:
        raise RuntimeError("Unconditional pip check FAILED:\n" +
                           process.stdout + process.stderr)
    print(process.stdout.strip())
    print("PASS: actual installed host-discover 0.4.14, host-install 0.14.9, "
          "host-identify 0.3.5; old 0.14.3 mismatch denied; "
          "production pins unchanged; no pip-check exception")


if __name__ == "__main__":
    check()
