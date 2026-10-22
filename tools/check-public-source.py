"""Check source-only publication exclusions and required first-party notices.

This is a path/metadata gate, not a privacy or copyright certification.
"""
import subprocess
import ast
import hashlib
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FORBIDDEN = {"version-share-handoff.json",
             "docs/station-access/PUBLIC-SOURCE-MIGRATION.md"}
DISALLOWED_PARTS = {".version-share", "node_modules", "__pycache__", ".venv", "dist"}
REQUIRED = {"LICENSE", "COPYRIGHT", "LICENSES/BSD-3-Clause.txt",
            "LICENSES/GPL-3.0-only.txt", "public-companion-pins.json"}
GRANT = "BSD-3-Clause OR GPL-3.0-only"


# SR-06: exact legacy artifacts remain available for review, never selectable.
# These hashes bind the original historic bytes; changing their source requires
# an explicit new controller/root-owner disposition.
QUARANTINED_SR06 = {
    'docs/station-access/legacy/noninstallable/vnc-application.py.txt': 'd4e4020fee5529ed1501b90361a6c21c3381b0b5',
    'docs/station-access/legacy/noninstallable/station-deployment-jobs.service.txt': '2c2f33d25c6490646565ddf137451f569dc12880',
    'docs/station-access/legacy/noninstallable/station-deployment-jobs.timer.txt': '918da82c1994147be03a91b8448d7079c1d68c7c',
    'docs/station-access/legacy/noninstallable/host-dns-reconcile.service.txt': '538786c11c8022f5bad05e54a5632e210d32c250',
    'docs/station-access/legacy/noninstallable/host-dns-reconcile.timer.txt': '825ad22209089af01771eb751cf69dc257a4ad5f'
}
LEGACY_INSTALL_GUIDE = "docs/station-access/DEPLOYMENT-JOBS.md"
WEB_COMPOSITION = "integration/production/station-access/application.py"

def _blob_sha(data):
    return hashlib.sha1(b"blob " + str(len(data)).encode() + bytes([0]) + data).hexdigest()


def _application_call(text):
    tree = ast.parse(text)
    calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)
             and isinstance(node.func, ast.Name) and node.func.id == "application"]
    if len(calls) != 1:
        return None, tree
    return {arg.arg: arg.value for arg in calls[0].keywords}, tree


def _literal(node):
    try:
        return ast.literal_eval(node)
    except (TypeError, ValueError, SyntaxError):
        return None


def _check_production_template(text):
    """The only deployable station application uses a protected singleton grant."""
    try:
        application, tree = _application_call(text)
    except SyntaxError:
        return False
    if application is None or any(
        _literal(application.get(name)) != value for name, value in (
            ("persistent", True), ("multiple_instances", False),
            ("execution_identity", "application"))
    ):
        return False
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "program":
            if any(kw.arg in ("user", "group") for kw in node.keywords):
                return False
    return True


def _check_legacy_vnc(text):
    """Multi-instance desktop examples may not acquire singleton grants."""
    try:
        application, tree = _application_call(text)
    except SyntaxError:
        return False
    if (application is None or
            _literal(application.get("multiple_instances")) is not True or
            _literal(application.get("persistent")) is True or
            "execution_identity" in application):
        return False
    # The historic named-user fixture remains a non-installable historical fact.
    return any(
        isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        and node.func.id == "program"
        and any(kw.arg == "user" and _literal(kw.value) == "regular"
                for kw in node.keywords)
        for node in ast.walk(tree)
    )



def _check_wheel_source_scope(text):
    """Never install the quarantined docs as package data or host units."""
    try:
        project = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return False
    setuptools = project.get("tool", {}).get("setuptools", {})
    packages = setuptools.get("packages", {})
    discovery = packages.get("find", {}) if isinstance(packages, dict) else {}
    if (setuptools.get("package-dir") != {"": "src"}
            or discovery.get("where") != ["src"]
            or discovery.get("include") != ["zog.station_access*"]
            or "data-files" in setuptools):
        return False
    package_data = setuptools.get("package-data", {})
    return all(
        name.startswith("zog.station_access")
        and all("legacy" not in item and "deployment/" not in item and
                "integration/" not in item for item in patterns)
        for name, patterns in package_data.items()
    )


def inspect_sr06(paths):
    problems = []
    candidates = set(paths)
    for path in sorted(candidates):
        name = Path(path)
        if ((path == "integration/application.py") or
            name.suffix in (".service", ".timer") or
            (name.name == "application.py" and name.parts[0] == "integration"
             and path != WEB_COMPOSITION)):
            problems.append((path, "sr06-unsafe-deployable-legacy-identity"))
    for path, expected in QUARANTINED_SR06.items():
        if path not in candidates:
            problems.append((path, "sr06-quarantine-missing"))
            continue
        file = ROOT / path
        if not file.is_file() or file.is_symlink() or _blob_sha(file.read_bytes()) != expected:
            problems.append((path, "sr06-quarantine-provenance-mismatch"))
    if WEB_COMPOSITION not in candidates or not _check_production_template(
            (ROOT / WEB_COMPOSITION).read_text() if (ROOT / WEB_COMPOSITION).is_file() else ""):
        problems.append((WEB_COMPOSITION, "sr06-protected-production-identity-required"))
    vnc = "docs/station-access/legacy/noninstallable/vnc-application.py.txt"
    if vnc in candidates and (ROOT / vnc).is_file() and not _check_legacy_vnc((ROOT / vnc).read_text()):
        problems.append((vnc, "sr06-legacy-vnc-contract-changed"))
    guide = ROOT / LEGACY_INSTALL_GUIDE
    if (LEGACY_INSTALL_GUIDE not in candidates or not guide.is_file() or
            "Install the example service/timer" in guide.read_text() or
            "Enable/start the timer" in guide.read_text()):
        problems.append((LEGACY_INSTALL_GUIDE, "sr06-legacy-worker-install-guide"))
    packaging = "pyproject.toml"
    if (packaging not in candidates or not (ROOT / packaging).is_file() or
            not _check_wheel_source_scope((ROOT / packaging).read_text())):
        problems.append((packaging, "sr06-wheel-packaging-scope-unsafe"))
    index = "docs/station-access/legacy/noninstallable/README.md"
    if index not in candidates or not (ROOT / index).is_file() or "NOT INSTALLABLE" not in (ROOT / index).read_text():
        problems.append((index, "sr06-quarantine-disposition-missing"))
    return problems


def inspect(paths):
    problems = []
    for filename in paths:
        name = Path(filename)
        if (name.is_absolute() or ".." in name.parts or filename in FORBIDDEN
                or any(part in DISALLOWED_PARTS for part in name.parts)):
            problems.append((filename, "excluded-path"))
            continue
        file = ROOT / name
        if file.is_symlink() or not file.is_file():
            problems.append((filename, "unsafe-source-file"))
    problems.extend(inspect_sr06(paths))
    for name in sorted(REQUIRED.difference(paths)):
        problems.append((name, "required-license-or-manifest-missing"))
    for name in ("LICENSE", "COPYRIGHT"):
        if name in paths and GRANT not in (ROOT / name).read_text():
            problems.append((name, "first-party-license-inconsistent"))
    return problems


def main():
    result = subprocess.run(["git", "-C", str(ROOT), "ls-files", "-z"],
                            capture_output=True, check=True)
    names = [x.decode("utf-8") for x in result.stdout.split(b"\0") if x]
    problems = inspect(names)
    for path, reason in problems:
        print(f"PUBLIC-SOURCE-HOLD: {path}: {reason}")
    print(f"Checked {len(names)} tracked paths; legal and privacy review is separate.")
    if problems:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
