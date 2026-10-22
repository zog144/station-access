"""Read-only, administrator-scoped application-software inspection.

Use image-build's public strict readers, not its store constructors, which can
initialize directories. No raw host paths or opaque provenance dictionaries
may cross this projection.
"""
from __future__ import annotations

import itertools
import os
import re
from pathlib import Path
from urllib.parse import urlsplit

from zog.image_build.application_software import read_artifact
from zog.image_build.application_views import read_view

_ID = re.compile(r"sha256:[0-9a-f]{64}$")
_MAX_VIEWS = 32
_MAX_ARTIFACTS = 128


def _valid_id(value):
    return isinstance(value, str) and bool(_ID.fullmatch(value))


class _ArtifactReader:
    def __init__(self, root):
        self.root = root

    def resolve(self, identity):
        if not _valid_id(identity):
            raise ValueError("invalid artifact identity")
        return read_artifact(self.root / "artifacts" / identity[7:])


def _published_views(directory):
    if directory.is_symlink() or not directory.is_dir():
        return (), False
    # Never walk an unbounded directory or follow a symlink.
    with os.scandir(directory) as iterator:
        names = [
            item.name for item in itertools.islice(iterator, _MAX_VIEWS + 1)
            if item.is_dir(follow_symlinks=False)
        ]
    return tuple(sorted(names[:_MAX_VIEWS])), len(names) > _MAX_VIEWS


def _sources(manifest):
    # Source identities are verified by image-build. Do not echo local file or
    # recipe URLs, source query strings, or arbitrary provenance metadata.
    links = []
    for value in manifest["sources"][:20]:
        url = value["url"]
        parsed = urlsplit(url)
        if (parsed.scheme == "https" and parsed.hostname and
                parsed.username is None and parsed.password is None and
                not parsed.query and not parsed.fragment):
            links.append({
                "name": value.get("name"),
                "url": url,
                "sha256": value["sha256"],
            })
    return {
        "source_count": len(manifest["sources"]),
        "https_sources": links,
        "notice_count": len(manifest["notices"]),
        "license_state": "notice-files-recorded" if manifest["notices"] else "unavailable",
        "provenance_state": "recorded" if manifest["provenance"] else "unavailable",
    }


def inspect(control, discover):
    """Bounded manifest evidence plus advisory preflight; no mount probes/writes."""
    specs = discover(control.project.application_dir)
    selected = {spec.software_view: spec.name for spec in specs.values()
                if spec.software_view}
    root = control.project.state_dir / "image-build" / "application-software"
    safe = (
        root.is_dir() and not root.is_symlink() and
        (root / "views").is_dir() and not (root / "views").is_symlink() and
        (root / "artifacts").is_dir() and not (root / "artifacts").is_symlink()
    )
    names, truncated = _published_views(root / "views") if safe else ((), False)
    identities = {"sha256:" + name for name in names if re.fullmatch(r"[0-9a-f]{64}", name)}
    identities.update(selected)
    reader = _ArtifactReader(root)
    views = []
    artifacts = {}
    overflow = False
    for identity in sorted(identities):
        intended = selected.get(identity)
        row = {
            "view": identity if _valid_id(identity) else None,
            "application": intended,
            "selected": intended is not None,
            "state": "unavailable",
            "profile": None,
            "artifacts": [],
            "composition_count": None,
            "runtime_count": 0,
            "launch_readiness": "not-verified",
            "mount_observation": "not-probed",
        }
        if safe and _valid_id(identity):
            try:
                view = read_view(reader, root / "views" / identity[7:])
                if intended is not None and view.manifest["application"] != intended:
                    raise ValueError("view/application identity disagreement")
                row.update(
                    application=view.manifest["application"],
                    state="verified",
                    profile=view.manifest["profile"],
                    artifacts=list(view.manifest["artifacts"]),
                    composition_count=len(view.manifest["composition"]),
                )
                for artifact_id in view.manifest["artifacts"]:
                    if artifact_id in artifacts:
                        continue
                    if len(artifacts) >= _MAX_ARTIFACTS:
                        overflow = True
                        continue
                    artifact = reader.resolve(artifact_id)
                    artifacts[artifact_id] = {
                        "artifact": artifact_id,
                        "application": artifact.manifest["application"],
                        "revision": artifact.manifest["revision"],
                        "architecture": artifact.manifest["architecture"],
                        **_sources(artifact.manifest),
                    }
            except Exception:
                # Invalid publication is *not* verified; exception details may
                # include host paths. Never expose them in the browser.
                row.update(state="unavailable", artifacts=[], composition_count=None)
        views.append(row)

    try:
        references = tuple(control.application_runtimes().values())
    except Exception:
        references = ()
    for row in views:
        if row["view"]:
            row["runtime_count"] = sum(
                getattr(runtime, "software_view", None) == row["view"]
                for runtime in references
            )
        if row["selected"] and row["state"] == "verified":
            # Controller's advisory read-only preflight; never mistake this for
            # an observation of running mounts or a launch authorization.
            try:
                result = control.preflight_application_launch(row["application"])
                if result.get("status") in ("ready-to-attempt", "blocked", "unable-to-verify"):
                    row["launch_readiness"] = result["status"]
            except Exception:
                pass
    return {
        "schema": 1,
        "basis": "verified-publication-and-expected-launched",
        "store": "available" if safe else "unavailable",
        "views_truncated": truncated,
        "artifacts_truncated": overflow,
        "views": views,
        "artifacts": sorted(artifacts.values(), key=lambda value: value["artifact"]),
        "mount_observation": "not-probed",
        "read_only": True,
    }

def inspect_application(control, discover, application_name):
    """Inspect one configured application and its exact selected immutable view.

    Unselected/invalid historical publications are not silently substituted.
    Does not call producer constructors or mutate the selected software.
    """
    if not isinstance(application_name, str) or not re.fullmatch(r"[A-Za-z0-9-]{1,128}", application_name):
        return None
    applications = discover(control.project.application_dir)
    spec = applications.get(application_name)
    if spec is None:
        return None
    identity = spec.software_view
    result = {
        "schema": 1,
        "application": application_name,
        "selection_basis": "current-application-specification",
        "view": identity if _valid_id(identity) else None,
        "state": "not-selected" if identity is None else "unavailable",
        "profile": None,
        "view_contract": None,
        "composition_count": None,
        "artifacts": [],
        "launch_readiness": "not-verified",
        "mount_observation": "not-probed",
        "read_only": True,
    }
    if not _valid_id(identity):
        return result
    root = control.project.state_dir / "image-build" / "application-software"
    if (root.is_symlink() or not root.is_dir() or
            (root / "artifacts").is_symlink() or not (root / "artifacts").is_dir() or
            (root / "views").is_symlink() or not (root / "views").is_dir()):
        return result
    reader = _ArtifactReader(root)
    try:
        view = read_view(reader, root / "views" / identity[7:])
        manifest = view.manifest
        if manifest["application"] != application_name:
            raise ValueError("selected view belongs to another application")
        artifacts = []
        for artifact_id in manifest["artifacts"]:
            artifact = reader.resolve(artifact_id)
            package = artifact.manifest
            if package["application"] != application_name:
                raise ValueError("artifact belongs to another application")
            artifacts.append({
                "artifact": artifact_id,
                "revision": package["revision"],
                "architecture": package["architecture"],
                "compatibility": {
                    "schema": package["compatibility"]["schema"],
                    "mount_contract": package["compatibility"]["mount_contract"],
                    "architecture": package["compatibility"]["architecture"],
                    "python": package["compatibility"]["python"],
                    "libraries": list(package["compatibility"]["libraries"]),
                },
                **_sources(package),
                # Only relative paths from a validated immutable artifact.
                "notice_files": list(package["notices"]),
            })
        result.update(
            state="verified",
            profile=manifest["profile"],
            view_contract=manifest["contract"],
            composition_count=len(manifest["composition"]),
            artifacts=artifacts,
        )
    except Exception:
        # Fail closed. Do not leak private manifest paths or partially verified
        # artifact data if even one referenced immutable object is unavailable.
        return result

    try:
        preflight = control.preflight_application_launch(application_name)
        if preflight.get("status") in {"ready-to-attempt", "blocked", "unable-to-verify"}:
            result["launch_readiness"] = preflight["status"]
    except Exception:
        pass
    return result
