"""Offline binding of exact image-build software views into two application specs.

No host paths, controller project mutation, application preparation or launches.
The output may be copied into a *new* intended project by its owning operator.
"""
import argparse
import json
import os
import re
import tempfile
from pathlib import Path
from urllib.parse import urlsplit

VIEW = re.compile(r"sha256:[0-9a-f]{64}\Z")
SCHEMA = "zog-station-production-composition-v1"
DNS_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")


def _public_origin(value):
    """Explicit, canonical HTTPS origin supplied by the deployment owner."""
    if (type(value) is not str or len(value) > 253
            or not value.startswith("https://") or value != value.strip()
            or any(c in value for c in ("\\", "\n", "\r", "\t"))):
        raise ValueError("explicit canonical HTTPS origin required")
    try:
        url = urlsplit(value)
        port = url.port
    except ValueError:
        raise ValueError("invalid HTTPS origin") from None
    host = url.hostname
    if (url.scheme != "https" or not host or url.username is not None
            or url.password is not None or url.path or url.query or url.fragment
            or url.netloc.endswith(":") or url.netloc != url.netloc.lower()
            or not all(DNS_LABEL.fullmatch(label) for label in host.split("."))
            or len(host) > 253 or (port is not None and port < 1)):
        raise ValueError("HTTPS DNS origin with no path or credentials required")
    return value, host


def render(*, station_template, archive_template, output_directory, station_view, archive_view, public_origin=None):
    from zog.box_control.specification import parse_application
    views = (station_view, archive_view)
    if any(not isinstance(view,str) or not VIEW.fullmatch(view) for view in views):
        raise ValueError("exact immutable application view digests required")
    bound_origin, public_host = _public_origin(public_origin) if public_origin is not None else (None, None)
    source_paths = [Path(station_template), Path(archive_template)]
    expected = ("station-access","archive-mirror")
    names = (("web",),("server","refresh-scheduler"))
    mounts = (("station-data",),("archive-data",))
    targets = ("/var/lib/station-access", "/var/lib/archive-mirror")
    # Explicitly reviewed, guest-only program environment keys. Do not let
    # source composition smuggle host enrollment secrets or an archive backend
    # into the station web process.
    environments = (
        {"DJANGO_SETTINGS_MODULE", "STATION_ACCESS_STATE_DIRECTORY",
         "STATION_ACCESS_DEBUG", "STATION_ACCESS_ALLOWED_HOSTS"},
        {"DJANGO_SETTINGS_MODULE", "ARCHIVE_MIRROR_STATE",
         "ARCHIVE_MIRROR_CONFIGURATION", "ARCHIVE_MIRROR_REQUIRE_OWNERSHIP"},
    )
    rendered = []
    for source,app,programs,writable,target,allowed_env,view in zip(
            source_paths,expected,names,mounts,targets,environments,views):
        if source.is_symlink() or not source.is_file():
            raise ValueError("untrusted application template")
        original = parse_application(source)
        if (original.name != app or tuple(p.name for p in original.programs) != programs
                or original.writable_mounts != writable or not original.persistent
                or original.software_view is not None
                or original.execution_identity != "application"
                or original.execution_binding is not None
                or original.multiple_instances or original.start_policy.value != "externally-controlled"
                or len(original.preparation) != 1
                or original.preparation[0].name != "prepare"
                or any(p.mounts != ((writable[0], target),)
                       for p in original.preparation + original.programs)
                or any(set(dict(p.environment)) - allowed_env
                       for p in original.preparation + original.programs)
                or any("mirror-live" in str(p.mounts) for p in original.programs)):
            raise ValueError("production application template differs from reviewed layout")
        if app == "archive-mirror":
            # Archive v2 must fail closed unless the provider actively verifies
            # its controller-owned storage/bindings. Enforce this for both
            # independently launched programs; the preparer must not carry a
            # surrogate ownership setting. A mere allowlist is insufficient.
            ownership = "ARCHIVE_MIRROR_REQUIRE_OWNERSHIP"
            if (any(dict(p.environment).get(ownership) != "1"
                    for p in original.programs)
                    or any(ownership in dict(p.environment)
                           for p in original.preparation)):
                raise ValueError("archive ownership verification is required for both programs")
        if original.preparation[0].command != ("/usr/bin/true",):
            raise ValueError("production preparation command differs from reviewed layout")
        if app == "station-access" and original.programs[0].command != (
                "/usr/bin/python3", "-m", "zog.station_access.cli",
                "--host", "127.0.0.1", "--port", "8000",
                "--state-directory", "/var/lib/station-access"):
            raise ValueError("production station entry point changed")
        text = source.read_text()
        if app == "station-access" and bound_origin is not None:
            # The operator binds an HTTPS origin; no private key, network route,
            # controller project or trust-root location is embedded here.
            old = '"STATION_ACCESS_ALLOWED_HOSTS": "localhost,127.0.0.1",'
            if text.count(old) != 1:
                raise ValueError("production host binding anchor changed")
            replacement = (
                f'"STATION_ACCESS_ALLOWED_HOSTS": "{public_host}",\n'
                f'            "STATION_ACCESS_CSRF_TRUSTED_ORIGINS": "{bound_origin}",\n'
                '            "STATION_ACCESS_SECURE_COOKIES": "1",\n'
                '            "STATION_ACCESS_TRUST_PROXY": "1",'
            )
            text = text.replace(old, replacement, 1)
        anchor = "application(\n"
        if text.count(anchor) != 1:
            raise ValueError("noncanonical application declaration")
        text = text.replace(anchor,anchor + f'    software_view="{view}",\n',1)
        rendered.append((app,view,text))
    root = Path(output_directory)
    if root.exists() or root.is_symlink():
        raise ValueError("composition output must be a new path")
    if root.parent.is_symlink() or not root.parent.is_dir():
        raise ValueError("composition output parent is unsafe")
    root.mkdir(mode=0o700)
    try:
        for name,view,text in rendered:
            directory=root/name
            directory.mkdir(mode=0o700)
            target=directory/"application.py"
            fd=os.open(target,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
            with os.fdopen(fd,"w") as out:
                out.write(text)
                out.flush()
                os.fsync(out.fileno())
            parsed=parse_application(target)
            if (parsed.name!=name or parsed.software_view!=view or
                    (parsed.execution_identity != "application" or parsed.execution_binding is not None)):
                raise ValueError("rendered application software identity changed")
            if name == "station-access" and bound_origin is not None:
                environment = dict(parsed.programs[0].environment)
                required = {
                    "STATION_ACCESS_ALLOWED_HOSTS": public_host,
                    "STATION_ACCESS_CSRF_TRUSTED_ORIGINS": bound_origin,
                    "STATION_ACCESS_SECURE_COOKIES": "1",
                    "STATION_ACCESS_TRUST_PROXY": "1",
                }
                if any(environment.get(key) != value for key, value in required.items()):
                    raise ValueError("rendered station HTTPS origin binding changed")
            if name == "archive-mirror" and (
                    any(dict(p.environment).get("ARCHIVE_MIRROR_REQUIRE_OWNERSHIP") != "1"
                        for p in parsed.programs)
                    or any("ARCHIVE_MIRROR_REQUIRE_OWNERSHIP" in dict(p.environment)
                           for p in parsed.preparation)):
                raise ValueError("rendered archive ownership verification changed")
        dirfd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:os.fsync(dirfd)
        finally:os.close(dirfd)
    except BaseException:
        # Refuse to remove ambiguous/partially emitted source or to overwrite
        # anything on retry. The operator must inspect the generated directory.
        raise
    return {"schema":SCHEMA,"state":"rendered","safe_to_cut_over":False,
            "applications":[{"name":name,"software_view":view}
                            for name,view,_ in rendered],
            "identity_source":"operator-supplied immutable views",
            "public_origin_binding":"explicit" if bound_origin else "unbound",
            "host_bindings":"administrator-policy-required"}


def main(argv=None):
    p=argparse.ArgumentParser()
    for arg in ("station-template","archive-template","output-directory",
                "station-view","archive-view"):
        p.add_argument("--"+arg,required=True)
    p.add_argument("--public-origin", help="Reviewed external HTTPS origin, e.g. https://station.example.net")
    a=p.parse_args(argv)
    try:
        result=render(station_template=a.station_template, archive_template=a.archive_template,
                      output_directory=a.output_directory,station_view=a.station_view,
                      archive_view=a.archive_view,public_origin=a.public_origin)
    except (OSError,ValueError):
        print(json.dumps({"schema":SCHEMA,"state":"blocked","safe_to_cut_over":False}))
        return 2
    print(json.dumps(result,sort_keys=True))
    return 0


if __name__=="__main__":
    raise SystemExit(main())
