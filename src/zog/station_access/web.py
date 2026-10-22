"""Same-origin frontend delivery for first-use and small-host deployments."""
import json
import mimetypes
import os
import re
from pathlib import Path, PurePosixPath

from django.conf import settings
from django.http import FileResponse, Http404, HttpResponse
from django.views.decorators.http import require_GET


_SHA256 = re.compile(r'[a-f0-9]{64}')


def _frontend_roots():
    """Read one atomic selection snapshot. Retained sets serve only hashed assets."""
    installation = getattr(settings, 'STATION_ACCESS_FRONTEND_INSTALLATION', '')
    if not installation:
        return [Path(settings.STATION_ACCESS_FRONTEND_DIRECTORY).resolve()]
    base = Path(installation).resolve()
    try:
        selection = base / 'selection.json'
        if selection.is_symlink() or selection.stat().st_size > 1024 * 1024:
            raise ValueError()
        data = json.loads(selection.read_text())
        identifiers = data['retained']
        if (data['schema'] != 1 or not isinstance(identifiers, list) or not identifiers
                or identifiers[0] != data['active'] or len(set(identifiers)) != len(identifiers)):
            raise ValueError()
        roots = []
        for identifier in identifiers:
            if not isinstance(identifier, str) or not re.fullmatch('[a-f0-9]{32}', identifier):
                raise ValueError()
            path = base / 'releases' / identifier / 'dist'
            if path.resolve() != path or not path.is_dir():
                raise ValueError()
            roots.append(path)
        return roots
    except (OSError, ValueError, KeyError, TypeError):
        raise Http404('No valid frontend selection; verify and activate an installation.') from None


def _relative(value):
    if not isinstance(value, str) or not value or '\x00' in value:
        return None
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in ('', '.', '..') for part in path.parts):
        return None
    return Path(*path.parts)


def _real_file_beneath(root, relative):
    candidate = root / relative
    try:
        resolved = candidate.resolve(strict=True)
    except OSError:
        return None
    if not resolved.is_relative_to(root) or not resolved.is_file():
        return None
    return resolved


def _application_view_file(root, relative):
    """Validate one immutable image-build application-view symlink binding.

    The trusted view root is controller-mounted read-only at
    /applications/station-access by default. Image-build composes each leaf as a
    relative link to /applications/.store/<artifact>/<same logical path>. Accept
    only that exact same-path binding and keep the resolved leaf inside that one
    artifact object.
    """
    configured = getattr(
        settings,
        'STATION_ACCESS_APPLICATION_VIEW_DIRECTORY',
        '/applications/station-access',
    )
    view_root = Path(configured)
    if not view_root.is_absolute():
        return None
    view_root = Path(os.path.abspath(view_root))
    if view_root.is_symlink() or not view_root.is_dir():
        return None
    if root != view_root and not root.is_relative_to(view_root):
        return None

    try:
        root_relative = root.relative_to(view_root)
    except ValueError:
        return None
    current = view_root
    for part in root_relative.parts:
        current = current / part
        if current.is_symlink() or not current.is_dir():
            return None

    logical = root_relative / relative
    current = view_root
    for part in logical.parts[:-1]:
        current = current / part
        if current.is_symlink() or not current.is_dir():
            return None
    leaf = view_root / logical
    if not leaf.is_symlink():
        return None

    try:
        target = os.readlink(leaf)
    except OSError:
        return None
    if os.path.isabs(target):
        return None

    store_root = view_root.parent / '.store'
    if store_root.is_symlink() or not store_root.is_dir():
        return None
    normalized = Path(os.path.normpath(os.path.join(str(leaf.parent), target)))
    try:
        store_relative = normalized.relative_to(store_root)
    except ValueError:
        return None
    if len(store_relative.parts) < 2 or not _SHA256.fullmatch(store_relative.parts[0]):
        return None

    artifact_root = store_root / store_relative.parts[0]
    if artifact_root.is_symlink() or not artifact_root.is_dir():
        return None
    expected = artifact_root / logical
    if normalized != expected:
        return None
    if target != os.path.relpath(expected, leaf.parent):
        return None
    try:
        resolved = expected.resolve(strict=True)
        artifact_resolved = artifact_root.resolve(strict=True)
    except OSError:
        return None
    if (not resolved.is_relative_to(artifact_resolved)
            or not resolved.is_file()):
        return None
    return resolved


def _frontend_path(root, relative):
    relative = _relative(relative)
    if relative is None:
        return None, False
    direct = _real_file_beneath(root, relative)
    if direct is not None:
        return direct, False
    bound = _application_view_file(root, relative)
    return (bound, True) if bound is not None else (None, False)


def _frontend_file(relative, retained=False):
    roots = _frontend_roots()
    for root in roots if retained else roots[:1]:
        path, _ = _frontend_path(root, relative)
        if path is None:
            continue
        response = FileResponse(path.open('rb'), content_type=mimetypes.guess_type(path.name)[0] or 'application/octet-stream')
        response['X-Content-Type-Options'] = 'nosniff'
        return response
    raise Http404('Frontend file not found; build and activate the complete frontend')


@require_GET
def portal(request, route=''):
    response = _frontend_file('index.html')
    response['Cache-Control'] = 'no-store'
    return response


@require_GET
def asset(request, filename):
    if not re.fullmatch(r'[A-Za-z0-9_-]+-[A-Za-z0-9_-]+\.(?:js|css|txt)', filename):
        raise Http404('Unknown hashed frontend asset')
    response = _frontend_file('assets/' + filename, retained=True)
    if response['Content-Type'] == 'text/plain':
        response['Content-Type'] = 'text/plain; charset=utf-8'
    response['Cache-Control'] = 'public, max-age=31536000, immutable'
    return response


@require_GET
def build_inventory(request):
    """Fixed public build evidence, independent of authentication and private state."""
    response = _frontend_file('frontend-build.json')
    response['Content-Type'] = 'application/json'
    response['Cache-Control'] = 'no-store'
    return response


@require_GET
def licenses(request):
    """Serve only the hashed, inventoried notice asset as inert plain text."""
    import hashlib
    root = _frontend_roots()[0]
    try:
        manifest_leaf = root / 'frontend-build.json'
        manifest_path, composed = _frontend_path(root, 'frontend-build.json')
        if manifest_path is None or (manifest_leaf.is_symlink() and not composed):
            raise ValueError()
        if manifest_path.stat().st_size > 1024 * 1024:
            raise ValueError()
        manifest = json.loads(manifest_path.read_text())
        name = manifest['licenses']
        if not isinstance(name, str) or not re.fullmatch(r'assets/LICENSES-[a-f0-9]{12}\.txt', name):
            raise ValueError()
        notice_path, _ = _frontend_path(root, name)
        if notice_path is None or notice_path.stat().st_size > 2 * 1024 * 1024:
            raise ValueError()
        data = notice_path.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        if digest != manifest['outputs'][name] or name != 'assets/LICENSES-' + digest[:12] + '.txt':
            raise ValueError()
    except (OSError, ValueError, KeyError, TypeError):
        raise Http404('Frontend license evidence unavailable; rebuild and install the complete frontend.') from None
    response = HttpResponse(data, content_type='text/plain; charset=utf-8')
    response['X-Content-Type-Options'] = 'nosniff'
    response['Content-Security-Policy'] = "default-src 'none'; sandbox"
    response['Cache-Control'] = 'no-store'
    return response
