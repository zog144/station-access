"""Actual Django views; no controller, database, cloud or external identity dependencies."""
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'src'))
from django.conf import settings
if not settings.configured:
    settings.configure(DEFAULT_CHARSET='utf-8')
from django.http import Http404
from django.test import RequestFactory, override_settings
from zog.station_access import web


class SelectionServingTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.request = RequestFactory().get('/')
        self.setting = override_settings(STATION_ACCESS_FRONTEND_INSTALLATION=self.root)
        self.setting.enable(); self.addCleanup(self.setting.disable)

    def release(self, identifier):
        root = self.root / 'releases' / identifier / 'dist'
        (root / 'assets').mkdir(parents=True)
        (root / 'index.html').write_text(identifier)
        data = ('legal ' + identifier).encode()
        sha = hashlib.sha256(data).hexdigest()
        name = 'assets/LICENSES-' + sha[:12] + '.txt'
        (root / name).write_bytes(data)
        (root / 'assets' / ('index-' + identifier + '.js')).write_text(identifier)
        (root / 'frontend-build.json').write_text(json.dumps({'licenses': name, 'outputs': {name: sha}}))
        return root, name

    def select(self, first, second):
        (self.root / 'selection.json').write_text(json.dumps({'schema': 1, 'active': first, 'retained': [first, second]}))

    def test_old_assets_retained_while_entry_and_notices_follow_active(self):
        first, second = 'a' * 32, 'b' * 32
        old, oldnotice = self.release(first); new, newnotice = self.release(second)
        self.select(second, first)
        response = web.portal(self.request)
        self.assertEqual(b''.join(response.streaming_content), second.encode())
        response = web.asset(self.request, oldnotice.removeprefix('assets/'))
        self.assertEqual(b''.join(response.streaming_content), (old / oldnotice).read_bytes())
        self.assertEqual(response['Content-Type'], 'text/plain; charset=utf-8')
        response = web.licenses(self.request)
        self.assertEqual(response.content, (new / newnotice).read_bytes())
        self.assertIn('sandbox', response['Content-Security-Policy'])
        response = web.asset(self.request, 'index-' + first + '.js')
        self.assertEqual(b''.join(response.streaming_content), first.encode())
        self.assertEqual(response['X-Content-Type-Options'], 'nosniff')

    def test_missing_corrupt_unsafe_or_symlink_selection_fails_closed(self):
        for data in (None, {}, {'schema': 1, 'active': '../private', 'retained': ['../private']},
                     {'schema': 1, 'active': 'a' * 32, 'retained': ['b' * 32]}):
            if data is not None:
                (self.root / 'selection.json').write_text(json.dumps(data))
            with self.assertRaises(Http404):
                web.portal(self.request)
        (self.root / 'selection.json').unlink()
        (self.root / 'selection.json').symlink_to('/etc/passwd')
        with self.assertRaises(Http404):
            web.portal(self.request)

    def test_only_hashed_asset_names_can_use_retention(self):
        for name in ('../installation.json', 'index.html', '../../etc/passwd', 'arbitrary.txt', 'folder/index-123.js'):
            with self.assertRaises(Http404):
                web.asset(self.request, name)


if __name__ == '__main__':
    unittest.main()


class ComposedApplicationViewServingTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        base = Path(self.temporary.name) / 'applications'
        self.view = base / 'station-access'
        self.store = base / '.store'
        self.frontend_relative = Path('share/station-access/frontend')
        self.frontend = self.view / self.frontend_relative
        self.frontend.mkdir(parents=True)
        self.store.mkdir()
        self.request = RequestFactory().get('/')
        self.settings = override_settings(
            STATION_ACCESS_FRONTEND_INSTALLATION='',
            STATION_ACCESS_FRONTEND_DIRECTORY=self.frontend,
            STATION_ACCESS_APPLICATION_VIEW_DIRECTORY=self.view,
        )
        self.settings.enable()
        self.addCleanup(self.settings.disable)

    def compose(self):
        artifact = 'c' * 64
        artifact_root = self.store / artifact
        target_root = artifact_root / self.frontend_relative
        (target_root / 'assets').mkdir(parents=True)
        notice = b'composed legal evidence'
        notice_sha = hashlib.sha256(notice).hexdigest()
        notice_name = 'assets/LICENSES-' + notice_sha[:12] + '.txt'
        files = {
            'index.html': b'<html>composed-view</html>',
            'frontend-build.json': json.dumps({
                'licenses': notice_name,
                'outputs': {notice_name: notice_sha},
            }).encode(),
            'assets/app-123456789abc.js': b'console.log("composed");',
            notice_name: notice,
        }
        for relative, data in files.items():
            target = target_root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            leaf = self.frontend / relative
            leaf.parent.mkdir(parents=True, exist_ok=True)
            leaf.symlink_to(os.path.relpath(target, leaf.parent))
        return artifact_root, notice_name, files

    def test_composed_view_entry_assets_inventory_and_notices(self):
        artifact_root, notice_name, files = self.compose()
        response = web.portal(self.request)
        self.assertEqual(b''.join(response.streaming_content), files['index.html'])
        response = web.portal(self.request, route='administration/archives')
        self.assertEqual(b''.join(response.streaming_content), files['index.html'])
        response = web.asset(self.request, 'app-123456789abc.js')
        self.assertEqual(b''.join(response.streaming_content), files['assets/app-123456789abc.js'])
        response = web.build_inventory(self.request)
        self.assertEqual(b''.join(response.streaming_content), files['frontend-build.json'])
        response = web.licenses(self.request)
        self.assertEqual(response.content, files[notice_name])
        self.assertIn('sandbox', response['Content-Security-Policy'])

    def test_symlink_to_wrong_logical_path_is_rejected(self):
        artifact_root, _, _ = self.compose()
        other = artifact_root / self.frontend_relative / 'other.html'
        other.write_text('not index')
        leaf = self.frontend / 'index.html'
        leaf.unlink()
        leaf.symlink_to(os.path.relpath(other, leaf.parent))
        with self.assertRaises(Http404):
            web.portal(self.request)

    def test_symlink_outside_store_is_rejected(self):
        outside = Path(self.temporary.name) / 'outside.html'
        outside.write_text('private')
        leaf = self.frontend / 'index.html'
        leaf.symlink_to(os.path.relpath(outside, leaf.parent))
        with self.assertRaises(Http404):
            web.portal(self.request)

    def test_store_artifact_symlink_escape_is_rejected(self):
        artifact = 'd' * 64
        artifact_root = self.store / artifact
        artifact_root.mkdir()
        target = artifact_root / self.frontend_relative / 'index.html'
        target.parent.mkdir(parents=True)
        outside = Path(self.temporary.name) / 'outside.html'
        outside.write_text('private')
        target.symlink_to(os.path.relpath(outside, target.parent))
        leaf = self.frontend / 'index.html'
        leaf.symlink_to(os.path.relpath(target, leaf.parent))
        with self.assertRaises(Http404):
            web.portal(self.request)

    def test_regular_file_cannot_smuggle_store_content(self):
        artifact = 'e' * 64
        target = self.store / artifact / self.frontend_relative / 'index.html'
        target.parent.mkdir(parents=True)
        target.write_text('store file')
        (self.frontend / 'index.html').write_text('ordinary local file')
        response = web.portal(self.request)
        self.assertEqual(b''.join(response.streaming_content), b'ordinary local file')
