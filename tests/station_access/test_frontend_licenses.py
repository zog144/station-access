import hashlib
import json
import os
from pathlib import Path
import tempfile
from django.contrib.auth import get_user_model
from django.test import SimpleTestCase, TestCase, override_settings

class FrontendLicenseTests(SimpleTestCase):
    def test_real_shipped_inventory_link_and_plain_text_are_public(self):
        from django.conf import settings
        root=Path(settings.STATION_ACCESS_FRONTEND_DIRECTORY)
        manifest=json.loads((root/'frontend-build.json').read_text())
        response=self.client.get('/frontend-build.json')
        self.assertEqual(response.status_code,200)
        self.assertEqual(json.loads(b''.join(response.streaming_content)),manifest)
        response=self.client.get('/')
        self.assertIn(('href="/'+manifest['licenses']+'"').encode(),b''.join(response.streaming_content))
        data=(root/manifest['licenses']).read_bytes()
        response=self.client.get('/licenses/')
        self.assertEqual(response.status_code,200);self.assertEqual(response.content,data)
        self.assertEqual(response['Content-Type'],'text/plain; charset=utf-8')
        self.assertEqual(response['X-Content-Type-Options'],'nosniff')
        self.assertEqual(response['Cache-Control'],'no-store')
        response=self.client.get('/'+manifest['licenses'])
        self.assertEqual(b''.join(response.streaming_content),data)
        self.assertEqual(hashlib.sha256(data).hexdigest(),manifest['outputs'][manifest['licenses']])
    def test_invalid_missing_changed_or_unsafe_manifest_never_serves_other_files(self):
        with tempfile.TemporaryDirectory() as directory, override_settings(STATION_ACCESS_FRONTEND_DIRECTORY=directory):
            root=Path(directory);(root/'assets').mkdir()
            self.assertEqual(self.client.get('/licenses/').status_code,404)
            for name in ('../private.txt','index.html','https://example/notice.txt'):
                (root/'frontend-build.json').write_text(json.dumps({'licenses':name,'outputs':{}}))
                self.assertEqual(self.client.get('/licenses/').status_code,404)
            name='assets/LICENSES-000000000000.txt';(root/name).write_text('<script>not executable</script>')
            (root/'frontend-build.json').write_text(json.dumps({'licenses':name,'outputs':{name:'wrong'}}))
            self.assertEqual(self.client.get('/licenses/').status_code,404)
    def test_legal_text_is_not_executable_html(self):
        with tempfile.TemporaryDirectory() as directory, override_settings(STATION_ACCESS_FRONTEND_DIRECTORY=directory):
            root=Path(directory);(root/'assets').mkdir();data=b'<script>alert("license fixture")</script>'
            sha=hashlib.sha256(data).hexdigest();name='assets/LICENSES-'+sha[:12]+'.txt';(root/name).write_bytes(data)
            (root/'frontend-build.json').write_text(json.dumps({'licenses':name,'outputs':{name:sha}}))
            response=self.client.get('/licenses/');self.assertEqual(response.content,data)
            self.assertEqual(response['Content-Type'],'text/plain; charset=utf-8');self.assertIn("default-src 'none'",response['Content-Security-Policy'])


class ComposedFrontendHttpTests(TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory();self.addCleanup(self.temporary.cleanup)
        base=Path(self.temporary.name)/'applications'
        self.view=base/'station-access';self.store=base/'.store'
        self.relative=Path('share/station-access/frontend')
        self.frontend=self.view/self.relative
        self.frontend.mkdir(parents=True);self.store.mkdir()
        artifact='f'*64
        target_root=self.store/artifact/self.relative
        (target_root/'assets').mkdir(parents=True)
        notice=b'composed notice'
        digest=hashlib.sha256(notice).hexdigest()
        self.notice_name='assets/LICENSES-'+digest[:12]+'.txt'
        self.files={
            'index.html':b'<html>composed station frontend</html>',
            'frontend-build.json':json.dumps({
                'licenses':self.notice_name,
                'outputs':{self.notice_name:digest},
            }).encode(),
            'assets/app-123456789abc.js':b'console.log("composed");',
            self.notice_name:notice,
        }
        for relative,data in self.files.items():
            target=target_root/relative
            target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(data)
            leaf=self.frontend/relative
            leaf.parent.mkdir(parents=True,exist_ok=True)
            leaf.symlink_to(os.path.relpath(target,leaf.parent))
        self.override=override_settings(
            STATION_ACCESS_FRONTEND_INSTALLATION='',
            STATION_ACCESS_FRONTEND_DIRECTORY=self.frontend,
            STATION_ACCESS_APPLICATION_VIEW_DIRECTORY=self.view,
        )
        self.override.enable();self.addCleanup(self.override.disable)

    def test_composed_view_serves_portal_archives_assets_inventory_and_notices(self):
        self.assertEqual(self.client.get('/').status_code,200)
        self.assertEqual(self.client.get('/administration/archives').status_code,200)
        self.assertEqual(
            b''.join(self.client.get('/assets/app-123456789abc.js').streaming_content),
            self.files['assets/app-123456789abc.js'],
        )
        self.assertEqual(
            b''.join(self.client.get('/frontend-build.json').streaming_content),
            self.files['frontend-build.json'],
        )
        notice=self.client.get('/licenses/')
        self.assertEqual(notice.status_code,200)
        self.assertEqual(notice.content,self.files[self.notice_name])
        admin=get_user_model().objects.create_superuser('composed-admin')
        self.client.force_login(admin)
        response=self.client.get('/archives/')
        self.assertEqual(response.status_code,200)
        self.assertEqual(b''.join(response.streaming_content),self.files['index.html'])
