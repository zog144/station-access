"""No implicit sharing of box-control persistent storage or host grants."""
from pathlib import Path
from unittest import TestCase

from zog.box_control.specification import parse_application

ROOT=Path(__file__).resolve().parents[2]
ARCHIVE_TEMPLATE=ROOT/'dependencies/zog144/archive-mirror/integration/production/archive-mirror/application.py'


class StationCompositionTests(TestCase):
    def archive_template(self):
        # Required cross-repository acceptance: an absent pinned checkout is
        # a test failure, not a falsely green skipped composition test.
        self.assertTrue(ARCHIVE_TEMPLATE.is_file(),
                        "Pinned archive-mirror checkout is required; restore exact "
                        "version-share-handoff.json dependency before testing")
        return ARCHIVE_TEMPLATE

    def test_production_station_web_owns_only_station_data(self):
        app=parse_application(ROOT/'integration/production/station-access/application.py')
        self.assertEqual(app.name,'station-access')
        self.assertTrue(app.persistent)
        self.assertEqual(app.execution_identity, "application")
        self.assertIsNone(app.execution_binding)
        self.assertEqual(tuple(step.name for step in app.preparation), ("prepare",))
        self.assertEqual(
            {(step.user, step.group) for step in app.preparation + app.programs},
            {("regular", None)},  # Legacy parser placeholder; grant binds before launch.
        )
        source = (ROOT / "integration/production/station-access/application.py").read_text()
        self.assertNotIn('user="regular"', source)
        self.assertNotIn('group=', source)
        self.assertEqual(app.writable_mounts,('station-data',))
        self.assertEqual(tuple(p.name for p in app.programs),('web',))
        self.assertEqual(dict(app.programs[0].mounts),{'station-data':'/var/lib/station-access'})
        self.assertNotIn('ARCHIVE_MIRROR_CONFIGURATION',dict(app.programs[0].environment))
        self.assertNotIn('/var/lib/archive-mirror',str(app))
        self.assertNotIn('/run/zog-host/',str(app))
        self.assertIsNone(app.software_view)  # requires exact deployment-bound selection

    def test_two_immutable_views_render_only_distinct_apps_and_preserve_mounts(self):
        import tempfile
        from zog.station_access.production_composition import render
        archive=self.archive_template()
        with tempfile.TemporaryDirectory() as temp:
            output=Path(temp)/'applications'
            result=render(
                station_template=ROOT/'integration/production/station-access/application.py',
                archive_template=archive,output_directory=output,
                station_view='sha256:'+'a'*64,archive_view='sha256:'+'b'*64)
            self.assertFalse(result['safe_to_cut_over'])
            station=parse_application(output/'station-access/application.py')
            mirror=parse_application(output/'archive-mirror/application.py')
            self.assertEqual(station.software_view,'sha256:'+'a'*64)
            self.assertEqual(station.execution_identity, "application")
            self.assertEqual(mirror.execution_identity, "application")
            self.assertIsNone(mirror.execution_binding)
            self.assertNotEqual(station.name, mirror.name)
            self.assertEqual(
                [dict(p.environment)["ARCHIVE_MIRROR_REQUIRE_OWNERSHIP"]
                 for p in mirror.programs], ["1", "1"])
            self.assertNotIn(
                "ARCHIVE_MIRROR_REQUIRE_OWNERSHIP",
                dict(mirror.preparation[0].environment))
            self.assertNotIn(
                "ARCHIVE_MIRROR_REQUIRE_OWNERSHIP",
                dict(station.programs[0].environment))
            for parsed in (station, mirror):
                for step in parsed.preparation + parsed.programs:
                    self.assertEqual(step.user, "regular")  # Unbound legacy parser placeholder.
                    self.assertIsNone(step.group)
            rendered_station = (output / 'station-access/application.py').read_text()
            rendered_archive = (output / 'archive-mirror/application.py').read_text()
            self.assertNotIn('user=', rendered_station + rendered_archive)
            self.assertNotIn('group=', rendered_station + rendered_archive)
            self.assertIsNone(station.execution_binding)
            self.assertEqual(mirror.software_view,'sha256:'+'b'*64)
            self.assertEqual(tuple(p.name for p in mirror.programs),('server','refresh-scheduler'))
            self.assertEqual(mirror.writable_mounts,('archive-data',))
            self.assertNotEqual(station.writable_mounts,mirror.writable_mounts)
            with self.assertRaises(ValueError):
                render(station_template=ROOT/'integration/production/station-access/application.py',
                       archive_template=archive,output_directory=output,
                       station_view='sha256:'+'c'*64,archive_view='sha256:'+'d'*64)

    def test_unknown_view_digest_is_rejected_without_outputs(self):
        import tempfile
        from zog.station_access.production_composition import render
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaises(ValueError):
                render(station_template=ROOT/'integration/production/station-access/application.py',
                       archive_template=ROOT/'integration/production/station-access/application.py',
                       output_directory=Path(temp)/'applications',
                       station_view='latest',archive_view='sha256:'+'b'*64)
            self.assertFalse((Path(temp)/'applications').exists())

    def test_composition_rejects_legacy_station_credentials_before_output(self):
        import tempfile
        from zog.station_access.production_composition import render
        from zog.box_control.errors import ConfigurationError
        source = ROOT / 'integration/production/station-access/application.py'
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            archive = self.archive_template()
            original = source.read_text()
            for label, unsafe in (
                ("omitted-symbolic-identity", original.replace('    execution_identity="application",\n', '')),
                ("chosen-user", original.replace('        name="web",\n', '        name="web",\n        user="regular",\n')),
                ("chosen-group", original.replace('        name="prepare",\n', '        name="prepare",\n        group="staff",\n')),
            ):
                template = root / 'untrusted.py'
                template.write_text(unsafe)
                output = root / 'rendered'
                with self.subTest(case=label), self.assertRaises((ValueError, ConfigurationError)):
                    render(station_template=template, archive_template=archive,
                           output_directory=output,
                           station_view='sha256:'+'a'*64,
                           archive_view='sha256:'+'b'*64)
                self.assertFalse(output.exists())

    def test_composition_refuses_cross_application_storage_or_host_credentials(self):
        import tempfile
        from zog.station_access.production_composition import render
        from zog.box_control.errors import ConfigurationError
        station = ROOT / 'integration/production/station-access/application.py'
        archive = self.archive_template()
        station_text, archive_text = station.read_text(), archive.read_text()
        examples = (
            ("station-archive-data-mount", station_text.replace(
                 '"/var/lib/station-access"', '"/var/lib/archive-mirror"'), archive_text),
            ("station-host-secret-env", station_text.replace(
                 '"STATION_ACCESS_DEBUG": "0",',
                 '"STATION_ACCESS_DEBUG": "0",\n'
                 '            "HOST_DISCOVER_ENROLLMENT_KEY": "/run/identity.pem",'), archive_text),
            ("station-unreviewed-launch", station_text.replace(
                 '"-m", "zog.station_access.cli"', '"-m", "os"'), archive_text),
            ("archive-without-controller-grant", station_text, archive_text.replace(
                 '    execution_identity="application",\n', '')),
            ("archive-station-storage", station_text, archive_text.replace(
                 '"/var/lib/archive-mirror"', '"/var/lib/station-access"')),
            ("archive-named-user", station_text, archive_text.replace(
                 '        name="prepare",\n', '        name="prepare",\n        user="regular",\n')),
            ("archive-host-export-env", station_text, archive_text.replace(
                 '"ARCHIVE_MIRROR_STATE": "/var/lib/archive-mirror",',
                 '"ARCHIVE_MIRROR_STATE": "/var/lib/archive-mirror",\n'
                 '                "HOST_DISCOVER_ENROLLMENT_KEY": "/run/key",')),
        )
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for label, modified_station, modified_archive in examples:
                with self.subTest(case=label):
                    station_path, archive_path = root / 'station.py', root / 'archive.py'
                    station_path.write_text(modified_station)
                    archive_path.write_text(modified_archive)
                    output = root / 'rendered'
                    with self.assertRaises((ValueError, ConfigurationError)):
                        render(station_template=station_path, archive_template=archive_path,
                               output_directory=output,
                               station_view='sha256:'+'a'*64,
                               archive_view='sha256:'+'b'*64)
                    self.assertFalse(output.exists())

    def test_archive_ownership_guard_cannot_be_removed_or_weakened_on_either_program(self):
        import tempfile
        from zog.station_access.production_composition import render
        from zog.box_control.errors import ConfigurationError
        station=ROOT/'integration/production/station-access/application.py'
        archive_source=self.archive_template().read_text()
        guard='                "ARCHIVE_MIRROR_REQUIRE_OWNERSHIP": "1",\n'
        self.assertEqual(archive_source.count(guard), 2)
        # Change *one* program at a time so a permissive "at least one"
        # check would fail these tests. All input rejection precedes output.
        for name in ('server','refresh-scheduler'):
            marker='name="'+name+'",'
            before,sep,after=archive_source.partition(marker)
            self.assertTrue(sep, name)
            middle,found,remainder=after.partition(guard)
            self.assertTrue(found, name)
            for label, replacement in (
                ('missing', ''),
                ('disabled', guard.replace('"1"', '"0"')),
                ('empty', guard.replace('"1"', '""')),
                ('boolean-like', guard.replace('"1"', '"true"')),
                ('whitespace', guard.replace('"1"', '" 1"')),
                ('boolean-true', guard.replace('"1"', 'True')),
                ('boolean-false', guard.replace('"1"', 'False')),
                ('numeric-zero', guard.replace('"1"', '0')),
                ('float-one', guard.replace('"1"', '1.0')),
            ):
                with self.subTest(program=name,case=label), tempfile.TemporaryDirectory() as temp:
                    directory=Path(temp)
                    untrusted=directory/'archive.py'
                    untrusted.write_text(before+sep+middle+replacement+remainder)
                    output=directory/'composed'
                    with self.assertRaises((ValueError, ConfigurationError)):
                        render(station_template=station,archive_template=untrusted,
                               output_directory=output,
                               station_view='sha256:'+'a'*64,
                               archive_view='sha256:'+'b'*64)
                    self.assertFalse(output.exists())

    def test_integer_one_normalizes_to_enabled_ownership_on_each_archive_program(self):
        """Parser-normalized integer 1 is the same effective guard as string '1'."""
        import tempfile
        from zog.station_access.production_composition import render
        station = ROOT / 'integration/production/station-access/application.py'
        archive_source = self.archive_template().read_text()
        guard = '                "ARCHIVE_MIRROR_REQUIRE_OWNERSHIP": "1",\n'
        self.assertEqual(archive_source.count(guard), 2)
        for name in ('server', 'refresh-scheduler'):
            marker = 'name="' + name + '",'
            before, sep, after = archive_source.partition(marker)
            self.assertTrue(sep, name)
            middle, found, rest = after.partition(guard)
            self.assertTrue(found, name)
            with self.subTest(program=name), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                template = root / 'archive.py'
                # Only one program is changed at a time.
                template.write_text(before + sep + middle +
                                    guard.replace('"1"', '1') + rest)
                output = root / 'rendered'
                result = render(
                    station_template=station, archive_template=template,
                    output_directory=output,
                    station_view='sha256:' + 'a'*64,
                    archive_view='sha256:' + 'b'*64,
                )
                self.assertEqual(result['state'], 'rendered')
                self.assertFalse(result['safe_to_cut_over'])
                parsed = parse_application(output / 'archive-mirror/application.py')
                self.assertEqual(
                    [dict(program.environment)['ARCHIVE_MIRROR_REQUIRE_OWNERSHIP']
                     for program in parsed.programs], ['1', '1'])
                self.assertEqual(
                    dict(parsed.preparation[0].environment).get(
                        'ARCHIVE_MIRROR_REQUIRE_OWNERSHIP'), None)
                self.assertNotIn(
                    'ARCHIVE_MIRROR_REQUIRE_OWNERSHIP',
                    (output / 'station-access/application.py').read_text())

    def test_archive_ownership_flag_cannot_move_to_preparation_or_station_web(self):
        import tempfile
        from zog.station_access.production_composition import render
        from zog.box_control.errors import ConfigurationError
        archive=self.archive_template()
        station=ROOT/'integration/production/station-access/application.py'
        guard='"ARCHIVE_MIRROR_REQUIRE_OWNERSHIP": "1",'
        source=station.read_text()
        archive_text=archive.read_text()
        # Ownership requirements belong to the two archive runtimes alone.
        moved=archive_text.replace(
            '        name="prepare",',
            '        name="prepare",\n'
            '        environment={"ARCHIVE_MIRROR_REQUIRE_OWNERSHIP": "1"},')
        contaminated=source.replace(
            '"STATION_ACCESS_DEBUG": "0",',
            '"STATION_ACCESS_DEBUG": "0",\n'
            '            "ARCHIVE_MIRROR_REQUIRE_OWNERSHIP": "1",')
        self.assertIn(guard,moved)
        self.assertNotEqual(source,contaminated)
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            for label,untrusted_station,untrusted_archive in (
                ('archive-preparation',source,moved),
                ('station-web',contaminated,archive_text)):
                with self.subTest(label=label):
                    station_path=root/'station.py'
                    archive_path=root/'archive.py'
                    station_path.write_text(untrusted_station)
                    archive_path.write_text(untrusted_archive)
                    output=root/'rendered'
                    with self.assertRaises((ValueError, ConfigurationError)):
                        render(station_template=station_path,archive_template=archive_path,
                               output_directory=output,
                               station_view='sha256:'+'a'*64,
                               archive_view='sha256:'+'b'*64)
                    self.assertFalse(output.exists())

    def test_reviewed_https_origin_binds_cookies_proxy_csrf_and_allowed_host(self):
        import tempfile
        from zog.station_access.production_composition import render
        station = ROOT / 'integration/production/station-access/application.py'
        archive = self.archive_template()
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / 'applications'
            result = render(
                station_template=station, archive_template=archive,
                output_directory=output,
                station_view='sha256:' + 'a'*64,
                archive_view='sha256:' + 'b'*64,
                public_origin='https://portal.example.test:8443',
            )
            self.assertEqual(result['public_origin_binding'], 'explicit')
            self.assertFalse(result['safe_to_cut_over'])
            parsed = parse_application(output/'station-access/application.py')
            web = dict(parsed.programs[0].environment)
            self.assertEqual(web['STATION_ACCESS_ALLOWED_HOSTS'], 'portal.example.test')
            self.assertEqual(web['STATION_ACCESS_CSRF_TRUSTED_ORIGINS'],
                             'https://portal.example.test:8443')
            self.assertEqual(web['STATION_ACCESS_SECURE_COOKIES'], '1')
            self.assertEqual(web['STATION_ACCESS_TRUST_PROXY'], '1')
            archive_spec = parse_application(output/'archive-mirror/application.py')
            for program in archive_spec.programs:
                environment = dict(program.environment)
                self.assertNotIn('STATION_ACCESS_CSRF_TRUSTED_ORIGINS', environment)
                self.assertEqual(environment['ARCHIVE_MIRROR_REQUIRE_OWNERSHIP'], '1')
            source = station.read_text()
            self.assertNotIn('STATION_ACCESS_TRUST_PROXY', source)
            self.assertNotIn('portal.example.test', source)

    def test_missing_external_origin_explicitly_remains_unbound(self):
        import tempfile
        from zog.station_access.production_composition import render
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / 'applications'
            result = render(
                station_template=ROOT/'integration/production/station-access/application.py',
                archive_template=self.archive_template(),
                output_directory=output,
                station_view='sha256:'+'a'*64,
                archive_view='sha256:'+'b'*64)
            self.assertEqual(result['public_origin_binding'], 'unbound')
            self.assertFalse(result['safe_to_cut_over'])
            parsed = parse_application(output/'station-access/application.py')
            self.assertNotIn('STATION_ACCESS_TRUST_PROXY',
                             dict(parsed.programs[0].environment))

    def test_bad_proxy_origins_rejected_without_publishing_source(self):
        import tempfile
        from zog.station_access.production_composition import render
        for origin in (
            '', 'http://portal.example.test', 'https://portal.example.test/',
            'https://portal.example.test/path',
            'https://portal.example.test?token=secret',
            'https://user:password@portal.example.test',
            'https://portal.example.test#fragment',
            'https://portal.example.test:0', 'https://portal.example.test:99999',
            'https://portal_example.test', 'https://portal.example.test.',
            'https://portal.example.test ', 'https://PORTAL.example.test',
            'https://portal.example.test\ninjection',
        ):
            with self.subTest(origin=origin), tempfile.TemporaryDirectory() as temp:
                output = Path(temp) / 'applications'
                with self.assertRaises(ValueError):
                    render(
                        station_template=ROOT/'integration/production/station-access/application.py',
                        archive_template=self.archive_template(), output_directory=output,
                        station_view='sha256:'+'a'*64, archive_view='sha256:'+'b'*64,
                        public_origin=origin)
                self.assertFalse(output.exists())

    def test_composition_cli_binds_reviewed_public_origin(self):
        import json
        import subprocess
        import sys
        import tempfile
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / 'applications'
            result = subprocess.run([
                sys.executable, '-m', 'zog.station_access.production_composition',
                '--station-template',
                str(ROOT/'integration/production/station-access/application.py'),
                '--archive-template', str(self.archive_template()),
                '--output-directory', str(output),
                '--station-view', 'sha256:'+'a'*64,
                '--archive-view', 'sha256:'+'b'*64,
                '--public-origin', 'https://portal.example.test',
            ], cwd=str(ROOT), text=True, capture_output=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(result.stdout)
            self.assertEqual(payload['public_origin_binding'], 'explicit')
            self.assertFalse(payload['safe_to_cut_over'])
            station = parse_application(output/'station-access/application.py')
            env = dict(station.programs[0].environment)
            self.assertEqual(env['STATION_ACCESS_ALLOWED_HOSTS'], 'portal.example.test')
            self.assertEqual(env['STATION_ACCESS_CSRF_TRUSTED_ORIGINS'],
                             'https://portal.example.test')
            self.assertEqual(env['STATION_ACCESS_SECURE_COOKIES'], '1')
            archive = parse_application(output/'archive-mirror/application.py')
            self.assertEqual([dict(p.environment)['ARCHIVE_MIRROR_REQUIRE_OWNERSHIP']
                              for p in archive.programs], ['1', '1'])
