"""Allowlist privacy, bounded collection and exclusive archive creation."""
import contextlib
import io
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from app.utility import support_bundle as bundle


SECRET = 'PRIVATE_SENTINEL_8347_NEVER_SHARE'


class TestSupportBundle(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.write('app/version.py', "__version__ = '5.4.0'\n")
        self.write('conf/default.yml', 'host: 127.0.0.1\nport: 8888\nplugins: [training]\n')
        self.write('plugins/training/hook.py', 'raise AssertionError("Plugin hook executed")\n')
        self.enterContext(patch.object(bundle, 'ROOT', self.root))
        self.enterContext(patch.object(bundle, 'probe', return_value={'status': 'available', 'value': '1.2.3'}))
        self.enterContext(patch.object(bundle.metadata, 'version', return_value='1.2.3'))

    def write(self, relative, value):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value, encoding='utf-8')
        return path

    def test_default_fallback_and_known_metadata(self):
        entries = bundle.collect(self.root)
        self.assertEqual(entries['environment.json']['caldera_version'], '5.4.0')
        self.assertTrue(entries['configuration.json']['used_default_fallback'])
        self.assertEqual(entries['configuration.json']['numeric_settings']['port'], 8888)
        self.assertTrue(entries['plugins.json']['training']['entrypoint_present'])

    def test_archive_excludes_secret_values_paths_and_forbidden_files(self):
        self.write('conf/local.yml', f'''host: https://user:{SECRET}@private.example/
port: '{SECRET}'
plugins: [training, '{SECRET}']
users: {{red: {{'{SECRET}': '{SECRET}'}}}}
api_key_red: '{SECRET}'
encryption_key: '{SECRET}'
crypt_salt: '{SECRET}'
custom: {{unknown: '{SECRET}'}}
''')
        for path in ('.env', 'data/cookie_storage', 'data/object_store', 'data/results/private.txt', 'conf/ssh_keys/key', '.git/config'):
            self.write(path, SECRET)
        log = self.write(SECRET + '.log', f'ERROR: Authorization: Bearer {SECRET}\nAn unlabelled secret: {SECRET}\nModuleNotFoundError: {SECRET}\n')
        output = self.root / 'support.zip'
        before = (self.root / 'conf/local.yml').read_bytes()
        bundle.write_bundle(output, bundle.collect(self.root, logs=[log]))
        with zipfile.ZipFile(output) as archive:
            self.assertEqual(set(archive.namelist()), {'manifest.json', 'environment.json', 'configuration.json', 'plugins.json', 'filesystem.json', 'logs/summary-1.json'})
            for name in archive.namelist():
                text = archive.read(name).decode()
                self.assertNotIn(SECRET, text)
                self.assertNotIn(str(self.root), text)
                json.loads(text)
            summary = json.loads(archive.read('logs/summary-1.json'))
            self.assertEqual(summary['severity_token_counts']['ERROR'], 1)
            self.assertEqual(summary['category_counts']['missing_module'], 1)
        self.assertEqual((self.root / 'conf/local.yml').read_bytes(), before)

    def test_malformed_yaml_and_unavailable_parser_are_safe(self):
        self.write('conf/local.yml', f'password: [{SECRET}\n')
        report = bundle.configuration_report(self.root, 'local')
        self.assertEqual(report['status'], 'unreadable_or_invalid_yaml')
        self.assertNotIn(SECRET, json.dumps(report))
        with patch.dict(sys.modules, {'yaml': None}):
            self.assertEqual(bundle.configuration_report(self.root, 'local')['status'], 'yaml_parser_unavailable')

    def test_missing_config_nonmapping_and_limit(self):
        self.assertEqual(bundle.configuration_report(self.root, 'missing')['status'], 'unreadable_or_invalid_yaml')
        self.write('conf/local.yml', '[]')
        self.assertEqual(bundle.configuration_report(self.root, 'local')['status'], 'invalid_mapping')
        self.write('conf/local.yml', '#' * (bundle.MAX_CONFIG + 1))
        self.assertEqual(bundle.configuration_report(self.root, 'local')['status'], 'too_large')

    def test_numeric_fields_are_bounded_and_booleans_are_rejected(self):
        report = bundle.project_configuration({'port': True, 'ability_refresh': SECRET, 'api_upload_max_size_mb': -1, 'plugins': [SECRET]})
        self.assertEqual(report['numeric_settings'], {})
        self.assertEqual(len(report['invalid_numeric_fields']), 3)
        self.assertNotIn(SECRET, json.dumps(report))

    def test_recursive_or_long_plugin_lists_do_not_leak(self):
        recursive = []
        recursive.append(recursive)
        self.assertEqual(bundle.project_configuration({'plugins': recursive})['known_enabled_plugins'], [])
        report = bundle.project_configuration({'plugins': ['training'] * 65 + [SECRET]})
        self.assertTrue(report['plugin_list_truncated'])
        self.assertEqual(report['known_enabled_plugins'], ['training'])

    def test_log_tail_is_bounded_and_text_is_not_returned(self):
        path = self.write('long.log', 'ERROR old\n' + ' ' * bundle.MAX_LOG + f'WARNING {SECRET}\n')
        report = bundle.log_report(path)
        self.assertTrue(report['tail_truncated'])
        self.assertEqual(report['severity_token_counts']['ERROR'], 0)
        self.assertEqual(report['severity_token_counts']['WARNING'], 1)
        self.assertNotIn(SECRET, json.dumps(report))
        self.assertEqual(bundle.log_report(self.root / 'missing')['status'], 'unreadable')

    def test_custom_metadata_versions_and_host_details_are_not_exported(self):
        bundle.metadata.version.return_value = SECRET
        with patch.object(bundle.platform, 'machine', return_value=SECRET), patch.object(bundle.platform, 'system', return_value=SECRET):
            report = bundle.environment_report(self.root)
        self.assertNotIn(SECRET, json.dumps(report))
        self.assertTrue(all(value is None for value in report['python_packages'].values()))
        bundle.metadata.version.side_effect = bundle.metadata.PackageNotFoundError(SECRET)
        self.assertTrue(all(value is None for value in bundle.environment_report(self.root)['python_packages'].values()))

    def test_version_source_is_not_executed(self):
        self.write('app/version.py', "__version__ = '5.4.0'\nraise AssertionError('must not execute')\n")
        self.assertEqual(bundle.environment_report(self.root)['caldera_version'], '5.4.0')

    def test_preview_writes_no_archive(self):
        before = set(self.root.rglob('*'))
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(bundle.main([]), 0)
        json.loads(output.getvalue())
        self.assertEqual(set(self.root.rglob('*')), before)

    def test_archive_creation_and_existing_file_protection(self):
        path = self.root / 'support.zip'
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(bundle.main(['--output', str(path)]), 0)
        before = path.read_bytes()
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(bundle.main(['--output', str(path)]), 1)
        self.assertEqual(path.read_bytes(), before)
        if os.name == 'posix':
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_missing_directories_are_reported(self):
        entries = bundle.collect(self.root)
        self.assertFalse(entries['filesystem.json']['data']['directory_present'])
        self.assertTrue(entries['filesystem.json']['conf']['directory_present'])

    def test_inaccessible_metadata_does_not_abort_collection_or_echo_paths(self):
        with patch.object(Path, 'is_file', side_effect=PermissionError(SECRET)), patch.object(Path, 'is_dir', side_effect=PermissionError(SECRET)):
            entries = bundle.collect(self.root)
        self.assertIsNone(entries['plugins.json']['training']['entrypoint_present'])
        self.assertIsNone(entries['filesystem.json']['conf']['directory_present'])
        self.assertNotIn(SECRET, json.dumps(entries))

    def test_log_directory_or_fifo_is_not_opened(self):
        self.assertEqual(bundle.log_report(self.root)['status'], 'unreadable')
        if hasattr(os, 'mkfifo'):
            fifo = self.root / 'log-pipe'
            os.mkfifo(fifo)
            self.assertEqual(bundle.log_report(fifo)['status'], 'unreadable')

    def test_invalid_arguments(self):
        for args in (['-E', '../private'], ['--output', 'not-a-zip.txt'], ['--log', 'x'] * 6):
            with self.subTest(args=args), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
                bundle.main(args)
            self.assertEqual(raised.exception.code, 2)

    def test_missing_output_directory(self):
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(bundle.main(['--output', str(self.root / 'missing/support.zip')]), 1)

    def test_standalone_preview_without_site_packages(self):
        result = subprocess.run([sys.executable, '-I', '-S', '-B', bundle.__file__], cwd=self.root,
                                capture_output=True, text=True, timeout=30, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)['configuration.json']['status'], 'yaml_parser_unavailable')


class TestProbes(unittest.TestCase):
    def test_tool_output_is_projected_to_version_only(self):
        result = subprocess.CompletedProcess([], 0, 'v22.23.5\n' + SECRET, SECRET)
        with patch.object(bundle.shutil, 'which', return_value='/private/' + SECRET), patch.object(bundle.subprocess, 'run', return_value=result) as run:
            report = bundle.probe(['node', '--version'], Path('.'), r'\Av?(\d+\.\d+\.\d+)(?=\s|$)')
        self.assertEqual(report['value'], '22.23.5')
        self.assertNotIn(SECRET, json.dumps(report))
        self.assertEqual(run.call_args.kwargs['timeout'], 5)
        self.assertEqual(run.call_args.kwargs['env']['GOTOOLCHAIN'], 'local')

    def test_missing_timeout_and_unrecognized_tools(self):
        with patch.object(bundle.shutil, 'which', return_value=None):
            self.assertEqual(bundle.probe(['node'], Path('.'), 'x')['status'], 'missing')
        for failure in (OSError(SECRET), subprocess.TimeoutExpired(SECRET, 5), subprocess.CompletedProcess([], 1, SECRET, SECRET)):
            kwargs = {'side_effect': failure} if isinstance(failure, Exception) else {'return_value': failure}
            with self.subTest(failure=failure), patch.object(bundle.shutil, 'which', return_value='node'), patch.object(bundle.subprocess, 'run', **kwargs):
                report = bundle.probe(['node'], Path('.'), r'\A(v)')
            self.assertEqual(report['status'], 'unavailable')
            self.assertNotIn(SECRET, json.dumps(report))
