"""Collect an allowlisted support report; raw configuration/logs stay local."""
import argparse
import hashlib
import io
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import zipfile
from datetime import datetime, timezone
from importlib import metadata
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MAX_CONFIG = 1024 * 1024
MAX_LOG = 1024 * 1024
PLUGINS = ('access', 'atomic', 'builder', 'compass', 'debrief', 'emu', 'fieldmanual', 'gameboard',
           'human', 'magma', 'manx', 'response', 'sandcat', 'ssl', 'stockpile', 'training')
PACKAGES = ('aiohttp', 'aiohttp-apispec', 'aiohttp-jinja2', 'aiohttp-session', 'aiohttp-security',
            'argon2-cffi', 'cryptography', 'jinja2', 'PyYAML', 'marshmallow', 'packaging', 'websockets', 'rich',
            'dirhash', 'marshmallow-enum', 'dnspython', 'asyncssh', 'aioftp', 'croniter', 'setuptools',
            'Markdown', 'reportlab', 'lxml', 'svglib', 'Sphinx', 'sphinx-rtd-theme', 'myst-parser', 'ldap3', 'pyasn1', 'docker')
NUMBERS = {'port': (1, 65535), 'ability_refresh': (1, 2147483647), 'session_expiration_days': (1, 2147483647),
           'client_max_size_mb': (1, 2147483647), 'api_upload_max_size_mb': (1, 2147483647)}
CATEGORIES = {'missing_plugin': 'Problem locating the', 'plugin_import_error': 'Error importing plugin',
              'plugin_enable_error': 'Error enabling plugin', 'ui_missing': 'Magma plugin dist not found',
              'permission_error': 'PermissionError', 'missing_module': 'ModuleNotFoundError',
              'traceback': 'Traceback (most recent call last)'}


def safe_version(value):
    if isinstance(value, str) and re.fullmatch(r'\d+(?:\.\d+){1,3}(?:(?:a|b|rc)\d+)?', value):
        return value
    return None


def present(path, directory=False):
    try:
        return path.is_dir() if directory else path.is_file()
    except OSError:
        return None


def probe(command, root, pattern):
    executable = shutil.which(command[0])
    if executable is None:
        return {'status': 'missing', 'value': None}
    environment = dict(os.environ, GOTOOLCHAIN='local', GOTELEMETRY='off', GIT_OPTIONAL_LOCKS='0')
    for option in ('NODE_OPTIONS', 'NODE_PATH', 'GIT_DIR', 'GIT_WORK_TREE', 'GIT_INDEX_FILE'):
        environment.pop(option, None)
    try:
        result = subprocess.run([executable, *command[1:]], cwd=root, env=environment, stdin=subprocess.DEVNULL,
                                capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=5, check=False)
        match = re.search(pattern, result.stdout) if result.returncode == 0 else None
        return {'status': 'available' if match else 'unavailable', 'value': match.group(1) if match else None}
    except (OSError, subprocess.TimeoutExpired):
        return {'status': 'unavailable', 'value': None}


def environment_report(root):
    packages = {}
    for name in PACKAGES:
        try:
            packages[name] = safe_version(metadata.version(name))
        except (metadata.PackageNotFoundError, OSError, ValueError):
            packages[name] = None
    try:
        version_path = root / 'app/version.py'
        if not present(version_path):
            raise OSError
        with version_path.open('rb') as source:
            version_source = source.read(MAX_CONFIG).decode('utf-8')
        match = re.search(r'^__version__\s*=\s*[\'\"](\d+\.\d+\.\d+)[\'\"]\s*$', version_source, re.MULTILINE)
    except (OSError, UnicodeError):
        match = None
    system = platform.system()
    machine = platform.machine()
    return {'system': system if system in ('Linux', 'Darwin', 'Windows') else 'other',
            'architecture': machine if machine in ('x86_64', 'AMD64', 'aarch64', 'arm64') else 'other',
            'python': safe_version(platform.python_version()), 'virtual_environment': sys.prefix != sys.base_prefix,
            'caldera_version': match.group(1) if match else None, 'python_packages': packages,
            'revision': probe(['git', 'rev-parse', 'HEAD'], root, r'\A([a-f0-9]{40})\s*\Z'),
            'tools': {'node': probe(['node', '--version'], root, r'\Av?(\d+\.\d+\.\d+)(?=\s|$)'),
                      'npm': probe(['npm', '--version'], root, r'\A(\d+\.\d+\.\d+)(?=\s|$)'),
                      'go': probe(['go', 'version'], root, r'\Ago version go(\d+\.\d+(?:\.\d+)?)(?=\s|$)')}}


def numeric_configuration(config):
    report = {'numeric_settings': {}, 'invalid_numeric_fields': []}
    for name, (minimum, maximum) in NUMBERS.items():
        if name not in config:
            continue
        value = config[name]
        if type(value) is int and minimum <= value <= maximum:
            report['numeric_settings'][name] = value
        else:
            report['invalid_numeric_fields'].append(name)
    return report


def plugin_configuration(config):
    report = {}
    plugins = config.get('plugins')
    report['plugins_is_list'] = isinstance(plugins, list)
    report['known_enabled_plugins'] = sorted({name for name in (plugins[:64] if isinstance(plugins, list) else [])
                                             if isinstance(name, str) and name in PLUGINS})
    report['plugin_list_truncated'] = isinstance(plugins, list) and len(plugins) > 64
    return report


def project_configuration(config):
    """Project trusted field names and bounded values, never arbitrary text."""
    report = {'status': 'readable', **numeric_configuration(config), **plugin_configuration(config)}
    host = config.get('host')
    report['host_binding'] = 'loopback' if host in ('localhost', '127.0.0.1', '::1') else 'other_or_unspecified'
    report['credential_fields_present'] = {name: name in config for name in ('api_key_red', 'api_key_blue', 'encryption_key', 'crypt_salt', 'users')}
    return report


def configuration_report(root, environment):
    path = root / 'conf' / f'{environment}.yml'
    fallback = environment == 'local' and present(path) is False
    if fallback:
        path = root / 'conf/default.yml'
    try:
        import yaml
    except ImportError:
        return {'status': 'yaml_parser_unavailable'}
    try:
        if not present(path):
            return {'status': 'unreadable_or_invalid_yaml'}
        with path.open('rb') as source:
            contents = source.read(MAX_CONFIG + 1)
        if len(contents) > MAX_CONFIG:
            return {'status': 'too_large'}
        config = yaml.safe_load(contents.decode('utf-8'))
    except (OSError, ValueError, yaml.YAMLError, RecursionError):
        return {'status': 'unreadable_or_invalid_yaml'}
    if not isinstance(config, dict):
        return {'status': 'invalid_mapping'}
    report = project_configuration(config)
    report['used_default_fallback'] = fallback
    return report


def log_report(path):
    """Summarize a bounded log tail. Neither lines nor filenames leave the host."""
    try:
        if not present(path):
            return {'status': 'unreadable'}
        with path.open('rb') as source:
            size = source.seek(0, os.SEEK_END)
            source.seek(max(0, size - MAX_LOG))
            text = source.read(MAX_LOG).decode('utf-8', errors='replace')
    except OSError:
        return {'status': 'unreadable'}
    levels = {level: len(re.findall(r'\b' + level + r'\b', text)) for level in ('ERROR', 'WARNING', 'INFO', 'DEBUG', 'CRITICAL')}
    return {'status': 'summarized', 'tail_truncated': size > MAX_LOG, 'severity_token_counts': levels,
            'category_counts': {name: text.count(marker) for name, marker in CATEGORIES.items()}}


def collect(root, environment='local', logs=()):
    entries = {'environment.json': environment_report(root), 'configuration.json': configuration_report(root, environment),
               'plugins.json': {name: {'entrypoint_present': present(root / 'plugins' / name / 'hook.py')} for name in PLUGINS}}
    entries['plugins.json']['magma']['built_index_present'] = present(root / 'plugins/magma/dist/index.html')
    entries['filesystem.json'] = {}
    for name in ('conf', 'data', 'data/results', 'data/payloads'):
        entries['filesystem.json'][name] = {'directory_present': present(root / name, directory=True),
                                            'current_process_access': os.access(root / name, os.R_OK | os.W_OK | os.X_OK)}
    for number, path in enumerate(logs, 1):
        entries[f'logs/summary-{number}.json'] = log_report(path)
    entries['manifest.json'] = {'schema_version': 1, 'created_utc': datetime.now(timezone.utc).isoformat(),
                                'privacy': 'Allowlisted metadata and log counts only; no raw source text.',
                                'omitted': ['raw configurations', 'raw logs', 'environment variables', 'usernames', 'hostnames',
                                            'credentials', 'sessions', 'operation data', 'payloads', 'Git remotes', 'unlisted packages']}
    return entries


def write_bundle(output, entries):
    """Create exclusively, requesting mode 0600 on POSIX; never overwrite files."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
        for name, report in entries.items():
            archive.writestr(name, json.dumps(report, indent=2).encode('utf-8'))
    payload = buffer.getvalue()
    descriptor = os.open(output, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(payload)
    except (OSError, ValueError, zipfile.BadZipFile):
        output.unlink(missing_ok=True)
        raise
    return hashlib.sha256(payload).hexdigest()


def main(argv=None):
    parser = argparse.ArgumentParser(description='Preview allowlisted support diagnostics or create a ZIP. Raw logs and configurations are excluded.')
    parser.add_argument('-E', '--environment', default='local', help='Configuration name in conf/ (default local, falling back to default).')
    parser.add_argument('--log', action='append', type=Path, default=[], help='Summarize a log tail; repeat up to five times. Text and filenames are excluded.')
    parser.add_argument('--output', type=Path, help='Create this new .zip file. Without --output, print the report preview as JSON.')
    args = parser.parse_args(argv)
    if not re.fullmatch(r'\w[\w-]*', args.environment, flags=re.ASCII):
        parser.error('environment must be a configuration name, not a path')
    if len(args.log) > 5:
        parser.error('at most five log files may be summarized')
    if args.output and args.output.suffix.lower() != '.zip':
        parser.error('output must have a .zip extension')
    entries = collect(ROOT, args.environment, args.log)
    if args.output is None:
        print(json.dumps(entries, indent=2))
        return 0
    try:
        digest = write_bundle(args.output, entries)
    except OSError:
        print('Cannot create archive. Choose a new filename in an existing writable directory.', file=sys.stderr)
        return 1
    print(f'Created {args.output}; {len(entries)} JSON reports; SHA-256 {digest}. No files were uploaded.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
