"""Release staging safety tests; fake only the external Go toolchain."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


VERSION = '0.8.0-cloud-preview.35'
SYMBOL = 'github.com/michael-ltm/sshm/internal/commands.Version'


class ReleaseBuilderTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        self.root = Path(self.scratch.name)
        (self.root / 'scripts').mkdir()
        self.script = self.root / 'scripts/build-cloud-clients.py'
        shutil.copyfile(Path(__file__).with_name('build-cloud-clients.py'), self.script)
        self.native = self.root / 'native'
        self.native.mkdir()
        self.output = self.root / 'staged'
        self.public = self.root / 'cloud/public/downloads'
        self.public.mkdir(parents=True)
        (self.public / 'release.json').write_bytes(b'published signed release')
        (self.public / 'sshm-darwin-arm64').write_bytes(b'published executable')
        self.public_before = {p.name: p.read_bytes() for p in self.public.iterdir()}
        for arch in ('amd64', 'arm64'):
            self.native_info(arch)
        tool_dir = self.root / 'tools'
        tool_dir.mkdir()
        go = tool_dir / 'go'
        go.write_text('''#!/usr/bin/env python3
import json, os, pathlib, sys
args = sys.argv[1:]
if args[:3] == ['version', '-m', '-json']:
    print(pathlib.Path(args[3]).read_text())
elif args[0] == 'build':
    if os.environ.get('FAIL_BUILD') == os.environ['GOARCH']:
        sys.exit(1)
    payload = {'os': os.environ['GOOS'], 'arch': os.environ['GOARCH'],
               'cgo': os.environ['CGO_ENABLED'], 'ldflags': args[args.index('-ldflags')+1]}
    pathlib.Path(args[args.index('-o')+1]).write_text(json.dumps(payload))
else:
    sys.exit('unexpected Go command: '+repr(args))
''')
        go.chmod(0o755)
        self.env = dict(os.environ, PATH=str(tool_dir) + os.pathsep + os.environ['PATH'])

    def native_info(self, arch, **overrides):
        settings = {'GOOS': 'darwin', 'GOARCH': arch, 'CGO_ENABLED': '1',
                    '-ldflags': f'-s -w -X {SYMBOL}={VERSION}'}
        settings.update(overrides)
        info = {'GoVersion': 'go1.26.1', 'Path': 'github.com/michael-ltm/sshm/cmd/sshm',
                'Settings': [{'Key': key, 'Value': value} for key, value in settings.items()]}
        (self.native / f'sshm-darwin-{arch}').write_text(json.dumps(info))

    def run_builder(self, *args):
        return subprocess.run([sys.executable, str(self.script), *args], cwd=self.root,
                              env=self.env, capture_output=True, text=True)

    def build(self, *args):
        return self.run_builder('--version', VERSION, '--darwin-dir', str(self.native),
                                '--output', str(self.output), *args)

    def assert_public_unchanged(self):
        self.assertEqual(self.public_before, {p.name: p.read_bytes() for p in self.public.iterdir()})

    def test_requires_explicit_version_and_native_directory(self):
        for args in [(), ('--version', VERSION), ('--darwin-dir', str(self.native))]:
            with self.subTest(args=args):
                result = self.run_builder(*args)
                self.assertNotEqual(result.returncode, 0)
                self.assert_public_unchanged()

    def test_rejects_unsafe_native_metadata_without_publishing(self):
        for bad in [{'CGO_ENABLED': '0'}, {'GOOS': 'linux'}, {'GOARCH': 'amd64'},
                    {'-ldflags': f'-X {SYMBOL}=0.8.0-cloud-preview.34'},
                    {'-ldflags': ''},
                    {'-ldflags': f'-X {SYMBOL}={VERSION} -X {SYMBOL}=wrong'}]:
            with self.subTest(bad=bad):
                self.native_info('arm64', **bad)
                result = self.build()
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(self.output.exists())
                self.assert_public_unchanged()

    def test_refuses_existing_output(self):
        self.output.mkdir()
        sentinel = self.output / 'sshm-linux-amd64'
        sentinel.write_bytes(b'existing release')
        result = self.build()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(sentinel.read_bytes(), b'existing release')
        self.assertEqual(list(self.output.iterdir()), [sentinel])
        self.assert_public_unchanged()

    def test_accepts_empty_optional_go_settings(self):
        # Real `go version -m -json` omits Value for empty optional flags.
        for arch in ('amd64', 'arm64'):
            path = self.native / f'sshm-darwin-{arch}'
            info = json.loads(path.read_text())
            info['Settings'].extend({'Key': key} for key in
                                    ('CGO_CFLAGS', 'CGO_CPPFLAGS', 'CGO_CXXFLAGS', 'CGO_LDFLAGS'))
            path.write_text(json.dumps(info))
        result = self.build()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((self.output / 'SHA256SUMS').is_file())
        self.assert_public_unchanged()

    def test_failed_build_does_not_leave_partial_release(self):
        self.env['FAIL_BUILD'] = 'arm64'
        result = self.build()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.output.exists())
        self.assert_public_unchanged()

    def test_stages_six_assets_with_matching_checksums(self):
        result = self.build()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(self.output.is_dir(), 'requested release directory must be staged')
        self.assertEqual(len(list(self.output.iterdir())), 7)
        for arch in ('amd64', 'arm64'):
            name = f'sshm-darwin-{arch}'
            self.assertEqual((self.output / name).read_bytes(), (self.native / name).read_bytes())
        for system in ('linux', 'windows'):
            for arch in ('amd64', 'arm64'):
                name = f'sshm-{system}-{arch}' + ('.exe' if system == 'windows' else '')
                built = json.loads((self.output / name).read_text())
                self.assertEqual((built['os'], built['arch'], built['cgo']), (system, arch, '0'))
                self.assertIn('-X github.com/michael-ltm/sshm/internal/commands.Version=0.8.0-cloud-preview.35', built['ldflags'])
        for line in (self.output / 'SHA256SUMS').read_text().splitlines():
            digest, name = line.split('  ')
            self.assertEqual(digest, hashlib.sha256((self.output / name).read_bytes()).hexdigest())
        self.assert_public_unchanged()

    def test_default_staging_is_versioned_and_does_not_publish(self):
        result = self.run_builder('--version', VERSION, '--darwin-dir', str(self.native))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((self.root / 'dist/releases' / VERSION / 'SHA256SUMS').is_file())
        self.assert_public_unchanged()

    def test_rejects_version_path_traversal(self):
        result = self.run_builder('--version', '../../escape', '--darwin-dir', str(self.native))
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / 'escape').exists())
        self.assert_public_unchanged()


if __name__ == '__main__':
    unittest.main()
