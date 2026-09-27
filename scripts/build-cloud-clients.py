#!/usr/bin/env python3
"""Stage six release clients, preserving native macOS Keychain support.

Requires native Darwin builds without -trimpath so Go build metadata retains
the commands.Version linker assignment. This script never publishes assets.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import tempfile
from concurrent.futures import ThreadPoolExecutor

ROOT = Path(__file__).resolve().parents[1]
VERSION_SYMBOL = 'github.com/michael-ltm/sshm/internal/commands.Version'


def verify_darwin(path, arch, version):
    result = subprocess.run(['go', 'version', '-m', '-json', str(path)],
                            check=True, capture_output=True, text=True)
    info = json.loads(result.stdout)
    if info.get('Path') != 'github.com/michael-ltm/sshm/cmd/sshm':
        raise ValueError(f'{path.name}: not an SSHM command binary')
    settings = {item['Key']: item['Value'] for item in info.get('Settings', [])}
    for key, expected in [('GOOS', 'darwin'), ('GOARCH', arch), ('CGO_ENABLED', '1')]:
        if settings.get(key) != expected:
            raise ValueError(f'{path.name}: requires {key}={expected}; got {settings.get(key)!r}')
    flags = iter(shlex.split(settings.get('-ldflags', '')))
    versions = []
    for flag in flags:
        if flag == '-X':
            assignment = next(flags, '')
        elif flag.startswith('-X='):
            assignment = flag.removeprefix('-X=')
        else:
            continue
        if assignment.startswith(VERSION_SYMBOL + '='):
            versions.append(assignment.split('=', 1)[1])
    if versions != [version]:
        raise ValueError(f'{path.name}: requires one embedded Version={version} linker assignment; '
                         'build native macOS artifacts without -trimpath')


def stage_release(version, darwin_dir, output):
    if output.exists() or output.is_symlink():
        raise FileExistsError(f'refusing to overwrite existing output: {output}')
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.sshm-release-', dir=output.parent) as scratch:
        staged = Path(scratch) / 'downloads'
        staged.mkdir()
        # Validate the exact copied bytes before building or publishing anything.
        for arch in ('amd64', 'arm64'):
            path = staged / f'sshm-darwin-{arch}'
            shutil.copy2(darwin_dir / path.name, path)
            verify_darwin(path, arch, version)

        def build(target):
            system, arch = target
            name = f'sshm-{system}-{arch}' + ('.exe' if system == 'windows' else '')
            env = dict(os.environ, GOOS=system, GOARCH=arch, CGO_ENABLED='0')
            subprocess.run(['go', 'build', '-trimpath', '-ldflags',
                            f'-s -w -X {VERSION_SYMBOL}={version}',
                            '-o', str(staged / name), './cmd/sshm'], cwd=ROOT, env=env, check=True)

        with ThreadPoolExecutor(max_workers=3) as pool:
            list(pool.map(build, [(system, arch) for system in ('linux', 'windows')
                                 for arch in ('amd64', 'arm64')]))
        sums = [hashlib.sha256(path.read_bytes()).hexdigest() + '  ' + path.name
                for path in sorted(staged.iterdir())]
        (staged / 'SHA256SUMS').write_text('\n'.join(sums) + '\n')
        if output.exists() or output.is_symlink():
            raise FileExistsError(f'refusing to overwrite existing output: {output}')
        staged.rename(output)
    print(f'Staged {version}: six clients and SHA256SUMS in {output}. Sign before publishing.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--version', required=True, help='new, unpublished release version')
    parser.add_argument('--darwin-dir', required=True, type=Path,
                        help='directory with native sshm-darwin-amd64 and sshm-darwin-arm64')
    parser.add_argument('--output', type=Path,
                        help='new staging directory (default: dist/releases/<version>)')
    args = parser.parse_args()
    if not re.fullmatch(r'0\.\d+\.\d+(?:[-.a-z0-9]+)?', args.version):
        parser.error('invalid release version')
    try:
        stage_release(args.version, args.darwin_dir,
                      (args.output or ROOT / 'dist/releases' / args.version).absolute())
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        parser.exit(1, f'error: {error}\n')


if __name__ == '__main__':
    main()
