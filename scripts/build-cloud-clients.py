#!/usr/bin/env python3
"""Build downloadable cloud-preview clients; no credentials or local config included."""
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor

root = Path(__file__).resolve().parents[1]
version = '0.8.0-cloud-preview.33'
out = root / 'dist/cloud-preview'
assets = root / 'cloud/public/downloads'
out.mkdir(parents=True, exist_ok=True)
assets.mkdir(parents=True, exist_ok=True)

def build(target):
    system, arch = target
    name = f'sshm-{system}-{arch}' + ('.exe' if system == 'windows' else '')
    env = dict(os.environ, GOOS=system, GOARCH=arch, CGO_ENABLED='0')
    subprocess.run(['go', 'build', '-trimpath', '-ldflags',
                    f'-s -w -X github.com/michael-ltm/sshm/internal/commands.Version={version}',
                    '-o', str(out / name), './cmd/sshm'], cwd=root, env=env, check=True)
    shutil.copy2(out / name, assets / name)
    return hashlib.sha256((out / name).read_bytes()).hexdigest() + '  ' + name

with ThreadPoolExecutor(max_workers=3) as pool:
    sums = sorted(pool.map(build, [(system, arch) for system in ('darwin', 'linux', 'windows') for arch in ('amd64', 'arm64')]))
for folder in (out, assets):
    (folder / 'SHA256SUMS').write_text('\n'.join(sums) + '\n')
print(f'Built {version}: {len(sums)} clients with SHA-256 manifests.')
