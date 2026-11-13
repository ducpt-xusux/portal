"""Package a built N91 frontend and backend for Linux."""

import argparse
from datetime import datetime, timezone
from hashlib import sha256
from io import BytesIO
from pathlib import Path
import json
import re
import subprocess
import tarfile


ROOT = Path(__file__).resolve().parents[1]
RELEASE = 'n91-portal-proxy-linux'
DEPLOY_FILES = (
    'README.md', 'install.sh', 'portal.env.example', 'n91-portal.service',
    'n91-portal-p17.service', 'n91-portal-p17.timer', 'n91-portal.nginx.conf',
    'portal-galera.service', 'portal-galera.timer',
)
def bundle_files(web: Path):
    for name in DEPLOY_FILES:
        source = ROOT / 'deploy/proxy' / name
        yield name, source.read_bytes().replace(b'\r\n', b'\n')
    yield 'backend/requirements.txt', (ROOT / 'backend/requirements.txt').read_bytes()
    for name in ('collect_galera_snapshot.py', 'galera_periodic.py'):
        yield f'backend/{name}', (ROOT / 'backend' / name).read_bytes()
    app = ROOT / 'backend/app'
    for path in sorted(app.rglob('*')):
        relative = path.relative_to(app)
        if (path.is_file() and path.suffix in {'.py', '.json', '.sql'}
                and not {'tests', '__pycache__'}.intersection(relative.parts)):
            yield f'backend/app/{relative.as_posix()}', path.read_bytes()

    if not (web / 'index.html').is_file() or not (web / 'assets').is_dir():
        raise ValueError('Build the frontend before packaging')
    for path in sorted(web.rglob('*')):
        if path.is_file():
            relative = path.relative_to(web)
            if any(part.startswith('.') for part in relative.parts) or path.is_symlink():
                raise ValueError('Unexpected hidden file or symlink in web build')
            yield f'web/{relative.as_posix()}', path.read_bytes()


def add(archive, name, raw, release):
    member = tarfile.TarInfo(f'{release}/{name}')
    member.size = len(raw)
    member.mode = 0o755 if name == 'install.sh' else 0o644
    archive.addfile(member, BytesIO(raw))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--web', type=Path, default=ROOT / 'deploy/.proxy-web-build')
    parser.add_argument('--release-name', default=RELEASE)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    if not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,79}', args.release_name):
        parser.error('Invalid release name')
    output = args.output or ROOT / 'deploy' / f'{args.release_name}.tar.gz'
    files = dict(bundle_files(args.web))
    sha = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    dirty = subprocess.check_output(
        ['git', 'status', '--porcelain', '--untracked-files=all', '--', 'backend', 'fe-api-staging', 'deploy/proxy', 'deploy/build_proxy_bundle.py'],
        cwd=ROOT, text=True,
    ).strip()
    web_assets = sorted(name for name in files if name.startswith('web/'))
    fingerprint = lambda names: sha256(json.dumps(
        {name: sha256(files[name]).hexdigest() for name in sorted(names)}, sort_keys=True,
    ).encode()).hexdigest()
    files['backend/portal-build.json'] = (json.dumps({
        'build_sha': None if dirty else sha,
        'build_utc': datetime.now(timezone.utc).isoformat(),
        'backend_release': fingerprint(name for name in files if name.startswith('backend/app/')),
        'frontend_build_sha': fingerprint(web_assets),
        # Populate only after verifying the independently deployed Controller.
        'collector_release': None,
    }, indent=2) + '\n').encode()
    sums = ''.join(f'{sha256(raw).hexdigest()}  {name}\n' for name, raw in sorted(files.items()))
    with output.open('xb') as target, tarfile.open(fileobj=target, mode='w:gz') as archive:
        for name, raw in files.items():
            add(archive, name, raw, args.release_name)
        add(archive, 'SHA256SUMS', sums.encode('ascii'), args.release_name)
    print(f'{output} ({len(files)} inputs with SHA-256)')


if __name__ == '__main__':
    main()
