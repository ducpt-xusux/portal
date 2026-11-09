"""Package a built N91 frontend, backend  for Linux."""

import argparse
from hashlib import sha256
from io import BytesIO
from pathlib import Path
import tarfile


ROOT = Path(__file__).resolve().parents[1]
RELEASE = 'n91-portal-proxy-linux'
DEPLOY_FILES = (
    'README.md', 'install.sh', 'portal.env.example', 'n91-portal.service',
    'n91-portal-p17.service', 'n91-portal-p17.timer', 'n91-portal.nginx.conf',
)
def bundle_files(web: Path):
    for name in DEPLOY_FILES:
        source = ROOT / 'deploy/proxy' / name
        yield name, source.read_bytes().replace(b'\r\n', b'\n')
    yield 'backend/requirements.txt', (ROOT / 'backend/requirements.txt').read_bytes()
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


def add(archive, name, raw):
    member = tarfile.TarInfo(f'{RELEASE}/{name}')
    member.size = len(raw)
    member.mode = 0o755 if name == 'install.sh' else 0o644
    archive.addfile(member, BytesIO(raw))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--web', type=Path, default=ROOT / 'deploy/.proxy-web-build')
    parser.add_argument('--output', type=Path, default=ROOT / f'deploy/{RELEASE}.tar.gz')
    args = parser.parse_args()
    files = dict(bundle_files(args.web))
    sums = ''.join(f'{sha256(raw).hexdigest()}  {name}\n' for name, raw in sorted(files.items()))
    with args.output.open('xb') as target, tarfile.open(fileobj=target, mode='w:gz') as archive:
        for name, raw in files.items():
            add(archive, name, raw)
        add(archive, 'SHA256SUMS', sums.encode('ascii'))
    print(f'{args.output} ({len(files)} verified inputs)')


if __name__ == '__main__':
    main()
