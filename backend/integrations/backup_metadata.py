"""Create a protected server-local logical backup; print metadata, never SQL data.

This is an operator-run producer, never invoked by the Portal API. Uses existing
Unix-socket DB authorization. Does not create credentials or transfer the backup.
"""
import argparse
from datetime import datetime, timezone
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--schema', required=True)
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--metadata-output', type=Path, required=True)
    args = parser.parse_args()
    if not re.fullmatch(r'[A-Za-z][A-Za-z0-9_]{0,63}', args.schema) or not args.directory.is_absolute():
        raise ValueError('Explicit schema and absolute backup directory required')
    os.umask(0o077)
    args.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    if args.directory.is_symlink() or args.directory.resolve() != args.directory:
        raise ValueError('Backup directory must not contain symlinks')
    os.chmod(args.directory, 0o700)
    started = datetime.now(timezone.utc)
    backup_id = args.schema + '-' + started.strftime('%Y%m%dT%H%M%S%fZ')
    destination = args.directory / (backup_id + '.sql.gz')
    process = subprocess.Popen(['mariadb-dump', '--protocol=socket', '--single-transaction', '--quick',
        '--skip-lock-tables', '--routines', '--events', '--triggers', '--hex-blob', '--no-tablespaces',
        '--databases', args.schema], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    with gzip.open(destination, 'xb') as output:
        shutil.copyfileobj(process.stdout, output)
    process.stdout.close()
    if process.wait(timeout=30) != 0:
        raise RuntimeError('Logical backup failed; archive is not marked valid')
    os.chmod(destination, 0o600)
    digest = hashlib.sha256()
    with destination.open('rb') as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b''):
            digest.update(chunk)
    metadata = {'schema_version':'portal-logical-backup-metadata-1', 'backup_id':backup_id,
        'source_schema':args.schema, 'backup_type':'LOGICAL', 'archive_name':destination.name,
        'created_at':started.isoformat(), 'finished_at':datetime.now(timezone.utc).isoformat(),
        'size_bytes':destination.stat().st_size, 'sha256':digest.hexdigest(), 'compression':'gzip',
        'restore_validated':False, 'scope':'CREATED_AND_HASHED_SERVER_LOCAL_NOT_RESTORE_VALIDATED'}
    args.metadata_output.write_text(json.dumps(metadata, indent=2))
    print(json.dumps(metadata))


if __name__ == '__main__':
    main()
