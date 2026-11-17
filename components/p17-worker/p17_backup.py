"""Consistent SQLite backup without stopping P17 worker. Owner-readable only."""
from __future__ import annotations
import argparse,hashlib,os,sqlite3,sys
from pathlib import Path

p=argparse.ArgumentParser()
p.add_argument('--source',default='/var/lib/db-firewall-p17/state.sqlite3')
p.add_argument('--dest',required=True)
a=p.parse_args()
source=Path(a.source);dest=Path(a.dest)
if (not source.is_file() or source.is_symlink() or dest.exists() or dest.is_symlink()
       or dest.parent.is_symlink() or not dest.parent.is_dir()):
    raise SystemExit('P17_BACKUP_STOP_UNSAFE_PATH')
fd=os.open(dest,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
os.close(fd)
try:
    with sqlite3.connect('file:'+str(source)+'?mode=ro',uri=True) as src:
        with sqlite3.connect(str(dest)) as dst:
            src.backup(dst)
            if dst.execute('PRAGMA integrity_check').fetchone()[0]!='ok':
                raise ValueError('P17_BACKUP_INTEGRITY_FAILED')
    os.chmod(dest,0o600)
    print('P17_BACKUP_VERIFIED='+str(dest))
    print('P17_BACKUP_SHA256='+hashlib.sha256(dest.read_bytes()).hexdigest())
except Exception:
    print('P17_BACKUP_STOP_CHECK_DESTINATION',file=sys.stderr)
    raise
