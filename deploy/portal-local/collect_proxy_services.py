#!/usr/bin/env python3
"""Observe EXACTLY three local systemd services; write a strict Portal snapshot.

Unprivileged, read-only systemctl show. Never restart/stop anything. No SQL,
network connections, credentials, shell, dynamic unit selection or log scraping.
Output conforms to portal-proxy-services-1 (backend/app/proxy_services.py).
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import tempfile

UNITS = (
    'db-firewall.service',
    'db-firewall-audit.service',
    'db-firewall-p17.service',
)
FIELDS = ('Id', 'LoadState', 'ActiveState', 'SubState', 'MainPID', 'Result')
SCHEMA = 'portal-proxy-services-1'
DEFAULT_OUTPUT = Path('/home/ubuntu/portal-local/.n91-proxy-health/proxy-services.json')


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec='milliseconds')


def one(unit: str, runner=subprocess.run) -> dict:
    if unit not in UNITS:
        raise ValueError('unit not in allowlist')
    attempted = utcnow()
    command = ['/usr/bin/systemctl', 'show', '--no-pager', unit]
    for field in FIELDS:
        command.extend(['-p', field])
    try:
        result = runner(command, capture_output=True, text=True, timeout=4, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {
            'unit': unit, 'attempted_at': attempted, 'observed_at': None,
            'read_ok': False, 'properties': {},
            'error_code': 'SYSTEMCTL_TIMEOUT' if isinstance(exc, subprocess.TimeoutExpired) else 'SYSTEMCTL_UNAVAILABLE',
        }
    values = {}
    if result.returncode == 0 and len(result.stdout) < 4096:
        for line in result.stdout.splitlines():
            field, sep, value = line.partition('=')
            if sep and field in FIELDS and field not in values:
                values[field] = value
    complete = (
        result.returncode == 0 and set(values) == set(FIELDS) and
        values.get('Id') == unit and
        bool(re.fullmatch(r'[0-9]{1,10}', values.get('MainPID', ''))) and
        all(len(values[field]) <= (128 if field == 'Id' else 64) for field in FIELDS)
    )
    return {
        'unit': unit, 'attempted_at': attempted,
        'observed_at': utcnow() if complete else None,
        'read_ok': bool(complete), 'properties': values if complete else {},
        'error_code': None if complete else 'SYSTEMCTL_READ_FAILED',
    }


def collect(runner=subprocess.run) -> dict:
    host = socket.gethostname().split('.')[0]
    if not re.fullmatch(r'[A-Za-z0-9_.:-]{1,128}', host):
        raise RuntimeError('UNSAFE_HOSTNAME')
    rows = [one(unit, runner=runner) for unit in UNITS]
    return {
        'schema': SCHEMA, 'source_host': host, 'collected_at': utcnow(),
        'mode': 'SNAPSHOT', 'scope': 'SYSTEMD_STATUS_ONLY', 'services': rows,
    }


def write_atomic(path: Path, data: dict) -> None:
    if not path.is_absolute() or path.is_symlink() or path.parent.is_symlink():
        raise RuntimeError('UNSAFE_OUTPUT_PATH')
    if not path.parent.is_dir():
        raise RuntimeError('OUTPUT_DIRECTORY_MISSING')
    raw = (json.dumps(data, ensure_ascii=False, separators=(',', ':')) + '\n').encode('utf-8')
    if len(raw) > 65536:
        raise RuntimeError('EXPORT_TOO_LARGE')
    temp = None
    try:
        fd, temp = tempfile.mkstemp(prefix='.proxy-sv-', dir=path.parent)
        with os.fdopen(fd, 'wb') as f:
            os.fchmod(f.fileno(), 0o640)
            f.write(raw)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp, path)
    finally:
        if temp and os.path.exists(temp):
            os.unlink(temp)


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output', type=Path, default=DEFAULT_OUTPUT)
    p.add_argument('--dry-run', action='store_true', help='Print summary, do not write output')
    args = p.parse_args()
    result = collect()
    if not args.dry_run:
        write_atomic(args.output, result)
    summary = []
    for row in result['services']:
        fields = row['properties']
        summary.append(f"{row['unit']}=" + (
            f"{fields['ActiveState']}/{fields['SubState']}/pid{fields['MainPID']}"
            if row['read_ok'] else row['error_code']
        ))
    print('PROXY_SERVICE_OBSERVATION', ' '.join(summary), 'written=' + str(not args.dry_run))


if __name__ == '__main__':
    main()
