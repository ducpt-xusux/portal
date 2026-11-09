"""Publish a bounded local P17 snapshot for a colocated Portal."""

import argparse
import json
import os
from pathlib import Path
import sqlite3
import tempfile

from .p17_snapshot import Snapshot, SnapshotError
from .proxy_export import P17_PATH, read_p17


def refresh(source: Path, output: Path) -> None:
    source = source.resolve(strict=True)
    if output.is_symlink():
        raise ValueError('P17 output must not be a symlink')
    output = output.resolve()
    if source.parent == output.parent or output.suffix != '.json':
        raise ValueError('P17 output must be a JSON file in a separate directory')
    if output.exists() and output.samefile(source):
        raise ValueError('P17 output aliases the source')

    payload = read_p17(source.as_uri().removeprefix('file:'))
    raw = json.dumps(payload, ensure_ascii=False, separators=(',', ':')).encode()
    Snapshot.parse(raw)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=output.parent, prefix='.p17-', delete=False) as handle:
            temporary = Path(handle.name)
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        temporary.replace(output)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=Path(P17_PATH))
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        refresh(args.source, args.output)
    except (OSError, ValueError, sqlite3.Error, SnapshotError) as exc:
        parser.exit(1, f'P17 snapshot refresh failed ({type(exc).__name__}). Last good snapshot preserved.\n')
    print('P17 snapshot refreshed.')


if __name__ == '__main__':
    main()
