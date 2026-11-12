"""Collect one Galera batch on Controller or receive it on Proxy."""
import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import subprocess
import sys
from tempfile import NamedTemporaryFile
from uuid import uuid4


NODES = ("galera-1", "galera-2", "galera-3")


def ssh(target, key, timeout, payload=None):
    return subprocess.run(
        ["ssh", "-T", "-i", str(key), "-o", "BatchMode=yes",
         "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=yes",
         "-o", "ConnectTimeout=4", "--", target],
        input=payload if payload is not None else b"", capture_output=True,
        check=True, timeout=timeout,
    ).stdout


def read_node(node, target, key):
    started = datetime.now(timezone.utc).isoformat()
    try:
        snapshot = json.loads(ssh(target, key, timeout=12))
        if snapshot["source_host"] != node or snapshot["schema"] != "portal-galera-node-1":
            raise ValueError("Unexpected node response")
        return snapshot
    except (OSError, subprocess.SubprocessError, ValueError, KeyError, TypeError):
        print(f"{node}: no valid WSREP response", file=sys.stderr)
        return {
            "schema": "portal-galera-node-1", "source_host": node,
            "mode": "SNAPSHOT", "scope": "LOCAL_SOCKET_WSREP",
            "attempted_at": started, "collected_at": datetime.now(timezone.utc).isoformat(),
            "observed_at": None, "read_ok": False, "metrics": {},
            "error_code": "WSREP_SOURCE_UNREACHABLE",
        }


def collect(key, targets, proxy):
    batch_id = str(uuid4())
    with ThreadPoolExecutor(max_workers=len(NODES)) as pool:
        jobs = [pool.submit(read_node, node, target, key)
                for node, target in zip(NODES, targets, strict=True)]
        snapshots = [job.result() for job in jobs]
    for snapshot in snapshots:
        snapshot["batch_id"] = batch_id
    ssh(proxy, key, timeout=8, payload=json.dumps(snapshots).encode())
    print(f"Published {batch_id}: {sum(item['read_ok'] for item in snapshots)}/{len(NODES)} WSREP reads")


def receive(directory):
    import fcntl
    import os
    from app.galera_snapshot import MAX_BYTES, NodeExport

    raw = sys.stdin.buffer.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ValueError("Oversized Galera batch")
    payload = json.loads(raw)
    if not isinstance(payload, list) or len(payload) != len(NODES):
        raise ValueError("Expected three Galera observations")
    snapshots = [NodeExport.model_validate(item) for item in payload]
    batch_ids = {item.batch_id for item in snapshots}
    latest_allowed = datetime.now(timezone.utc) + timedelta(seconds=5)
    if ({item.source_host for item in snapshots} != set(NODES)
            or len(batch_ids) != 1 or None in batch_ids
            or any(item.collected_at > latest_allowed for item in snapshots)):
        raise ValueError("Invalid Galera batch")

    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    # Lock the directory so overlapping deliveries cannot interleave their files.
    descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        for item in snapshots:
            destination = directory / f"{item.source_host}.json"
            with NamedTemporaryFile(dir=directory, delete=False) as stream:
                temporary = Path(stream.name)
                try:
                    stream.write(item.model_dump_json(by_alias=True).encode() + b"\n")
                    stream.flush()
                    temporary.replace(destination)
                finally:
                    temporary.unlink(missing_ok=True)
    finally:
        os.close(descriptor)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    collector = commands.add_parser("collect")
    collector.add_argument("--key", type=Path, required=True)
    collector.add_argument("--nodes", nargs=len(NODES), required=True)
    collector.add_argument("--proxy", required=True)
    receiver = commands.add_parser("receive")
    receiver.add_argument("directory", type=Path)
    args = parser.parse_args()
    if args.command == "collect":
        collect(args.key, args.nodes, args.proxy)
    else:
        receive(args.directory)


if __name__ == "__main__":
    main()
