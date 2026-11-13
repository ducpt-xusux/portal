"""Collect one Galera batch on Controller or receive it on Proxy."""
import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
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
        response = ssh(target, key, timeout=12)
    except (OSError, subprocess.SubprocessError):
        code = "WSREP_SOURCE_UNREACHABLE"
    else:
        try:
            snapshot = json.loads(response)
            if (snapshot["source_host"] != node or snapshot["schema"] != "portal-galera-node-1"
                    or type(snapshot["read_ok"]) is not bool):
                raise ValueError("Unexpected node response")
            return snapshot
        except (ValueError, KeyError, TypeError, RecursionError):
            code = "WSREP_RESULT_INVALID"
    print(f"{node}: {code}", file=sys.stderr)
    return {
        "schema": "portal-galera-node-1", "source_host": node,
        "mode": "SNAPSHOT", "scope": "LOCAL_SOCKET_WSREP",
        "attempted_at": started, "collected_at": datetime.now(timezone.utc).isoformat(),
        "observed_at": None, "read_ok": False, "metrics": {}, "error_code": code,
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
    from app.galera_snapshot import MAX_BYTES, TTL, NodeExport, batch_lock
    from app.proxy_services import unique_object

    raw = sys.stdin.buffer.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ValueError("Oversized Galera batch")
    payload = json.loads(raw, object_pairs_hook=unique_object)
    if not isinstance(payload, list) or len(payload) != len(NODES):
        raise ValueError("Expected three Galera observations")
    snapshots = [NodeExport.model_validate(item) for item in payload]
    batch_ids = {item.batch_id for item in snapshots}
    now = datetime.now(timezone.utc)
    if ({item.source_host for item in snapshots} != set(NODES)
            or len(batch_ids) != 1 or None in batch_ids
            or any(not -5 <= (now - item.collected_at).total_seconds() <= TTL for item in snapshots)):
        raise ValueError("Invalid Galera batch")

    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    with batch_lock(directory, exclusive=True):
        for item in snapshots:
            destination = directory / f"{item.source_host}.json"
            try:
                with destination.open("rb") as stream:
                    previous = NodeExport.model_validate_json(stream.read(MAX_BYTES + 1))
            except (FileNotFoundError, ValueError):
                continue
            if previous.batch_id and (
                    item.batch_id == previous.batch_id or item.collected_at <= previous.collected_at):
                raise ValueError("Replayed or out-of-order Galera batch")
        for item in snapshots:
            destination = directory / f"{item.source_host}.json"
            temporary = None
            try:
                with NamedTemporaryFile(dir=directory, delete=False) as stream:
                    temporary = Path(stream.name)
                    stream.write(item.model_dump_json(by_alias=True).encode() + b"\n")
                temporary.replace(destination)
            finally:
                if temporary is not None:
                    temporary.unlink(missing_ok=True)


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
