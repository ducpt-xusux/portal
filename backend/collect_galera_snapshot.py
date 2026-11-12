"""Run once on each Galera VM; print a read-only, timestamped JSON observation."""
from datetime import datetime, timezone
import json
import socket
import subprocess

FIELDS = (
    "wsrep_cluster_status", "wsrep_cluster_size", "wsrep_local_state_comment",
    "wsrep_ready", "wsrep_connected", "wsrep_cluster_state_uuid",
    "wsrep_local_state_uuid", "wsrep_cluster_conf_id",
)


def collect(runner=subprocess.run):
    stamp = lambda: datetime.now(timezone.utc).isoformat()
    result = dict(schema="portal-galera-node-1", source_host=socket.gethostname(),
                  mode="SNAPSHOT", scope="LOCAL_SOCKET_WSREP", attempted_at=stamp(),
                  observed_at=None, read_ok=False, metrics={}, error_code=None)
    query = "SHOW GLOBAL STATUS WHERE Variable_name IN (" + ",".join("'" + key + "'" for key in FIELDS) + ");"
    try:
        process = runner(["sudo", "-n", "mariadb", "--protocol=socket", "--batch",
                          "--skip-column-names", "--connect-timeout=5", "-e", query],
                         capture_output=True, text=True, timeout=10)
        if process.returncode:
            result["error_code"] = "WSREP_READ_FAILED"
        else:
            for line in process.stdout.splitlines():
                key, separator, value = line.partition("\t")
                if not separator or key not in FIELDS or key in result["metrics"] or len(value) > 128:
                    raise ValueError("Unexpected result")
                result["metrics"][key] = value
            result["read_ok"] = set(result["metrics"]) == set(FIELDS)
            if result["read_ok"]:
                result["observed_at"] = stamp()
            else:
                result["error_code"] = "WSREP_FIELDS_MISSING"
    except subprocess.TimeoutExpired:
        result["error_code"] = "WSREP_TIMEOUT"
    except OSError:
        result["error_code"] = "WSREP_CLIENT_UNAVAILABLE"
    except ValueError:
        result.update(metrics={}, error_code="WSREP_RESULT_INVALID")
    result["collected_at"] = stamp()
    return result


if __name__ == "__main__":
    print(json.dumps(collect(), indent=2))
