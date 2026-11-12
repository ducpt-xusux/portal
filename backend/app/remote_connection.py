"""Bounded, host-key-verified SSH reads through a jump host. No stored passwords."""
from dataclasses import dataclass
from pathlib import Path
import socket
import time

import paramiko


class RemoteError(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class RemoteTarget:
    jump_host: str
    jump_user: str
    proxy_host: str
    proxy_user: str
    known_hosts: Path
    timeout: float = 15


class JumpReader:
    def __init__(self, target, jump_password, proxy_password):
        self.target = target
        self._passwords = (jump_password, proxy_password)
        self._jump = self._proxy = None

    def close(self):
        for client in (self._proxy, self._jump):
            if client is not None:
                client.close()
        self._jump = self._proxy = None

    def _client(self):
        client = paramiko.SSHClient()
        client.load_system_host_keys(str(self.target.known_hosts))
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
        return client

    def connect(self):
        if self._proxy is not None:
            transport = self._proxy.get_transport()
            if transport and transport.is_active():
                return
        self.close()
        target = self.target
        try:
            self._jump = self._client()
            options = dict(timeout=target.timeout, banner_timeout=target.timeout,
                           auth_timeout=target.timeout, allow_agent=False, look_for_keys=False)
            self._jump.connect(target.jump_host, username=target.jump_user,
                               password=self._passwords[0], **options)
            transport = self._jump.get_transport()
            transport.set_keepalive(20)
            channel = transport.open_channel("direct-tcpip", (target.proxy_host, 22),
                                             ("127.0.0.1", 0), timeout=target.timeout)
            self._proxy = self._client()
            self._proxy.connect(target.proxy_host, username=target.proxy_user,
                                password=self._passwords[1], sock=channel, **options)
            self._proxy.get_transport().set_keepalive(20)
        except paramiko.BadHostKeyException:
            self.close()
            raise RemoteError("SSH_HOST_KEY_MISMATCH") from None
        except paramiko.AuthenticationException:
            self.close()
            raise RemoteError("SSH_AUTHENTICATION_FAILED") from None
        except (paramiko.SSHException, OSError, EOFError):
            self.close()
            raise RemoteError("SSH_CONNECTION_FAILED") from None

    def python(self, source, max_bytes=24 * 1024 * 1024):
        self.connect()
        channel = None
        try:
            channel = self._proxy.get_transport().open_session(timeout=self.target.timeout)
            channel.settimeout(self.target.timeout)
            channel.exec_command("python3 -B -")
            channel.sendall(source.encode("utf-8"))
            channel.shutdown_write()
            output = bytearray()
            deadline = time.monotonic() + self.target.timeout
            channel.settimeout(0.2)
            while True:
                if time.monotonic() > deadline:
                    raise RemoteError("SSH_READ_TIMEOUT")
                try:
                    chunk = channel.recv(65536)
                    if not chunk:
                        break  # Read through EOF, even if exit status arrives before the final data.
                    output.extend(chunk)
                    if len(output) > max_bytes:
                        raise RemoteError("SSH_RESPONSE_TOO_LARGE")
                except socket.timeout:
                    pass
                # Drain stderr, but never expose remote text or credentials in logs.
                if channel.recv_stderr_ready():
                    channel.recv_stderr(65536)
            while not channel.exit_status_ready():
                if time.monotonic() > deadline:
                    raise RemoteError("SSH_READ_TIMEOUT")
                time.sleep(0.01)
            if channel.recv_exit_status() != 0:
                raise RemoteError("REMOTE_READ_FAILED")
            return bytes(output)
        except RemoteError:
            # A timed-out channel can leave the SSH transports apparently active
            # but unusable. The next poll must establish a new verified jump and
            # Proxy connection instead of reusing that uncertain connection.
            self.close()
            raise
        except (paramiko.SSHException, OSError, EOFError):
            self.close()
            raise RemoteError("SSH_READ_FAILED") from None
        finally:
            if channel is not None:
                channel.close()


INSPECT_SOURCE = '''import json, os, sqlite3
from pathlib import Path
result = {"uid": os.getuid(), "p17": {}, "audit": {}}
db = sqlite3.connect("file:/var/lib/db-firewall-p17/state.sqlite3?mode=ro", uri=True, timeout=3)
db.execute("PRAGMA query_only=ON")
db.execute("BEGIN")
result["p17"]["tables"] = {table: db.execute("SELECT COUNT(*) FROM " + table).fetchone()[0] for table in ("metadata", "processed_events", "incidents", "outbox")}
result["p17"]["columns"] = {table: [row[1] for row in db.execute("PRAGMA table_info(" + table + ")")] for table in ("metadata", "processed_events", "incidents", "outbox")}
db.rollback()
db.close()
with open("/var/log/db-firewall/audit.jsonl", "rb") as f:
    result["audit"]["bytes"] = os.fstat(f.fileno()).st_size
    line = f.readline(1048577)
    result["audit"]["first_line_complete"] = line.endswith(b"\\n")
    if line and len(line) <= 1048576:
        row = json.loads(line)
        result["audit"]["first_record_keys"] = sorted(row.keys())
        result["audit"]["event_type"] = row.get("event_type")
        result["audit"]["risk_status"] = row.get("risk_status")
print(json.dumps(result))
'''


if __name__ == "__main__":
    import getpass
    import json
    target = RemoteTarget("100.100.10.10", "controller", "192.168.253.20", "ubuntu",
                          Path.home() / ".ssh" / "known_hosts")
    jump_password = getpass.getpass("Controller SSH password: ")
    proxy_password = getpass.getpass("Proxy SSH password: ")
    reader = JumpReader(target, jump_password, proxy_password)
    try:
        print(json.dumps(json.loads(reader.python(INSPECT_SOURCE, max_bytes=65536)), indent=2))
    except RemoteError as exc:
        print(json.dumps({"error": exc.code}))
        raise SystemExit(1)
    finally:
        reader.close()
