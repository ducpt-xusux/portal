"""Opt-in, loopback-only Nova noVNC access; no admin fallback or VM mutations."""
from dataclasses import replace
from threading import Lock
import time
from urllib.parse import parse_qs, urlsplit
from uuid import UUID

from .openstack_inventory import InventoryError, InventoryReader, Transport
from .schemas import utc_now


class ConsoleError(Exception):
    def __init__(self, status, code):
        self.status, self.code = status, code
        super().__init__(code)


class ConsoleIdentity(InventoryReader):
    # A separate credential may delegate member-level console creation. Inventory
    # still accepts only reader. Never accept an admin/service token in this path.
    # Keystone can include the reader role implied by member in a token.
    accepted_roles = (frozenset({"reader"}), frozenset({"member"}), frozenset({"member", "reader"}))
    role_error_code = "CONSOLE_CREDENTIAL_SCOPE_REQUIRED"


def origin(value):
    try:
        parsed = urlsplit(value)
        if (parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username
                or parsed.password or parsed.path not in {"", "/"} or parsed.query or parsed.fragment):
            raise ValueError()
        return parsed.scheme, parsed.hostname.lower(), parsed.port or (443 if parsed.scheme == "https" else 80)
    except (ValueError, TypeError):
        raise ConsoleError(503, "CONSOLE_ORIGIN_INVALID") from None


def validate_console_url(value, allowed_origin):
    try:
        if not isinstance(value, str) or not 1 <= len(value) <= 4096 or any(ord(c) < 33 for c in value) or "\\" in value:
            raise ValueError()
        parsed = urlsplit(value)
        if (parsed.username or parsed.password or parsed.fragment
                or parsed.path not in {"/vnc_lite.html", "/vnc_auto.html", "/vnc.html"}):
            raise ValueError()
        actual = (parsed.scheme, (parsed.hostname or "").lower(), parsed.port or (443 if parsed.scheme == "https" else 80))
        if actual != origin(allowed_origin):
            raise ValueError()
        query = parse_qs(parsed.query, keep_blank_values=True, strict_parsing=True)
        if set(query) == {"path"} and len(query["path"]) == 1:
            websocket = urlsplit(query["path"][0])
            if websocket.scheme or websocket.netloc or websocket.path not in {"", "websockify", "/websockify"} or websocket.fragment:
                raise ValueError()
            query = parse_qs(websocket.query, keep_blank_values=True, strict_parsing=True)
        if set(query) != {"token"} or len(query["token"]) != 1:
            raise ValueError()
        UUID(query["token"][0])
        return value
    except (ValueError, TypeError):
        raise ConsoleError(502, "CONSOLE_URL_REJECTED") from None


class ConsoleService:
    def __init__(self, settings, transport=None, clock=None, monotonic=None):
        self.settings = settings
        self.identity = ConsoleIdentity(replace(settings,
            openstack_credential_path=settings.openstack_console_credential_path or settings.openstack_credential_path),
            transport=transport or Transport(), clock=clock)
        self.lock = Lock()
        self.monotonic = monotonic or time.monotonic
        self.attempts = {}

    def capabilities(self):
        enabled = self.settings.openstack_console_enabled
        if enabled:
            origin(self.settings.openstack_console_origin)
        return {"enabled": enabled, "protocol": "vnc", "type": "novnc",
                "console_origin": self.settings.openstack_console_origin if enabled else None,
                "project_id": self.settings.openstack_project_id,
                "access_mode": "LOOPBACK_ONLY", "permission_verified": False,
                "credential_profile": "DEDICATED_CONSOLE" if self.settings.openstack_console_credential_path else "INVENTORY_READER",
                "reason": None if enabled else "CONSOLE_NOT_CONFIGURED"}

    def create(self, server_id):
        if not self.settings.openstack_console_enabled:
            raise ConsoleError(503, "CONSOLE_NOT_CONFIGURED")
        origin(self.settings.openstack_console_origin)
        try:
            server_id = str(UUID(server_id))
        except (ValueError, TypeError):
            raise ConsoleError(422, "CONSOLE_SERVER_ID_INVALID") from None
        with self.lock:
            now = self.monotonic()
            self.attempts = {key: expiry for key, expiry in self.attempts.items() if expiry > now}
            if server_id in self.attempts or len(self.attempts) >= 8:
                raise ConsoleError(429, "CONSOLE_REQUEST_RATE_LIMITED")
            self.attempts[server_id] = now + 10
            try:
                self.identity.configured()
                base = self.settings.openstack_compute_url.rstrip("/") + "/servers/" + server_id
                # Fresh GET; never authorize from cached inventory or browser data.
                server = self.identity.get(base).get("server")
                if not isinstance(server, dict) or server.get("id") != server_id:
                    raise ConsoleError(502, "CONSOLE_SERVER_RESPONSE_INVALID")
                if server.get("project_id", server.get("tenant_id")) != self.settings.openstack_project_id:
                    raise ConsoleError(403, "CONSOLE_PROJECT_OUTSIDE_SCOPE")
                if server.get("status") != "ACTIVE":
                    raise ConsoleError(409, "CONSOLE_VM_NOT_ACTIVE")
                for attempt in range(2):
                    self.identity.authenticate()
                    try:
                        data, _ = self.identity.transport.send("POST", base + "/remote-consoles",
                            token=self.identity.token, nova_version="2.6",
                            body={"remote_console": {"protocol": "vnc", "type": "novnc"}})
                        break
                    except InventoryError as error:
                        if error.code == "OPENSTACK_AUTH_REJECTED" and attempt == 0:
                            self.identity.token = None
                            continue
                        raise
                remote = data.get("remote_console")
                if not isinstance(remote, dict) or remote.get("protocol") != "vnc" or remote.get("type") != "novnc":
                    raise ConsoleError(502, "CONSOLE_RESPONSE_INVALID")
                url = validate_console_url(remote.get("url"), self.settings.openstack_console_origin)
                return {"server_id": server_id, "project_id": self.settings.openstack_project_id,
                        "protocol": "vnc", "type": "novnc", "url": url,
                        "issued_at": utc_now(), "expires_at": None, "expiry_known": False}
            except InventoryError as error:
                if error.code == "OPENSTACK_READ_FORBIDDEN":
                    raise ConsoleError(403, "CONSOLE_PERMISSION_DENIED") from None
                if error.code == "OPENSTACK_AUTH_REJECTED":
                    raise ConsoleError(503, "CONSOLE_AUTH_REJECTED") from None
                if error.http_status == 404:
                    raise ConsoleError(404, "CONSOLE_VM_NOT_FOUND") from None
                if error.http_status in {400, 409, 501}:
                    raise ConsoleError(409, "CONSOLE_UNAVAILABLE") from None
                raise ConsoleError(503, error.code) from None
