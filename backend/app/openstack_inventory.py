"""Project-scoped Nova/Neutron reads using a reader application credential.

Only the Keystone token exchange uses POST. Inventory uses GET; this module has
no server/port/SG mutation operations. Secrets and upstream errors never leave it.
"""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address
import hashlib
import json
import socket
from threading import Lock
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener
from uuid import UUID

from .proxy_services import unique_object
from .schemas import iso

REFRESH_SECONDS = 15
TTL = 45
MAX_BYTES = 4 * 1024 * 1024
PAGE_SIZE = 200
MAX_RECORDS = 10000


class InventoryError(Exception):
    def __init__(self, code, http_status=None):
        self.code = code
        self.http_status = http_status
        super().__init__(code)


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Transport:
    def __init__(self):
        self.opener = build_opener(ProxyHandler({}), NoRedirect())

    def send(self, method, url, *, body=None, token=None, nova_version=None, revision=None):
        headers = {"Accept": "application/json"}
        if nova_version:
            headers["OpenStack-API-Version"] = "compute " + nova_version
        if token:
            headers["X-Auth-Token"] = token
        if revision is not None:
            headers["If-Match"] = f"revision_number={revision}"
        if body is not None:
            headers["Content-Type"] = "application/json"
        request = Request(url, data=json.dumps(body).encode() if body is not None else None,
                          headers=headers, method=method)
        try:
            with self.opener.open(request, timeout=5) as response:
                raw = response.read(MAX_BYTES + 1)
                if len(raw) > MAX_BYTES:
                    raise InventoryError("OPENSTACK_RESPONSE_TOO_LARGE")
                try:
                    data = json.loads(raw, object_pairs_hook=unique_object)
                except (ValueError, UnicodeError, RecursionError):
                    raise InventoryError("OPENSTACK_RESPONSE_INVALID") from None
                if not isinstance(data, dict):
                    raise InventoryError("OPENSTACK_RESPONSE_INVALID")
                return data, response.headers.get("X-Subject-Token")
        except HTTPError as error:
            # Never include response body/URL/headers in an error message.
            status = error.code
            error.close()
            if status == 401:
                raise InventoryError("OPENSTACK_AUTH_REJECTED", status) from None
            if status == 403:
                raise InventoryError("OPENSTACK_READ_FORBIDDEN", status) from None
            raise InventoryError("OPENSTACK_HTTP_ERROR", status) from None
        except (URLError, OSError, TimeoutError, socket.timeout):
            raise InventoryError("OPENSTACK_CONNECTION_FAILED") from None


def identifier(value):
    if not isinstance(value, str):
        raise InventoryError("OPENSTACK_RESPONSE_INVALID")
    try:
        UUID(value)
    except ValueError:
        raise InventoryError("OPENSTACK_RESPONSE_INVALID") from None
    return value


def text(value, maximum=256):
    if value is None:
        return None
    if not isinstance(value, str) or len(value) > maximum:
        raise InventoryError("OPENSTACK_RESPONSE_INVALID")
    return value


def rows(value):
    if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
        raise InventoryError("OPENSTACK_RESPONSE_INVALID")
    return value


def network_state(ports, quarantine_sg_id):
    if not quarantine_sg_id or not ports or any(
        port["port_security_enabled"] is not True or not port["security_group_ids"]
        for port in ports
    ):
        return "UNKNOWN"
    groups = [port["security_group_ids"] for port in ports]
    if all(ids == [quarantine_sg_id] for ids in groups):
        return "QUARANTINED"
    if any(quarantine_sg_id in ids for ids in groups):
        return "MISMATCH"
    return "NORMAL"


class InventoryReader:
    accepted_roles = (frozenset({"reader"}),)
    role_error_code = "OPENSTACK_READER_SCOPE_REQUIRED"

    def __init__(self, settings, transport=None, clock=None, monotonic=None):
        self.settings = settings
        self.transport = transport or Transport()
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.monotonic = monotonic or time.monotonic
        self.lock = Lock()
        self.token = None
        self.token_expiry = None
        self.cached = None
        self.cached_ports = []
        self.network_classification_configured = False
        self.fingerprint = None
        self.last_attempt = None
        self.last_success = None
        self.last_error = None
        self.retry_after = 0
        self.observation_from = None

    def configured(self):
        cfg = self.settings
        if not cfg.openstack_enabled:
            raise InventoryError("OPENSTACK_NOT_CONFIGURED")
        if cfg.openstack_credential_path is None:
            raise InventoryError("OPENSTACK_CREDENTIAL_NOT_CONFIGURED")
        try:
            identifier(cfg.openstack_project_id)
            for url in (cfg.openstack_auth_url, cfg.openstack_compute_url, cfg.openstack_network_url):
                parsed = urlsplit(url)
                if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
                    raise ValueError("Endpoint")
            if urlsplit(cfg.openstack_auth_url).path.rstrip("/") != "/v3":
                raise ValueError("Keystone v3 required")
        except (ValueError, InventoryError):
            raise InventoryError("OPENSTACK_CONFIGURATION_INVALID") from None

    def authenticate(self):
        now = self.clock()
        if self.token and self.token_expiry and self.token_expiry > now + timedelta(seconds=30):
            return
        try:
            with self.settings.openstack_credential_path.open("rb") as stream:
                raw = stream.read(65537)
            if len(raw) > 65536:
                raise ValueError("Oversized credential")
            value = json.loads(raw.decode("utf-8-sig"), object_pairs_hook=unique_object)
            credential_id, secret = value["id"], value["secret"]
            if not isinstance(credential_id, str) or not credential_id or not isinstance(secret, str) or not 1 <= len(secret) <= 4096:
                raise ValueError("Invalid credential")
            if value.get("project_id") != self.settings.openstack_project_id:
                raise ValueError("Credential scope")
        except OSError:
            raise InventoryError("OPENSTACK_CREDENTIAL_UNAVAILABLE") from None
        except (ValueError, KeyError, TypeError, UnicodeError, RecursionError):
            raise InventoryError("OPENSTACK_CREDENTIAL_INVALID") from None
        payload = {"auth": {"identity": {"methods": ["application_credential"],
                    "application_credential": {"id": credential_id, "secret": secret}}}}
        data, token = self.transport.send("POST", self.settings.openstack_auth_url.rstrip("/") + "/auth/tokens", body=payload)
        try:
            auth = data["token"]
            role_names = {item["name"] for item in auth["roles"]}
            if frozenset(role_names) not in self.accepted_roles or auth["project"]["id"] != self.settings.openstack_project_id:
                raise InventoryError(self.role_error_code)
            expiry = datetime.fromisoformat(auth["expires_at"].replace("Z", "+00:00"))
            if not expiry.tzinfo or expiry <= now + timedelta(seconds=30) or not isinstance(token, str) or not token:
                raise ValueError("Token expiry")
        except (KeyError, TypeError, ValueError):
            raise InventoryError("OPENSTACK_AUTH_RESPONSE_INVALID") from None
        self.token, self.token_expiry = token, expiry

    def get(self, url):
        self.authenticate()
        try:
            return self.transport.send("GET", url, token=self.token)[0]
        except InventoryError as error:
            if error.code != "OPENSTACK_AUTH_REJECTED":
                raise
            self.token = None
            self.authenticate()
            return self.transport.send("GET", url, token=self.token)[0]

    def collection(self, base, path, key, *, project_filter=False, deadline):
        result, seen, marker = [], set(), None
        for _ in range(100):
            if self.monotonic() > deadline:
                raise InventoryError("OPENSTACK_COLLECTION_TIMEOUT")
            params = {"limit": PAGE_SIZE}
            if project_filter:
                params["project_id"] = self.settings.openstack_project_id
            if marker:
                params["marker"] = marker
            data = self.get(base.rstrip("/") + path + "?" + urlencode(params))
            page = rows(data.get(key))
            for item in page:
                row_id = identifier(item.get("id"))
                if row_id in seen:
                    raise InventoryError("OPENSTACK_PAGINATION_INVALID")
                seen.add(row_id)
                result.append(item)
            if len(result) > MAX_RECORDS:
                raise InventoryError("OPENSTACK_COLLECTION_TOO_LARGE")
            links = rows(data.get(key + "_links", []))
            more = any(link.get("rel") == "next" for link in links)
            if not more and len(page) < PAGE_SIZE:
                return result
            if not page:
                raise InventoryError("OPENSTACK_PAGINATION_INVALID")
            # Never follow a server-supplied URL with our token. Only a validated
            # marker is sent to the explicitly configured endpoint.
            marker = page[-1]["id"]
        raise InventoryError("OPENSTACK_COLLECTION_TOO_LARGE")

    def same_project(self, row):
        if row.get("project_id", row.get("tenant_id")) != self.settings.openstack_project_id:
            raise InventoryError("OPENSTACK_PROJECT_SCOPE_MISMATCH")

    def collect(self):
        cfg = self.settings
        deadline = self.monotonic() + 25
        servers = self.collection(cfg.openstack_compute_url, "/servers/detail", "servers", deadline=deadline)
        ports = self.collection(cfg.openstack_network_url, "/v2.0/ports", "ports", project_filter=True, deadline=deadline)
        floating = self.collection(cfg.openstack_network_url, "/v2.0/floatingips", "floatingips", project_filter=True, deadline=deadline)
        groups = self.collection(cfg.openstack_network_url, "/v2.0/security-groups", "security_groups", project_filter=True, deadline=deadline)
        group_names = {group["id"]: text(group.get("name")) for group in groups}
        quarantine_sg_id = next((
            group["id"] for group in groups
            if group["id"].lower() == cfg.openstack_quarantine_sg_id
            and group.get("project_id", group.get("tenant_id")) == cfg.openstack_project_id
        ), None)
        fip_by_port = {}
        for fip in floating:
            self.same_project(fip)
            if fip.get("port_id"):
                port_id = identifier(fip["port_id"])
                address = text(fip.get("floating_ip_address"), 64)
                try:
                    ip_address(address)
                except (ValueError, TypeError):
                    raise InventoryError("OPENSTACK_RESPONSE_INVALID") from None
                fip_by_port.setdefault(port_id, []).append({"floating_ip_address": address})
        by_server = {}
        for port in ports:
            self.same_project(port)
            port_id = port["id"]
            device_id = text(port.get("device_id"))
            fixed = []
            for ip in rows(port.get("fixed_ips")):
                address = text(ip.get("ip_address"), 64)
                try:
                    ip_address(address)
                except (ValueError, TypeError):
                    raise InventoryError("OPENSTACK_RESPONSE_INVALID") from None
                fixed.append({"ip_address": address, "subnet_id": identifier(ip.get("subnet_id"))})
            sg_ids = port.get("security_groups")
            if not isinstance(sg_ids, list) or len(sg_ids) != len(set(sg_ids)):
                raise InventoryError("OPENSTACK_RESPONSE_INVALID")
            sg_ids = [identifier(item) for item in sg_ids]
            security = port.get("port_security_enabled")
            if security is not None and type(security) is not bool:
                raise InventoryError("OPENSTACK_RESPONSE_INVALID")
            mapped = {
                "port_id": port_id, "project_id": cfg.openstack_project_id,
                "device_id": device_id, "device_owner": text(port.get("device_owner")),
                "network_id": identifier(port.get("network_id")), "status": text(port.get("status"), 64),
                "mac_address": text(port.get("mac_address"), 64), "fixed_ips": fixed,
                "floating_ips": fip_by_port.get(port_id, []), "security_group_ids": sg_ids,
                "security_groups": [{"id": item, "name": group_names.get(item)} for item in sg_ids],
                "port_security_enabled": security,
            }
            by_server.setdefault(device_id, []).append(mapped)
        workloads = []
        for server in servers:
            self.same_project(server)
            server_id = server["id"]
            vm_ports = sorted(by_server.get(server_id, []), key=lambda item: item["port_id"])
            state = network_state(vm_ports, quarantine_sg_id)
            workloads.append({
                "server_id": server_id, "name": text(server.get("name")), "project_id": cfg.openstack_project_id,
                "nova_status": text(server.get("status"), 64),
                "compute_host": text(server.get("OS-EXT-SRV-ATTR:host")),
                "role": None, "protected": None, "network_state": state, "network_observation": None,
                "incident_refs": [], "risk_exposure": None,
                "ports": vm_ports,
            })
        # Keep all Neutron ports, including detached/non-compute ports, so an
        # overlapping address cannot appear unique merely because Nova omitted it.
        self.collected_ports = [port for ports in by_server.values() for port in ports]
        workloads.sort(key=lambda item: ((item["name"] or "").casefold(), item["server_id"]))
        return workloads, quarantine_sg_id is not None

    def read(self):
        with self.lock:
            return self._read_locked()

    def refresh_next_read(self):
        with self.lock:
            self.retry_after = 0

    def read_mapping_inventory(self):
        with self.lock:
            items, meta, fingerprint = self._read_locked()
            return items, deepcopy(self.cached_ports), meta, fingerprint

    def _read_locked(self):
        self.configured()
        tick = self.monotonic()
        if tick >= self.retry_after:
            self.last_attempt = self.clock()
            try:
                data, classification_configured = self.collect()
                # Hash source values, not observation timestamps. Identical
                # polls keep cursors valid; membership/state changes invalidate them.
                fingerprint = hashlib.sha256(json.dumps(data, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
                observed = self.clock()
                for vm in data:
                    vm["observed_at"] = iso(observed)
                    if vm["network_state"] != "UNKNOWN":
                        vm["network_observation"] = {
                            "state": vm["network_state"],
                            "verification": "LIVE_NEUTRON_READ",
                            "observed_at": vm["observed_at"],
                        }
                    for port in vm["ports"]:
                        port["observed_at"] = iso(observed)
                self.cached, self.fingerprint = data, fingerprint
                self.network_classification_configured = classification_configured
                self.cached_ports = deepcopy(self.collected_ports)
                self.last_success, self.observation_from, self.last_error = observed, self.last_attempt, None
            except InventoryError as error:
                self.last_error = error.code
            except (ValueError, TypeError, KeyError, AttributeError, RecursionError):
                self.last_error = "OPENSTACK_RESPONSE_INVALID"
            self.retry_after = self.monotonic() + REFRESH_SECONDS
        if self.cached is None:
            raise InventoryError(self.last_error or "OPENSTACK_INVENTORY_UNAVAILABLE")
        now = self.clock()
        stale = bool(self.last_error) or (now - self.observation_from).total_seconds() > TTL
        meta = {
            "source_system": "Nova / Neutron", "source_schema": "openstack-inventory-1",
            "source_mode": "LIVE", "data_state": "CACHED_STALE" if stale else "CURRENT",
            "freshness_state": "STALE" if stale else "FRESH", "stale_after_seconds": TTL,
            "read_at": iso(now), "data_as_of": iso(self.last_success),
            "observed_at": iso(self.last_success), "observation_from": iso(self.observation_from),
            "last_attempt": iso(self.last_attempt), "last_success": iso(self.last_success),
            "last_error_code": self.last_error, "source_ref": "sha256:" + self.fingerprint,
            "project_id": self.settings.openstack_project_id, "refresh_seconds": REFRESH_SECONDS,
            "scope": "SINGLE_PROJECT_READONLY",
            "network_classification": "CONFIGURED" if self.network_classification_configured else "NOT_CONFIGURED",
            "network_stale_after_seconds": TTL,
        }
        return deepcopy(self.cached), meta, self.fingerprint
