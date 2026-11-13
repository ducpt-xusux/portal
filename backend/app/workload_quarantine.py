"""Apply the configured Neutron quarantine SG with a separate member identity."""
from dataclasses import replace
from threading import Lock
from urllib.parse import urlencode

from .openstack_inventory import InventoryError, InventoryReader, identifier, rows


class QuarantineError(Exception):
    def __init__(self, status, code):
        self.status, self.code = status, code
        super().__init__(code)


class QuarantineIdentity(InventoryReader):
    accepted_roles = (frozenset({"member"}), frozenset({"member", "reader"}))
    role_error_code = "QUARANTINE_MEMBER_SCOPE_REQUIRED"


class WorkloadQuarantine:
    def __init__(self, settings, transport=None):
        self.settings = settings
        self.identity = QuarantineIdentity(replace(
            settings, openstack_credential_path=settings.openstack_quarantine_credential_path,
        ), transport=transport)
        self.lock = Lock()

    def configured(self):
        credential = self.settings.openstack_quarantine_credential_path
        return bool(self.settings.openstack_enabled and credential and credential != self.settings.openstack_credential_path
                    and self.settings.openstack_quarantine_sg_id)

    def apply(self, server_id, record_attempt, *, record_verified=None):
        if not self.configured():
            raise QuarantineError(503, "QUARANTINE_NOT_CONFIGURED")
        if not self.lock.acquire(blocking=False):
            raise QuarantineError(409, "QUARANTINE_BUSY")
        try:
            self.identity.configured()
            identifier(server_id)
            return self._apply(server_id, record_attempt, record_verified)
        except InventoryError as error:
            if error.http_status == 412:
                raise QuarantineError(409, "QUARANTINE_CONFLICT") from None
            if error.http_status == 403:
                raise QuarantineError(403, "QUARANTINE_NEUTRON_FORBIDDEN") from None
            if error.http_status == 404:
                raise QuarantineError(404, "QUARANTINE_TARGET_UNAVAILABLE") from None
            raise QuarantineError(503, error.code) from None
        finally:
            self.lock.release()

    def _ports(self, network, server_id):
        query = urlencode({"device_id": server_id, "project_id": self.settings.openstack_project_id,
                           "limit": 9})
        response = self.identity.get(network + "/ports?" + query)
        ports = rows(response.get("ports"))
        if not 1 <= len(ports) <= 8 or response.get("ports_links"):
            raise QuarantineError(409, "QUARANTINE_PORT_SCOPE_UNVERIFIED")
        by_id = {}
        for port in ports:
            port_id = identifier(port.get("id"))
            self._verify_port(port, server_id)
            if port_id in by_id:
                raise QuarantineError(409, "QUARANTINE_PORT_SCOPE_UNVERIFIED")
            by_id[port_id] = port
        return by_id

    def _verify_port(self, port, server_id):
        if (not isinstance(port, dict) or port.get("device_id") != server_id
                or port.get("project_id", port.get("tenant_id")) != self.settings.openstack_project_id
                or not str(port.get("device_owner", "")).startswith("compute:")
                or port.get("port_security_enabled") is not True
                or type(port.get("revision_number")) is not int or port["revision_number"] < 0
                or not isinstance(port.get("security_groups"), list) or not port["security_groups"]):
            raise QuarantineError(409, "QUARANTINE_PORT_SCOPE_UNVERIFIED")
        for group in port["security_groups"]:
            identifier(group)

    def _attachments(self, server_url):
        response = self.identity.get(server_url + "/os-interface")
        attachments = rows(response.get("interfaceAttachments"))
        return {identifier(row.get("port_id")) for row in attachments}

    def _apply(self, server_id, record_attempt, record_verified):
        cfg = self.settings
        compute = cfg.openstack_compute_url.rstrip("/")
        network = cfg.openstack_network_url.rstrip("/") + "/v2.0"
        target = [identifier(cfg.openstack_quarantine_sg_id)]
        server_url = f"{compute}/servers/{server_id}"
        server = self.identity.get(server_url).get("server")
        if not isinstance(server, dict) or server.get("id") != server_id:
            raise QuarantineError(404, "QUARANTINE_TARGET_UNAVAILABLE")
        self.identity.same_project(server)
        extension = self.identity.get(network + "/extensions/revision-if-match").get("extension")
        if not isinstance(extension, dict) or extension.get("alias") != "revision-if-match":
            raise QuarantineError(409, "QUARANTINE_REVISION_UNAVAILABLE")
        group = self.identity.get(f"{network}/security-groups/{target[0]}").get("security_group")
        if (not isinstance(group, dict) or group.get("id") != target[0]
                or group.get("project_id", group.get("tenant_id")) != cfg.openstack_project_id
                or group.get("security_group_rules") != []):
            raise QuarantineError(409, "QUARANTINE_SG_NOT_EMPTY_OR_OUTSIDE_PROJECT")

        ports = self._ports(network, server_id)
        if set(ports) != self._attachments(server_url):
            raise QuarantineError(409, "QUARANTINE_PORT_SCOPE_UNVERIFIED")
        record_attempt([
            {"port_id": port_id, "revision_number": port["revision_number"],
             "security_group_ids": port["security_groups"][:]}
            for port_id, port in ports.items()
        ])
        attempted = {}
        try:
            for port_id, port in ports.items():
                if port["security_groups"] == target:
                    continue
                url = f"{network}/ports/{port_id}"
                attempted[port_id] = port
                try:
                    self._write(url, target, port["revision_number"])
                except InventoryError as error:
                    if error.http_status is not None and 400 <= error.http_status < 500:
                        attempted.pop(port_id)
                    raise
            verified = self._ports(network, server_id)
            observed_at = self.identity.clock()
            if (set(verified) != set(ports) or set(verified) != self._attachments(server_url)
                    or any(port["security_groups"] != target for port in verified.values())):
                raise QuarantineError(409, "QUARANTINE_VERIFICATION_FAILED")
        except (InventoryError, QuarantineError):
            if not self._restore(network, server_id, attempted, target):
                raise QuarantineError(503, "QUARANTINE_RESTORE_UNVERIFIED") from None
            raise
        if record_verified:
            record_verified(observed_at)
        return "QUARANTINED" if attempted else "ALREADY_QUARANTINED"

    def _write(self, url, groups, revision):
        self.identity.authenticate()
        self.identity.transport.send("PUT", url, token=self.identity.token, revision=revision,
                                     body={"port": {"security_groups": groups}})

    def _restore(self, network, server_id, attempted, target):
        complete = True
        for port_id, original in reversed(list(attempted.items())):
            url = f"{network}/ports/{port_id}"
            try:
                current = self.identity.get(url).get("port")
                self._verify_port(current, server_id)
                groups = original["security_groups"]
                if current.get("id") != port_id:
                    complete = False
                elif set(current["security_groups"]) == set(groups):
                    continue
                elif (current["security_groups"] == target
                      and current["revision_number"] == original["revision_number"] + 1):
                    self._write(url, groups, current["revision_number"])
                    restored = self.identity.get(url).get("port")
                    self._verify_port(restored, server_id)
                    complete = complete and restored.get("id") == port_id and set(restored["security_groups"]) == set(groups)
                else:
                    complete = False
            except (InventoryError, QuarantineError):
                complete = False
        return complete
