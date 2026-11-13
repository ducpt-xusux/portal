from dataclasses import dataclass
from pathlib import Path
import os


ROOT = Path(__file__).resolve().parents[1]


def absolute_path(value: str) -> Path:
    path = Path(value).expanduser()
    return path.resolve() if path.is_absolute() else (ROOT / path).resolve()


def optional_path(name: str) -> Path | None:
    value = os.getenv(name)
    return absolute_path(value) if value else None


@dataclass(frozen=True)
class Settings:
    audit_path: Path
    database_path: Path
    mode: str = "live"
    poll_seconds: float = 5
    cors_origins: tuple[str, ...] = ("http://127.0.0.1:5173", "http://localhost:5173")
    api_key: str = ""
    p17_snapshot_path: Path | None = None
    p17_local_readonly: bool = False
    proxy_sync_status_path: Path | None = None
    v4_audit_enabled: bool = False
    proxy_services_path: Path | None = None
    galera_snapshot_dir: Path | None = None
    build_manifest_path: Path | None = None
    openstack_enabled: bool = False
    openstack_credential_path: Path | None = None
    openstack_auth_url: str = ""
    openstack_compute_url: str = ""
    openstack_network_url: str = ""
    openstack_project_id: str = ""
    openstack_quarantine_sg_id: str = ""
    openstack_quarantine_credential_path: Path | None = None
    openstack_console_enabled: bool = False
    openstack_console_origin: str = ""
    openstack_console_credential_path: Path | None = None
    evaluation_index_path: Path | None = None
    p16h_import_context: str | None = None
    evidence_index_path: Path | None = None
    evidence_local_readonly: bool = False
    session_auth_enabled: bool = False
    business_database_path: Path | None = None
    session_local_http: bool = False
    investigation_policy_path: Path | None = None
    investigation_policy_sha256: str = ""
    investigation_policy_version: str = ""
    investigation_controller_path: Path | None = None
    investigation_controller_sha256: str = ""
    evaluation_observations_path: Path | None = None
    evaluation_observations_sha256: str = ""
    system_observations_path: Path | None = None
    system_observations_sha256: str = ""
    evaluation_source_context: str = "EVALUATION"
    defense_source_registry_path: Path | None = None
    defense_archive_dir: Path | None = None
    investigation_controller_archive_path: Path | None = None
    investigation_controller_binding_path: Path | None = None
    investigation_controller_binding_sha256: str = ""

    def __post_init__(self):
        if self.defense_source_registry_path is not None:
            protected_paths = (
                self.audit_path, self.database_path, self.p17_snapshot_path,
                self.evidence_index_path, self.evaluation_index_path, self.business_database_path,
                self.openstack_credential_path, self.openstack_console_credential_path,
                self.openstack_quarantine_credential_path,
                self.proxy_sync_status_path, self.proxy_services_path,
                self.investigation_policy_path, self.investigation_controller_path,
                self.investigation_controller_archive_path, self.investigation_controller_binding_path,
                self.evaluation_observations_path, self.system_observations_path,
            )
            registry = self.defense_source_registry_path.resolve()
            for source in protected_paths:
                if source is not None and (
                    registry == source.resolve()
                    or registry.is_file() and source.is_file() and registry.samefile(source)
                ):
                    raise ValueError("Defense source registry must use a dedicated metadata file")
        if self.evidence_index_path and self.evidence_index_path.resolve() in {
            path.resolve() for path in (self.audit_path, self.database_path, self.p17_snapshot_path, self.evaluation_index_path) if path
        }:
            raise ValueError("Evidence index must use a dedicated metadata registry")
        if self.p16h_import_context not in {None, "TEST", "EVALUATION", "IMPORTED_UNVERIFIED"}:
            raise ValueError("Invalid P16H import context")
        if self.p16h_import_context in {"TEST", "EVALUATION"} and self.mode != "snapshot":
            raise ValueError("Test/evaluation P16H imports require a separate snapshot store")
        if self.mode not in {"live", "snapshot"}:
            raise ValueError("AUDIT_MODE must be live or snapshot")
        if not 0.1 <= self.poll_seconds <= 3600:
            raise ValueError("AUDIT_POLL_SECONDS must be between 0.1 and 3600")
        if self.audit_path.resolve() == self.database_path.resolve():
            raise ValueError("Database and audit source must be different files")
        if self.p17_snapshot_path and self.p17_snapshot_path.resolve() in {
            self.audit_path.resolve(), self.database_path.resolve()
        }:
            raise ValueError("P17 snapshot must be a separate read-only JSON source")

    @classmethod
    def from_env(cls):
        return cls(
            audit_path=absolute_path(os.getenv("AUDIT_PATH", "/var/log/db-firewall/audit.jsonl")),
            database_path=absolute_path(os.getenv("DATABASE_PATH", "data/portal.sqlite3")),
            mode=os.getenv("AUDIT_MODE", "live"),
            poll_seconds=float(os.getenv("AUDIT_POLL_SECONDS", "5")),
            cors_origins=tuple(x.strip() for x in os.getenv(
                "CORS_ORIGINS", "http://127.0.0.1:5173,http://localhost:5173"
            ).split(",") if x.strip()),
            api_key=os.getenv("PORTAL_API_KEY", ""),
            p17_snapshot_path=absolute_path(os.environ["P17_SNAPSHOT_PATH"]) if os.getenv("P17_SNAPSHOT_PATH") else None,
            p17_local_readonly=os.getenv("P17_LOCAL_READONLY", "false").lower() == "true",
            proxy_sync_status_path=absolute_path(os.environ["PROXY_SYNC_STATUS_PATH"]) if os.getenv("PROXY_SYNC_STATUS_PATH") else None,
            v4_audit_enabled=os.getenv("V4_AUDIT_ENABLED", "false").lower() == "true",
            proxy_services_path=absolute_path(os.environ["PROXY_SERVICES_PATH"]) if os.getenv("PROXY_SERVICES_PATH") else None,
            galera_snapshot_dir=absolute_path(os.environ["GALERA_SNAPSHOT_DIR"]) if os.getenv("GALERA_SNAPSHOT_DIR") else None,
            build_manifest_path=optional_path("PORTAL_BUILD_MANIFEST"),
            openstack_enabled=os.getenv("OPENSTACK_INVENTORY_ENABLED", "false").lower() == "true",
            openstack_credential_path=absolute_path(os.environ["OPENSTACK_CREDENTIAL_PATH"]) if os.getenv("OPENSTACK_CREDENTIAL_PATH") else None,
            openstack_auth_url=os.getenv("OPENSTACK_AUTH_URL", ""),
            openstack_compute_url=os.getenv("OPENSTACK_COMPUTE_URL", ""),
            openstack_network_url=os.getenv("OPENSTACK_NETWORK_URL", ""),
            openstack_project_id=os.getenv("OPENSTACK_PROJECT_ID", ""),
            openstack_quarantine_sg_id=os.getenv("OPENSTACK_QUARANTINE_SG_ID", "").strip().lower(),
            openstack_quarantine_credential_path=optional_path("OPENSTACK_QUARANTINE_CREDENTIAL_PATH"),
            openstack_console_enabled=os.getenv("OPENSTACK_CONSOLE_ENABLED", "false").lower() == "true",
            openstack_console_origin=os.getenv("OPENSTACK_CONSOLE_ORIGIN", ""),
            openstack_console_credential_path=absolute_path(os.environ["OPENSTACK_CONSOLE_CREDENTIAL_PATH"]) if os.getenv("OPENSTACK_CONSOLE_CREDENTIAL_PATH") else None,
            evaluation_index_path=absolute_path(os.environ["PORTAL_EVALUATION_INDEX"]) if os.getenv("PORTAL_EVALUATION_INDEX") else None,
            p16h_import_context=os.getenv("P16H_IMPORT_CONTEXT") or None,
            evidence_index_path=absolute_path(os.environ["PORTAL_EVIDENCE_INDEX"]) if os.getenv("PORTAL_EVIDENCE_INDEX") else None,
            evidence_local_readonly=os.getenv("PORTAL_EVIDENCE_LOCAL_READONLY", "false").lower() == "true",
            session_auth_enabled=os.getenv("PORTAL_SESSION_AUTH", "false").lower() == "true",
            business_database_path=optional_path("PORTAL_BUSINESS_DATABASE"),
            session_local_http=os.getenv("PORTAL_SESSION_LOCAL_HTTP", "false").lower() == "true",
            investigation_policy_path=optional_path("PORTAL_INVESTIGATION_POLICY"),
            investigation_policy_sha256=os.getenv("PORTAL_INVESTIGATION_POLICY_SHA256", ""),
            investigation_policy_version=os.getenv("PORTAL_INVESTIGATION_POLICY_VERSION", ""),
            investigation_controller_path=optional_path("PORTAL_INVESTIGATION_CONTROLLER"),
            investigation_controller_sha256=os.getenv("PORTAL_INVESTIGATION_CONTROLLER_SHA256", ""),
            evaluation_observations_path=optional_path("PORTAL_EVALUATION_OBSERVATIONS"),
            evaluation_observations_sha256=os.getenv("PORTAL_EVALUATION_OBSERVATIONS_SHA256", ""),
            system_observations_path=optional_path("PORTAL_SYSTEM_OBSERVATIONS"),
            system_observations_sha256=os.getenv("PORTAL_SYSTEM_OBSERVATIONS_SHA256", ""),
            evaluation_source_context=os.getenv("PORTAL_EVALUATION_SOURCE_CONTEXT", "EVALUATION"),
            defense_source_registry_path=optional_path("PORTAL_DEFENSE_SOURCE_REGISTRY"),
            defense_archive_dir=optional_path("PORTAL_DEFENSE_ARCHIVE_DIR"),
            investigation_controller_archive_path=optional_path("PORTAL_INVESTIGATION_CONTROLLER_ARCHIVE"),
            investigation_controller_binding_path=optional_path("PORTAL_INVESTIGATION_CONTROLLER_BINDING"),
            investigation_controller_binding_sha256=os.getenv("PORTAL_INVESTIGATION_CONTROLLER_BINDING_SHA256", ""),
        )
