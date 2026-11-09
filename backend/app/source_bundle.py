"""Read-only intake. Reports metadata; never publishes an index or connects upstream."""
import json
from pathlib import Path
import re
from .evidence_models import Summary
from .evidence_registry import (EvidenceError, bounded_path, no_links, read_bytes, load_model,
                                json_bytes, digest, build_index, now)
from .source_bundle_models import SourceBundleManifest, SourceBundleHealth

MAX_FILE = 8 * 1024 * 1024
MAX_TOTAL = 64 * 1024 * 1024
MAX_ROWS = 5000
MAX_JSON = 2 * 1024 * 1024
PROXY_REFS = ['60_CASE_JOIN', 'LIVE_POLICY_PREFLIGHT', 'LIVE_EVENT_LINKAGE', 'POLICY_32', 'PROTOCOL_3',
    'P17_SEVEN_CASES', 'P17_INCIDENT_ALERT', 'P17_DURABLE', 'PACKET_RELAY', 'PRIVACY_SAMPLE',
    'PRIVACY_CANARY', 'PRODUCER_FAULT', 'PROTOCOL_PATCH', 'REAL_AUDIT_SCHEMA', 'FRAMING_TELEMETRY',
    'P16H_P17_CHECKPOINT', 'P16H_RECOVERY', 'PROXY_FAILOVER']
CONTROLLER_REFS = ['GLOBAL_ACTIONS', 'INCIDENT_ACTIONS', 'CONTAINMENT', 'WATCHDOG', 'CYCLE_START', 'HANDLED_INCIDENTS', 'NEUTRON_SNAPSHOT']
REQUIRED_GROUPS = {
    'P16H': ['P16H_RECENT', 'P16H_HEALTH', 'P16H_WIRE_CONTRACT'],
    'PROXY_EVIDENCE': ['PROXY_02P1_MANIFEST', *PROXY_REFS],
    'CONTROLLER_EVIDENCE': ['CONTROLLER_02P2_REPORT', *CONTROLLER_REFS],
    'POLICY_RISK': ['ACTIVE_POLICY_RC5', 'ACTIVE_RISK_RC6'],
    'EVALUATION': ['WORKBOOK', 'CASE_CATALOG', 'CASE_OBSERVED', 'CORRELATION_REPLAY'],
    'G07': ['G07_C1_REPORT'],
    'SYSTEM': ['HA_SUMMARY', 'TLS_SUMMARY', 'PRIVACY_SUMMARY', 'STAGING_SUMMARY'],
    'P19': ['P19_GATE'],
}
SCHEMAS = {'EVIDENCE_SUMMARY_V1': 'portal-sanitized-summary-1', 'P16H_HEALTH_V1': 'portal-p16h-health-1',
           'P16H_LOCAL_IMPORT_V1': 'portal-p16h-import-1'}
FORBIDDEN_KEYS = re.compile(r'(^|_)(raw_sql|raw_query|sql_text|password|passwd|token|secret|private_key|openrc|alert_json|raw_payload|raw_envelope)($|_)', re.I)


def failure(code):
    raise EvidenceError('SOURCE_BUNDLE_' + code)


def local_root(root):
    # Reject network roots before stat/resolve; input is a local operator copy only.
    value = str(root)
    if value.startswith(('\\\\', '//')) or '://' in value:
        failure('LOCAL_ROOT_REQUIRED')
    return Path(root)


def no_secret_fields(value, depth=0):
    if depth > 12:
        failure('DEPTH_LIMIT')
    if isinstance(value, dict):
        for key, child in value.items():
            if FORBIDDEN_KEYS.search(key):
                failure('PRIVATE_FIELDS_REJECTED')
            no_secret_fields(child, depth + 1)
    elif isinstance(value, list):
        for child in value:
            no_secret_fields(child, depth + 1)


def inspect_content(raw, entry, context):
    profile = entry.validation_profile
    if profile == 'WITHHELD':
        return {'schema_check': 'NOT_REVIEWED', 'privacy_check': 'WITHHELD_NOT_EXPOSED', 'record_count': None,
                'limitations': ['HASH_ONLY_NO_CONTENT_OR_VERDICT_VERIFICATION', 'SOURCE_ADAPTER_REQUIRED']}
    if entry.declared_schema != SCHEMAS[profile]:
        failure('DECLARED_SCHEMA_MISMATCH')
    if profile == 'EVIDENCE_SUMMARY_V1':
        summary = load_model(raw, Summary)
        if summary.run_id != entry.source_run_id or summary.execution_mode not in entry.execution_modes:
            failure('SUMMARY_SCOPE_MISMATCH')
        return {'schema_check': 'LOCAL_SCHEMA_CHECKED', 'privacy_check': 'CLOSED_ENUM_SCHEMA_CHECKED', 'record_count': 1,
                'limitations': ['HASH_IS_NOT_TESTCASE_PASS_OR_HUMAN_SIGNOFF']}
    if profile == 'P16H_HEALTH_V1':
        health = load_model(raw, SourceBundleHealth)
        if health.context != context or health.observed_at != entry.data_as_of or health.collected_at != entry.captured_at:
            failure('HEALTH_SCOPE_MISMATCH')
        return {'schema_check': 'LOCAL_SCHEMA_CHECKED', 'privacy_check': 'CLOSED_ENUM_SCHEMA_CHECKED', 'record_count': 1,
                'limitations': ['OFFLINE_HEALTH_PROFILE_NOT_WIRE_CONTRACT', 'HISTORICAL_CAPTURE_NOT_CURRENT_HEALTH']}
    # Local import profile supplied by group A; it is explicitly not a socket protocol.
    from .p16h_normalizer import normalize_line, ImportError as P16HImportError
    rows = raw.splitlines()
    if not rows or len(rows) > MAX_ROWS or any(not row.strip() for row in rows):
        failure('ROW_LIMIT_OR_EMPTY_RECORD')
    identities = set()
    for row in rows:
        value = json.loads(json_bytes(row))
        no_secret_fields(value)
        try:
            normalized = normalize_line(row)
        except (P16HImportError, ValueError, TypeError):
            failure('P16H_LOCAL_PROFILE_INVALID')
        if normalized.get('schema_version') != 'portal-p16h-import-1' or normalized.get('context') != context:
            failure('P16H_SCOPE_MISMATCH')
        source = normalized['source']
        if source.get('source_host') != entry.source_host or source.get('source_run_id') != entry.source_run_id:
            failure('P16H_SCOPE_MISMATCH')
        identity = (normalized['delivery']['stream_id'], normalized['delivery']['envelope']['record']['event_id'])
        if identity in identities:
            failure('P16H_DUPLICATE_STREAM_EVENT')
        identities.add(identity)
    return {'schema_check': 'LOCAL_PROFILE_CHECKED', 'privacy_check': 'CONTENT_WITHHELD_REVIEW_REQUIRED', 'record_count': len(rows),
            'limitations': ['ROW_COUNT_NOT_REQUEST_COUNT', 'OFFLINE_IMPORT_PROFILE_NOT_WIRE_CONTRACT',
                            'MASKED_TEXT_NOT_INDEPENDENTLY_ATTESTED', 'NO_CANONICAL_DATABASE_WRITE']}


def groups(files):
    result = []
    # Never combine host/run populations to claim a complete 18/7-file set.
    scopes = sorted({(f['source_host'], f['source_run_id']) for f in files})
    for group, required in REQUIRED_GROUPS.items():
        populations = []
        for host, run in scopes:
            selected = [f for f in files if f['source_host'] == host and f['source_run_id'] == run and f['source_ref'] in required]
            if selected:
                provided = {f['source_ref'] for f in selected}
                populations.append({'source_host': host, 'source_run_id': run, 'provided_refs': sorted(provided),
                    'missing_refs': [ref for ref in required if ref not in provided],
                    'status': 'RECEIVED_REVIEW_REQUIRED'})
        result.append({'group': group, 'populations': populations, 'status': 'RECEIVED_REVIEW_REQUIRED' if populations else 'NOT_PROVIDED'})
    return result


def inspect_bundle(root, manifest_relative='manifest.json'):
    try:
        root = local_root(root)
        raw_manifest = read_bytes(bounded_path(root, manifest_relative), MAX_JSON)
        manifest_value = json.loads(json_bytes(raw_manifest))
        if not isinstance(manifest_value, dict):
            failure('INVALID_MANIFEST')
        if manifest_value.get('schema_version') == 'portal-evidence-bundle-1':
            # Reuse existing importer validation, intentionally never call publish().
            index = build_index(root, manifest_relative)
            live_runs = {run.run_id for run in index.runs if run.context == 'LIVE'}
            if any(run.upper().startswith('TEST-') for run in live_runs) or any(a.source_system == 'TEST' and a.run_id in live_runs for a in index.artifacts):
                failure('TEST_FIXTURE_CONTEXT_DENIED')
            return {'schema_version': 'n91-source-receipt-1', 'status': 'EVIDENCE_DRY_RUN_VALID',
                    'bundle_manifest_sha256': digest(raw_manifest), 'checked_at': now(),
                    'contexts': sorted({run.context for run in index.runs}), 'artifact_count': len(index.artifacts),
                    'registry_written': False, 'source_modified': False,
                    'limitations': ['EXISTING_EVIDENCE_IMPORTER_DRY_RUN_ONLY', 'NO_REAL_SOURCE_OR_SIGNOFF_ATTESTATION']}
        manifest = load_model(raw_manifest, SourceBundleManifest)
        files, total = [], len(raw_manifest)
        for entry in manifest.files:
            if len(entry.relative_path.split('/')) > 6:
                failure('PATH_DEPTH_LIMIT')
            segments = [part.casefold() for part in entry.relative_path.split('/')]
            if any(part.startswith(('.env', '.secrets', '.aws', 'admin-openrc')) for part in segments) or Path(segments[-1]).suffix in {'.pem', '.key', '.p12', '.pfx', '.sql', '.sqlite', '.sqlite3', '.db'}:
                failure('SENSITIVE_FILE_KIND_DENIED')
            path = bounded_path(root, entry.relative_path)
            raw = read_bytes(path, MAX_FILE)
            total += len(raw)
            if total > MAX_TOTAL:
                failure('TOTAL_SIZE_LIMIT')
            if digest(raw) != entry.sha256 or len(raw) != entry.size_bytes:
                failure('HASH_OR_SIZE_MISMATCH')
            details = inspect_content(raw, entry, manifest.context)
            files.append({'artifact_id': entry.artifact_id, 'filename': path.name, 'source_ref': entry.source_ref,
                'source_host': entry.source_host, 'source_run_id': entry.source_run_id,
                'execution_modes': entry.execution_modes, 'captured_at': entry.model_dump(mode='json')['captured_at'],
                'data_as_of': entry.model_dump(mode='json')['data_as_of'], 'timestamp_basis': entry.timestamp_basis,
                'declared_schema': entry.declared_schema, 'validation_profile': entry.validation_profile,
                'sha256': entry.sha256, 'size_bytes': len(raw), 'integrity': 'BYTE_HASH_MATCH',
                'original_sha256': entry.original_sha256, 'original_hash_verification': 'UNVERIFIED_PRODUCER_CLAIM' if entry.original_sha256 else 'NOT_PROVIDED',
                'transformation': entry.transformation, 'operator_sanitization': entry.operator_sanitization, **details})
        # Detect replacement of manifest after its first read; receipts refer to these exact bytes.
        if read_bytes(bounded_path(root, manifest_relative), MAX_JSON) != raw_manifest:
            failure('MANIFEST_CHANGED')
        return {'schema_version': 'n91-source-receipt-1', 'status': 'TEST_ONLY' if manifest.context == 'TEST' else 'RECEIPT_CHECKED_REVIEW_REQUIRED',
                'bundle_id': manifest.bundle_id, 'context': manifest.context, 'checked_at': now(),
                'bundle_manifest_sha256': digest(raw_manifest), 'artifact_count': len(files), 'files': files,
                'groups': groups(files), 'registry_written': False, 'source_modified': False,
                'adapter_ready': False, 'strict_ready': 'UNKNOWN',
                'limitations': ['NO_AUTOMATIC_IMPORT', 'HASH_IS_NOT_VERDICT_OR_HUMAN_SIGNOFF',
                                'SOURCE_SCHEMA_AND_SEMANTICS_REVIEW_REQUIRED', 'WIRE_CONTRACT_NOT_INFERRED']}
    except (OSError, ValueError, RuntimeError, KeyError, TypeError):
        failure('SOURCE_UNAVAILABLE_OR_INVALID')


def inspect_incoming(incoming):
    """Only one-level operator bundle directories; no recursive scan or raw unmanifested file reads."""
    incoming = local_root(incoming)
    if not incoming.exists():
        return {'status': 'WAITING_FOR_USER_BUNDLE', 'bundles': [], 'registry_written': False}
    try:
        no_links(incoming)
        bundles, pending = [], 0
        for child in sorted(incoming.iterdir()):
            if child.name == 'README.md':
                continue
            if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,79}', child.name):
                pending += 1; continue
            no_links(child)
            if child.is_dir() and (child / 'manifest.json').is_file():
                receipt = inspect_bundle(child)
                bundles.append({'directory': child.name, 'receipt': receipt})
            else:
                pending += 1
        return {'status': 'RECEIPTS_AVAILABLE_REVIEW_REQUIRED' if bundles else 'WAITING_FOR_USER_BUNDLE',
                'bundles': bundles, 'unmanifested_entries_not_read': pending, 'registry_written': False}
    except (OSError, ValueError, RuntimeError):
        failure('INCOMING_UNAVAILABLE')


def inventory_existing(workspace):
    """A narrow list: references and old snapshot are never promoted to fresh source artifacts."""
    workspace = local_root(workspace)
    names = ['N91_PORTAL_DEV_HANDOFF_CHI_TIET_20261108.docx', 'Dữ liệu portal.docx',
             'N91_PORTAL_DAC_TA_TRIEN_KHAI_DAY_DU_V3_20261108.docx',
             'N91_Portal_v4_1_OpenAPI_3_1_Extended_20261105.yaml', 'N91_Portal_v4_1_Dac_ta_DEV_20261105.pdf',
             'N91_MA_TRAN_DEMO_RULE_CASE_PORTAL_V2_20261107.xlsx', 'p17-portal-20261027T152846997946Z.json']
    result = []
    for name in names:
        path = Path(workspace) / name
        if not path.exists():
            result.append({'filename': name, 'status': 'NOT_FOUND'}); continue
        try:
            raw = read_bytes(path, 16 * 1024 * 1024 if path.suffix in ('.docx', '.pdf') else MAX_FILE)
            result.append({'filename': name, 'size_bytes': len(raw), 'sha256': digest(raw),
                'schema': 'FROZEN_OPENAPI_3_1' if name.endswith('.yaml') else 'REFERENCE_DOCUMENT' if path.suffix in ('.docx', '.pdf') else 'NOT_ASSESSED',
                'status': 'REFERENCE_ONLY' if path.suffix in ('.docx', '.pdf', '.yaml') else 'EXISTING_NOT_NEW_BUNDLE_UNASSESSED'})
        except (EvidenceError, OSError, ValueError, RuntimeError):
            result.append({'filename': name, 'status': 'UNAVAILABLE_OR_OVER_LIMIT'})
    return {'schema_version': 'n91-source-inventory-1', 'status': 'NO_SOURCE_ACCEPTANCE_FROM_REFERENCES', 'files': result,
            'limitations': ['NO_CACHE_OR_CREDENTIAL_SCAN', 'OLD_SNAPSHOT_NOT_CURRENT_SOURCE', 'NO_CONTENTS_EXPORTED']}
