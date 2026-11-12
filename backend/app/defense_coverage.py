"""Read-only projections of reviewed 07D formats, tied to the P0-01 receipt."""
from datetime import datetime
from ipaddress import ip_address
import json
import re

from .defense_bundle import DefenseBundleError, DefenseRegistry, verified_archive_artifacts
from .demo_coverage import CATALOG
from .evidence_registry import EvidenceError, json_bytes
from .n91_investigation.models import SourceStamp
from .n91_investigation.response_history import project_cycle
from .n91_investigation.sources import SourceError
from .schemas import iso


def values(text, key):
    return [value.strip() for value in re.findall(
        rf'^[ \t]*{re.escape(key)}[ \t]*=[ \t]*([^\r\n]+)', text, re.MULTILINE)]


def one(text, key):
    found = values(text, key)
    require(len(found) == 1)
    return found[0]


def require(condition):
    if not condition:
        raise ValueError('Unsupported evidence projection')


def stamp(value):
    require(isinstance(value, str) and len(value) <= 40 and 'T' in value)
    at = datetime.fromisoformat(value.replace('Z', '+00:00'))
    require(at.utcoffset() is not None)
    return at


def numbers(data, *keys):
    result = [data[key] for key in keys]
    require(all(type(value) is int and 0 <= value <= 100000 for value in result))
    return result


def evidence_ref(artifact):
    return {
        'evidence_id': artifact.artifact_id, 'host': artifact.source_host, 'label': artifact.label,
        'sha256': artifact.sha256, 'size_bytes': artifact.size_bytes, 'origin_mode': artifact.origin_mode,
        'scope': artifact.scope, 'manifest_created_at': artifact.manifest_created_at,
        'raw_download_allowed': False,
    }


def defense_coverage(registry_path, archive_dir):
    registry, receipt_sha = DefenseRegistry(registry_path).read()
    archives, unavailable = {}, []
    for receipt in registry.archives:
        host = receipt.source_host
        try:
            archives[host] = verified_archive_artifacts(archive_dir / f'07D_bundle_{host}.tar.gz', registry, host)
        except DefenseBundleError:
            unavailable.append(host)

    available = {(host, label): entry for host, (_, artifacts) in archives.items()
                 for label, entry in artifacts.items()}
    rows = {entry['scenario_id']: {
        'scene_id': entry['scenario_id'], 'status': 'UNAVAILABLE', 'outcome': None,
        'observed_at': None, 'evidence': [], 'metrics': {}, 'reason': 'OBSERVATION_NOT_AVAILABLE',
    } for entry in CATALOG}

    def text(host, label):
        return available[host, label][1].decode('utf-8', 'strict')

    def document(host, label):
        return json.loads(json_bytes(available[host, label][1]))

    def set_scene(scene, outcome, refs, at=None, *, status='OBSERVED_LIMITED', reason=None, **metrics):
        evidence = [evidence_ref(available[ref][0]) for ref in refs]
        rows[scene].update(status=status, outcome=outcome, evidence=evidence,
                           observed_at=iso(at) if at is not None else None, metrics=metrics, reason=reason)

    def topology():
        proxy = ('proxy', 'PROXY_PREFLIGHT')
        observed = text(*proxy)
        require(one(observed, 'RUN_ID') == registry.run_id)
        nodes = [(host, 'GALERA_HEALTH') for host in ('galera-1', 'galera-2', 'galera-3')
                 if (host, 'GALERA_HEALTH') in available and one(text(host, 'GALERA_HEALTH'), 'HOST') == host]
        set_scene('SC-01', 'PREFLIGHT_OBSERVED', [proxy, *nodes], stamp(one(observed, 'UTC')),
                  status='PARTIAL', reason='PREFLIGHT_ONLY', node_observations=len(nodes))

    def policy(scene, client_ref, proxy_ref, marker, decision):
        client, proxy = text(*client_ref), text(*proxy_ref)
        require(one(client, 'RUN_ID') == one(proxy, 'RUN_ID') == registry.run_id)
        require(one(client, marker) == 'PASS' and decision in values(proxy, 'POLICY_DECISION'))
        if decision == 'BLOCK':
            require(any('CTX-006' in rule for rule in values(proxy, 'MATCHED_RULES')))
        set_scene(scene, decision, [client_ref, proxy_ref], stamp(one(client, 'UTC')),
                  reason='SOURCE_REPORTED_OBSERVATION')

    def correlation():
        audit_ref = ('proxy', 'NEW_CORR002_AUDIT')
        audit = text(*audit_ref)
        manifest = archives['proxy'][0]
        require(one(audit, 'INCIDENT_ID') == manifest.incident_id and one(audit, 'CORRELATION') == 'CORR-002')
        require(one(audit, 'LINK_TYPE') == 'RECONSTRUCTED_WINDOW' and one(audit, 'DIRECT_MEMBERSHIP') == 'NOT_ASSUMED')
        _, candidates = audit.split('===== CORRELATION CANDIDATES =====', 1)
        candidates, canonical = candidates.split('===== P16H CANONICAL AUDIT =====', 1)
        events, requests = values(candidates, 'EVENT_ID'), values(candidates, 'REQUEST_ID')
        for identities in (events, requests):
            require(len(set(identities)) == len(identities) == 3 and all(re.fullmatch(
                r'[a-fA-F0-9]{8}(?:-[a-fA-F0-9]{4}){3}-[a-fA-F0-9]{12}', value) for value in identities))
        require(sorted(events) == sorted(values(canonical, 'EVENT_ID')))
        sequences = [int(value) for value in values(candidates, 'EVENT_SEQ')]
        require(len(sequences) == len(set(sequences)) == 3 and sequences == manifest.event_sequences)
        at = [stamp(value) for value in values(candidates, 'UTC')]
        require(len(at) == 3 and sorted(at) == at and len(set(at)) == 3)
        span = round((at[-1] - at[0]).total_seconds(), 6)
        require(one(audit, 'DISTINCT_REQUEST_IDS') == '3' and 0 < span <= 60)
        require(one(audit, 'EVIDENCE_COUNT') == '3' and values(canonical, 'ACTION') == ['BLOCK'] * 3)
        set_scene('SC-04', 'BLOCK', [audit_ref], at[0],
                  reason='EVENT_IN_RECONSTRUCTED_WINDOW', event_sequences=sequences[:1])
        set_scene('SC-05', 'CORR002_CANDIDATES', [audit_ref], at[-1],
                  reason='RECONSTRUCTED_WINDOW', event_sequences=sequences, window_seconds=span)
        if values(canonical, 'MASK') == ['MASKED'] * 3 and one(audit, 'RAW_SQL_PRINTED') == 'NO':
            refs = [audit_ref]
            isolated_ref = ('proxy', 'F02_AUDIT_ISOLATED')
            metrics = {'masked_events': 3}
            if isolated_ref in available:
                isolated = document(*isolated_ref)
                passed, total = numbers(isolated, 'passed', 'total')
                if isolated.get('f02_real_audit_schema') == 'OFFLINE_PASS' and passed <= total:
                    refs.append(isolated_ref)
                    metrics.update(isolated_pass=passed, isolated_total=total)
            set_scene('SC-12', 'AUDIT_MASKED', refs, at[-1], reason='MASKED_SAMPLE_ONLY', **metrics)

    def controller_cycle():
        ref = ('controller', 'CONTAINMENT')
        artifact, raw = available[ref]
        manifest, records = archives['controller']
        require(artifact.scope == 'LAB')
        source = SourceStamp(source_system='CONTROLLER', source_ref=artifact.artifact_id,
                             source_sha256=artifact.sha256, source_schema=artifact.source_schema,
                             execution_mode='TEST' if registry.run_context == 'TEST' else 'HISTORICAL')
        cycle, _ = project_cycle(raw, records, source)
        detail = cycle.containment
        require(cycle.incident_id == manifest.incident_id)
        applied, restored = detail.quarantined_at_utc, detail.restored_at_utc
        require(applied is not None and restored is not None and applied < restored)
        return ref, cycle, applied, restored

    def quarantine():
        ref, _, applied, restored = controller_cycle()
        tcp_ref = ('p17-lab-clone', 'CLONE_TCP')
        probe = text(*tcp_ref)
        require(ip_address(one(probe, 'SOURCE_IP')) == ip_address(document(*ref)['source_ip']))
        timeouts = re.findall(r'^SAMPLE=\d+ UTC=(\S+) RESULT=TCP_TIMEOUT\s*$', probe, re.MULTILINE)
        count = sum(applied <= stamp(value) < restored for value in timeouts)
        require(count > 0 and one(probe, 'SQL_SENT') == 'NO')
        set_scene('SC-07', 'LAB_QUARANTINE', [ref, tcp_ref], applied,
                  reason='CONTROLLER_RECORDED_LAB', tcp_timeouts=count)

    def restore():
        ref, cycle, applied, restored = controller_cycle()
        detail = cycle.containment
        verified_ref = ('controller', 'RESTORE_VERIFICATION')
        verification = text(*verified_ref)
        require(one(verification, 'RUN_ID') == registry.run_id and one(verification, 'INCIDENT_ID') == cycle.incident_id)
        before, after = (next(item for item in cycle.snapshots if item.phase == phase)
                         for phase in ('BEFORE', 'AFTER'))
        require(detail.status == 'RESTORED' and detail.original_sgs and
                set(before.security_group_ids) == set(after.security_group_ids) == set(detail.original_sgs))
        require(one(verification, 'CLONE_ORIGINAL_SGS_RESTORED') == 'PASS')
        canary_ref = ('app', 'APP_CANARY')
        canary = text(*canary_ref)
        passing = re.findall(r'^SAMPLE=\d+ UTC=(\S+) RESULT=PASS BACKEND=galera-[123]\s*$', canary, re.MULTILINE)
        during = sum(applied <= stamp(value) < restored for value in passing)
        require(during > 0)
        set_scene('SC-08', 'LAB_RESTORE', [ref, verified_ref, ('controller', 'CLONE_BEFORE'),
                  ('controller', 'CLONE_AFTER'), canary_ref], restored,
                  reason='CONTROLLER_RECORDED_LAB', duration_seconds=(restored - applied).total_seconds(),
                  during_canary_pass=during)

    def fixtures():
        ref = ('proxy', 'SIXTY_FIXTURES')
        fixture = available[ref][0].fixture_catalog
        require(fixture is not None)
        set_scene('SC-10', 'FIXTURES_PENDING', [ref], status='NOT_EXECUTED',
                  reason='FIXTURE_CATALOG_ONLY', **fixture.model_dump())

    def transport():
        tls_ref, ha_ref, app_ref = ('proxy', 'TWO_LEG_TLS'), ('proxy', 'BACKEND_HA_ISOLATED'), ('app', 'APP_AVAILABILITY')
        tls, ha = text(*tls_ref), document(*ha_ref)
        require(one(tls, 'FRONTEND_TLS') == one(tls, 'BACKEND_TLS') == 'PASS')
        front = int(one(tls, 'FRONTEND_TLS_SESSIONS'))
        back = int(one(tls, 'BACKEND_TLS_SESSIONS'))
        passed, total = numbers(ha, 'pass', 'total')
        require(0 < front <= 100000 and 0 < back <= 100000 and passed <= total)
        node_failure_unexecuted = app_ref in available and one(text(*app_ref), 'GALERA_NODE_FAILURE_TEST') == 'NOT_EXECUTED'
        set_scene('SC-13', 'TLS_HA_SAMPLES', [tls_ref, ha_ref, *([app_ref] if node_failure_unexecuted else [])],
                  status='PARTIAL', reason='NODE_FAILURE_NOT_EXECUTED' if node_failure_unexecuted else 'NODE_FAILURE_UNAVAILABLE',
                  frontend_sessions=front, backend_sessions=back, isolated_pass=passed, isolated_total=total)

    def recovery():
        ref = ('g07-restore-c1', 'G07_SOURCE_REPORT')
        report = document(*ref)
        require(report['scope'] == 'ISOLATED_MARIADB_DB_SERVICE_ONLY'
                and report['production_rpo_measured'] is False and report['g07_03_strict_acceptance'] == 'REVIEW_REQUIRED')
        rpo, rto = (report[f'lab_{key}_seconds'] for key in (
            'rpo_last_recoverable_commit_to_fault', 'rto_fault_to_recovered_query'))
        require(all(type(value) in (int, float) and 0 <= value <= 86400 for value in (rpo, rto)))
        set_scene('SC-14', 'ISOLATED_RECOVERY', [ref], stamp(report['recovery_query_verified_utc']),
                  reason='LAB_SCOPE_ONLY', rpo_seconds=rpo, rto_seconds=rto)

    def protocol():
        ref = ('proxy', 'F01_F02_STAGING')
        report = document(*ref)
        require(report['scope'] == 'STAGED_SOURCE_AST_ONLY_NO_LIVE_IMPORT' and report['production_patch_applied'] is False)
        counts = numbers(report, 'core_pass', 'probe_pass', 'framing_pass')
        set_scene('SC-15', 'STAGING_REGRESSION', [ref], reason='STAGING_SCOPE_ONLY', staging_pass=sum(counts))

    for project in (
        topology,
        lambda: policy('SC-02', ('app', 'APP_SQL'), ('proxy', 'APP_ALLOW_AUDIT'), 'SCENE1_APP_SQL', 'ALLOW'),
        lambda: policy('SC-03', ('p17-lab-clone', 'CLONE_BLOCK'), ('proxy', 'CLONE_BLOCK_AUDIT'), 'CLONE_POLICY_BLOCK', 'BLOCK'),
        correlation, quarantine, restore, fixtures, transport, recovery, protocol,
    ):
        try:
            project()
        except (EvidenceError, SourceError, KeyError, TypeError, ValueError, StopIteration, RuntimeError):
            # A source-specific failure preserves other supported scene observations.
            continue

    rows['SC-06']['reason'] = 'DECISION_SOURCE_UNAVAILABLE'
    rows['SC-09']['reason'] = 'POLICY_CATALOG_NOT_VERIFIED'
    rows['SC-11'].update(status='NOT_EXECUTED', reason='CORRELATION_EXECUTION_REPORT_MISSING')
    rows['SC-16']['reason'] = 'P19_SOURCE_NOT_CONNECTED'
    return {
        'schema_version': 'portal-defense-coverage-1', 'run_id': registry.run_id, 'context': registry.run_context,
        'freshness_state': 'HISTORICAL', 'strict_ready': 'UNKNOWN', 'registry_sha256': receipt_sha,
        'verified_archive_count': len(archives), 'artifact_count': len(available),
        'missing_hosts': registry.missing_hosts, 'unavailable_hosts': unavailable, 'scenes': list(rows.values()),
    }
