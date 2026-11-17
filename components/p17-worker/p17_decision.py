"""P17.3 incident review and non-executing containment pre-plan.

No OpenStack imports or subprocess. Never updates incidents or Security Groups.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import sqlite3
import sys
from datetime import datetime,timezone
from pathlib import Path

from p17_durable import DEFAULT_DB, P17Stop, dbconnect, meta


def score_level(score):
    if score is None:return 'UNKNOWN'
    if score>=60:return 'CRITICAL'
    if score>=40:return 'HIGH'
    if score>=20:return 'WARNING'
    return 'LOW'


def mapping_verified(snapshot,ip,*,max_age_s=600,now=None):
    if not isinstance(snapshot,dict):return False,['MAPPING_MISSING']
    canonical={k:v for k,v in snapshot.items() if k!='snapshot_sha256'}
    expected_hash=hashlib.sha256(json.dumps(canonical,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    reasons=[]
    if snapshot.get('snapshot_sha256')!=expected_hash:reasons.append('MAPPING_SNAPSHOT_HASH_INVALID')
    if snapshot.get('source_ip')!=ip:reasons.append('SOURCE_IP_CHANGED')
    if snapshot.get('schema')!='p17-neutron-readonly-1':reasons.append('MAPPING_SCHEMA_UNKNOWN')
    if snapshot.get('expected_ids_matched') is not True:reasons.append('OPERATOR_EXPECTED_IDS_UNVERIFIED')
    if snapshot.get('port_security_enabled') is not True:reasons.append('PORT_SECURITY_UNVERIFIED')
    if snapshot.get('action_executed')!='NONE':reasons.append('MAPPING_RECORD_NOT_READ_ONLY')
    m=snapshot.get('mapping')
    if not isinstance(m,dict) or any(not isinstance(m.get(k),str) or not m[k] for k in
       ('port_id','project_id','network_id','server_id')):reasons.append('MAPPING_MISSING_FIELDS')
    try:
        dt=datetime.fromisoformat(snapshot['observed_at_utc'].replace('Z','+00:00'))
        if dt.tzinfo is None or not (0 <= ((now or datetime.now(timezone.utc))-dt.astimezone(timezone.utc)).total_seconds() <= max_age_s):
            reasons.append('MAPPING_STALE_OR_FUTURE')
    except (ValueError,TypeError,KeyError,OverflowError):reasons.append('MAPPING_TIME_INVALID')
    return len(reasons)==0,reasons


def decide(incident, mapping=None, *, lab_dedicated=False,now=None):
    iid,ip,rule,n,peak,status=incident
    severity=score_level(peak)
    strong=rule in ('CORR-002','CORR-004') and n>=3 and severity=='CRITICAL'
    mapping_ok,mapping_reasons=mapping_verified(mapping,ip,now=now)
    reasons=[]
    if rule=='CORR-005':reasons.append('OPERATIONAL_COMPATIBILITY_SIGNAL_NOT_ATTACK_PROOF')
    if severity=='UNKNOWN':reasons.append('P15_SCORE_UNKNOWN')
    if not strong:reasons.append('EVIDENCE_NOT_APPROVED_FOR_CONTAINMENT')
    reasons.extend(mapping_reasons)
    if not lab_dedicated:reasons.append('UNVERIFIED_SHARED_OR_PRODUCTION_WORKLOAD')
    eligible=strong and mapping_ok and lab_dedicated and status=='REVIEW_REQUIRED'
    return {
      'incident_id':iid,'source_ip':ip,'correlation_rule':rule,
      'evidence_request_count':n,'p15_peak_risk_score':peak,
      'p15_severity':severity,'evidence_rule_qualified':strong,
      'source_port_mapping_verified':mapping_ok,'dedicated_lab_workload_asserted':bool(lab_dedicated),
      'dry_run_candidate':bool(eligible),'operator_approval_obtained':False,
      'decision':'CANDIDATE_FOR_MANUAL_CONTAINMENT_REVIEW' if eligible else 'REVIEW_REQUIRED',
      'blocking_reasons':sorted(set(reasons)),
      'action_executed':'NONE','isolation_authorized':False,
      'openstack_mutations':0,
    }


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--incident-id',required=True)
    p.add_argument('--db',default=DEFAULT_DB)
    p.add_argument('--mapping-file',type=Path)
    p.add_argument('--lab-dedicated',action='store_true',help='Only dedicated, expendable lab VM')
    a=p.parse_args(argv)
    db=dbconnect(a.db)
    try:
        meta(db)
        row=db.execute('''SELECT incident_id,client_ip,signal_rule,evidence_count,peak_p15,status
                          FROM incidents WHERE incident_id=?''',(a.incident_id,)).fetchone()
        if row is None:raise P17Stop('INCIDENT_NOT_FOUND')
        mapping=None
        if a.mapping_file:
            if a.mapping_file.is_symlink() or not a.mapping_file.is_file():raise P17Stop('MAPPING_FILE_UNSAFE')
            mapping=json.loads(a.mapping_file.read_text())
        plan=decide(row,mapping,lab_dedicated=a.lab_dedicated)
        print(json.dumps(plan,indent=2,sort_keys=True))
        print('P17_3_DECISION_DRY_RUN_ONLY_NO_OPENSTACK_WRITE')
    finally:db.close()

if __name__=='__main__':
    try:main()
    except (P17Stop,sqlite3.DatabaseError,ValueError,OSError) as e:
        print('P17_3_STOP: '+str(e),file=sys.stderr)
        raise SystemExit(2)
