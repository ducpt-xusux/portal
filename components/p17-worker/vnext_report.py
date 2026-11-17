#!/usr/bin/env python3
"""Read-only P17 VNext console/HTML report. No P16H commands, no database writes."""
import argparse
import html
import json
import sqlite3
import sys
import time
from datetime import datetime, timezone
from pathlib import Path


def h(x):
    if x is None:return '<span class="mute">UNAVAILABLE</span>'
    return html.escape(str(x))


def fetch(dbpath):
    p=Path(dbpath)
    if not p.is_file():raise ValueError('P17_SQLITE_NOT_FOUND')
    # URI mode=ro and PRAGMA query_only prevent all writes, including checkpoint changes.
    from urllib.parse import quote
    con=sqlite3.connect('file:'+quote(str(p.resolve()),safe='/')+'?mode=ro',uri=True)
    con.row_factory=sqlite3.Row
    try:
        con.execute('PRAGMA query_only=ON')
        tables={x[0] for x in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if not {'vnext_events','vnext_cases','vnext_signals','metadata','processed_events','incidents'}.issubset(tables):
            raise ValueError('VNEXT_NOT_INSTALLED_OR_MIGRATED')
        meta={r['key']:r['value'] for r in con.execute('SELECT key,value FROM metadata')}
        result={'read_at_utc':datetime.now(timezone.utc).isoformat(),
            'stream_id':meta.get('stream_id'),'checkpoint':meta.get('last_committed_sequence'),
            'legacy_events':con.execute('SELECT COUNT(*) FROM processed_events').fetchone()[0],
            'legacy_incidents':con.execute('SELECT COUNT(*) FROM incidents').fetchone()[0],
            'vnext_events':con.execute('SELECT COUNT(*) FROM vnext_events').fetchone()[0],
            'vnext_cases':con.execute('SELECT COUNT(*) FROM vnext_cases').fetchone()[0],
            'vnext_outbox_pending':con.execute('SELECT COUNT(*) FROM vnext_trace_outbox WHERE delivered=0').fetchone()[0],
            'cases':[dict(row) for row in con.execute('SELECT * FROM vnext_cases ORDER BY updated_utc DESC LIMIT 40')],
            'events':[dict(row) for row in con.execute('SELECT * FROM vnext_events ORDER BY stream_sequence DESC LIMIT 60')],
            'signals':[dict(row) for row in con.execute('SELECT * FROM vnext_signals ORDER BY updated_utc DESC LIMIT 50')],
            'members':[dict(row) for row in con.execute('''SELECT ce.case_id,ce.event_id,ce.reason,
                  e.event_ms,e.risk_score,e.stream_sequence FROM vnext_case_evidence ce
                  JOIN vnext_events e ON ce.stream_id=e.stream_id AND ce.event_id=e.event_id
                  ORDER BY e.stream_sequence DESC LIMIT 250''')],
        }
        return result
    finally:con.close()


def render(data):
    case_rows=[]
    for c in data['cases']:
        signal_ids=', '.join(json.loads(c['signal_ids_json']))
        members=[m for m in data['members'] if m['case_id']==c['case_id']]
        time_span=(max(m['event_ms'] for m in members)-min(m['event_ms'] for m in members))//1000 if len(members)>1 else 0
        sample=', '.join(m['event_id'] for m in members[:15])
        case_rows.append('<tr><td><code>'+h(c['case_id'])+'</code><details><summary>Evidence members</summary>'+h(sample)+'</details></td><td>'+h(c['source_ip'])+'</td><td>'+h(c['severity'])+'</td><td>'+h(signal_ids)+'</td><td>'+h(c['evidence_count'])+'<small class="muted"> · span '+h(time_span)+'s</small></td><td>'+h(c['peak_p15'])+'</td><td>'+h(c['status'])+'</td><td><strong>NO_ACTION</strong></td></tr>')
    event_rows=[]
    for e in data['events']:
        t=json.loads(e['trace_json'])
        p14=t.get('p14',{})
        p15=t.get('p15',{})
        p17=t.get('p17',{})
        evn=list(p17.get('matched_signals') or [])
        event_rows.append('<tr><td>'+h(e['stream_sequence'])+'</td><td><code>'+h(e['event_id'])+'</code></td><td>'+h(t['source_ip'])+'</td><td>'+h(t['db_user'])+'</td><td>'+h(p14.get('effective_action'))+'</td><td>'+h(', '.join(p14.get('matched_rules') or []))+'</td><td>'+h(p15.get('risk_score'))+'</td><td>'+h(e['qualify_reason'])+'</td><td>'+h(', '.join(evn))+'</td><td><code>'+h(p17.get('case_id'))+'</code></td></tr>')
        event_rows.append('<tr><td colspan="10"><details><summary>Decision Trace (P14 + P15 + P16H + 22 CORR, including NOT_MET reasons)</summary><pre>'+h(json.dumps(t,ensure_ascii=False,indent=2))+'</pre></details></td></tr>')
    def tile(label,val):return f'<div class="metric"><small>{h(label)}</small><strong>{h(val)}</strong></div>'
    css='''body{font-family:Inter,system-ui,Arial,sans-serif;background:#0b1220;color:#e6edf6;margin:0;padding:25px}
    h1{margin:0 0 9px;font-size:26px}.sub{color:#a4b5cb;margin-bottom:20px;line-height:1.55}
    .metrics{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin-bottom:25px}
    .metric{border:1px solid #2b3f58;border-radius:11px;padding:13px;background:#142036}
    .metric small{display:block;color:#96acc9;margin-bottom:4px}.metric strong{font-size:24px}
    .box{border:1px solid #27374c;border-radius:12px;background:#121e31;margin-bottom:22px;overflow:auto}
    h2{font-size:18px;margin:18px 15px}table{border-collapse:collapse;width:100%;min-width:900px;font-size:13px}
    th{background:#1b2c44;color:#c5d5eb;white-space:nowrap;text-align:left;padding:11px 12px}
    td{border-top:1px solid #27374c;padding:10px 12px;vertical-align:top}tr:hover{background:#1b2940}
    code{font-size:12px;color:#86cdf8}.mute{color:#8192a8}.warn{color:#ffc97c}
    .note{border-left:3px solid #d2a46d;padding:11px 15px;background:#1b2531;color:#e2d4ba;margin-bottom:22px}
    .footer{color:#8ea0b7;font-size:13px}pre{white-space:pre-wrap;overflow-wrap:anywhere;max-height:500px;overflow:auto;color:#d2e2f6;padding:12px;background:#0c1729;border-radius:8px}details{padding:6px}summary{cursor:pointer;color:#87c8f6}
    '''
    cards=''.join([tile('Legacy events',data['legacy_events']),tile('Legacy incidents',data['legacy_incidents']),
            tile('New VNext traces',data['vnext_events']),tile('New VNext cases',data['vnext_cases']),
            tile('Trace log pending',data['vnext_outbox_pending']),tile('Checkpoint',data['checkpoint'])])
    return f'''<!doctype html><html lang="vi"><head><meta charset="utf-8"><meta http-equiv="refresh" content="5"><meta name="viewport" content="width=device-width,initial-scale=1"><title>N91 P17 VNext live audit</title><style>{css}</style></head>
    <body><h1>N91 P17 VNext — Actual committed SQLite</h1><div class="sub">Nguồn: Proxy P17 G03 V3 · Stream {h(data['stream_id'])} · Đọc lúc {h(data['read_at_utc'])} UTC · Trang này được tạo từ SQLite read-only.</div>
    <div class="metrics">{cards}</div>
    <div class="note"><strong>Hợp đồng an toàn:</strong> VNext chỉ tạo case REVIEW_REQUIRED trong bảng riêng. Không chạm legacy incidents, không ủy quyền P17.5, không kết luận đã SQLi thành công. Các kết quả mới chỉ áp dụng cho event sau khi nâng cấp; lịch sử không tự backfill.</div>
    <div class="box"><h2>VNext cases (mới)</h2><table><thead><tr><th>Case ID</th><th>Source IP</th><th>Severity</th><th>Matched detectors</th><th>Request evidence</th><th>P15 peak</th><th>Review</th><th>Response</th></tr></thead><tbody>{''.join(case_rows) or '<tr><td colspan="8">Chưa có case mới</td></tr>'}</tbody></table></div>
    <div class="box"><h2>Recent committed events (P14 → P15 → P16H → P17)</h2><table><thead><tr><th>Seq</th><th>Event ID</th><th>Source IP</th><th>DB User</th><th>P14 action</th><th>Matched rules</th><th>P15 Risk</th><th>VNext eligibility</th><th>Triggered detectors</th><th>VNext case</th></tr></thead><tbody>{''.join(event_rows) or '<tr><td colspan="10">Chưa có event mới; gửi SQL từ App hoặc Clone để thấy dữ liệu</td></tr>'}</tbody></table></div>
    <div class="footer">P17 VNext candidate · Không phải sản phẩm production-ready · Không có OpenStack write trong VNext</div></body></html>'''


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--db',default='/var/lib/db-firewall-p17/state.sqlite3')
    ap.add_argument('--out',default='/home/ubuntu/p17_vnext_live.html')
    ap.add_argument('--watch',type=int,default=0,help='refresh HTML every N seconds; 0 = once')
    args=ap.parse_args()
    if args.watch and args.watch<2:ap.error('--watch must be >=2')
    try:
        while True:
            data=fetch(args.db)
            p=Path(args.out)
            if p.is_symlink() or not p.parent.is_dir() or p.parent.is_symlink():
                raise ValueError('REPORT_OUTPUT_PATH_UNSAFE')
            temp=p.with_name(p.name+'.tmp')
            temp.write_text(render(data),encoding='utf-8')
            temp.chmod(0o600)
            temp.replace(p)
            print('REPORT_UPDATED',str(p),'stream_checkpoint='+str(data['checkpoint']),
                  'new_events='+str(data['vnext_events']),'new_cases='+str(data['vnext_cases']),flush=True)
            if not args.watch:break
            time.sleep(args.watch)
    except (ValueError,OSError,sqlite3.DatabaseError) as exc:
        print('REPORT_FAILED '+str(exc),file=sys.stderr)
        raise SystemExit(2)

if __name__=='__main__':main()
