"""Plain-text notes only; no HTML rendering or arbitrary source exports."""
import csv
import io
import re
import unicodedata


def plain_text(value: str) -> str:
    value = value.strip()
    if not value or len(value) > 1000:
        raise ValueError('Note length invalid')
    if any(unicodedata.category(c) in {'Cc', 'Cf'} and c not in '\n\t' for c in value):
        raise ValueError('Control characters forbidden')
    if '<' in value or '>' in value or re.search(
        r'(?i)(-----BEGIN|(?:password|passwd|secret|token|authorization|api[_-]?key)\s*[:=]|'
        r'\b(?:SELECT\s+(?:\d|\*|.+?\s+FROM)|INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM|DROP\s+TABLE)\b)', value):
        raise ValueError('Sensitive or markup content forbidden')
    return value


def csv_cell(value) -> str:
    text = '' if value is None else str(value)
    # Compatibility characters and ignorable prefixes can hide a formula marker.
    normalized = ''.join(c for c in unicodedata.normalize('NFKC', text)
                         if unicodedata.category(c) != 'Cf')
    if normalized.startswith(('\t', '\r', '\n')) or normalized.lstrip().startswith(('=', '+', '-', '@')):
        return "'" + text
    return text


def notes_csv(notes) -> str:
    output = io.StringIO(newline='')
    writer = csv.writer(output)
    columns = ('note_id', 'incident_id', 'note', 'actor_id', 'created_at')
    writer.writerow(columns)
    for note in notes:
        writer.writerow([csv_cell(note.get(column)) for column in columns])
    return output.getvalue()


def evidence_csv(data) -> str:
    output = io.StringIO(newline='')
    writer = csv.writer(output, quoting=csv.QUOTE_ALL)
    metadata = (
        'incident_id', 'stream_id', 'export_id', 'audit_id', 'scope', 'completeness', 'generated_at',
        'signal_rule', 'evidence_membership', 'recorded_evidence_count', 'candidate_count',
        'exported_event_count', 'event_limit', 'has_more', 'reason_codes', 'source_system',
        'source_schema', 'source_mode', 'execution_mode', 'captured_at', 'snapshot_sha256',
    )
    fields = ('event_id', 'request_id', 'stream_sequence', 'occurred_at', 'source_ip', 'decision',
              'risk_status', 'risk_score', 'matched_rules', 'source_ref', 'payload_sha256')
    writer.writerow(('record_type', *metadata, *fields))
    stamp = {**data, 'completeness': 'PARTIAL', 'has_more': str(data['has_more']).lower(),
             'reason_codes': ' | '.join(data['reason_codes'])}
    writer.writerow(('METADATA', *(csv_cell(stamp[key]) for key in metadata), *('' for _ in fields)))
    for item in data['items']:
        record = {**item, 'matched_rules': ' | '.join(item['matched_rules'])}
        writer.writerow(('EVIDENCE', *(csv_cell(stamp[key]) for key in metadata),
                         *(csv_cell(record[key]) for key in fields)))
    return '\ufeff' + output.getvalue()
