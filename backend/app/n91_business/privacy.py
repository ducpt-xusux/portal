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
    # Includes tab/newline/space-prefixed spreadsheet formula payloads.
    if text.lstrip(' \t\r\n').startswith(('=', '+', '-', '@')):
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
