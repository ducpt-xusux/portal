"""Record a verified MySQL TLS handshake from the host running this command.

No SQL, DB authentication, private keys or certificate bodies are collected.
This observation does not assert the parameters of a different SQL session.
"""
import argparse
from datetime import datetime, timezone
import ipaddress
import json
import re
import socket
import subprocess


def probe(target, ca_file):
    ipaddress.ip_address(target)
    route = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        route.connect((target, 3306))
        source_ip = route.getsockname()[0]
    finally:
        route.close()
    result = subprocess.run(['openssl', 's_client', '-starttls', 'mysql', '-connect', target + ':3306',
        '-CAfile', ca_file, '-verify_ip', target, '-verify_return_error', '-brief'],
        input=b'', capture_output=True, timeout=10)
    text = (result.stdout + result.stderr).decode('utf-8', errors='replace')
    fields = {}
    for line in text.splitlines():
        key, _, value = line.partition(':')
        if key.strip() in {'Protocol version', 'Ciphersuite', 'Verification'}:
            fields[key.strip()] = value.strip()
    protocol, cipher = fields.get('Protocol version'), fields.get('Ciphersuite')
    verified = fields.get('Verification') == 'OK'
    if not verified or protocol not in {'TLSv1.2', 'TLSv1.3'} or not cipher or not re.fullmatch(r'[A-Za-z0-9_-]{1,100}', cipher):
        raise RuntimeError('TLS_HANDSHAKE_NOT_VERIFIED')
    return {'schema': 'portal-tls-handshake-1', 'source_host': socket.gethostname(), 'source_ip': source_ip,
        'target_ip': target, 'target_port': 3306, 'observed_at': datetime.now(timezone.utc).isoformat(),
        'protocol': protocol, 'cipher': cipher, 'ca_verified': True, 'peer_ip_verified': True,
        'scope': 'TLS_HANDSHAKE_ONLY_NO_DB_AUTH_OR_SQL', 'business_writes': False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target', required=True)
    parser.add_argument('--ca-file', required=True)
    args = parser.parse_args()
    print(json.dumps(probe(args.target, args.ca_file)))
