"""One bounded OpenStack request over an authenticated SSH exec channel.

No listener, shell command or general URL proxy. Host-local config chooses the
project, endpoints and existing credential files. Never log input or tokens.
"""
import argparse
import json
from pathlib import Path
import re
import sys
import subprocess
import os
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener
from uuid import UUID

MAX_BYTES = 4 * 1024 * 1024


class Rejected(Exception):
    pass


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise Rejected()
        result[key] = value
    return result


def send(method, url, *, body=None, token=None, revision=None, nova_version=None):
    headers = {'Accept': 'application/json'}
    if token:
        headers['X-Auth-Token'] = token
    if body is not None:
        headers['Content-Type'] = 'application/json'
    if revision is not None:
        headers['If-Match'] = 'revision_number=' + str(revision)
    if nova_version:
        headers['OpenStack-API-Version'] = 'compute ' + nova_version
    request = Request(url, data=json.dumps(body).encode() if body is not None else None, headers=headers, method=method)
    with build_opener(ProxyHandler({}), NoRedirect()).open(request, timeout=8) as response:
        raw = response.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise Rejected()
        return json.loads(raw, object_pairs_hook=unique_object), response.headers.get('X-Subject-Token')


def authenticate(config, profile):
    path = Path(config['profiles'][profile])
    credential = json.loads(path.read_bytes(), object_pairs_hook=unique_object)
    if credential['project_id'] != config['project_id']:
        raise Rejected()
    body = {'auth': {'identity': {'methods': ['application_credential'],
        'application_credential': {k: credential[k] for k in ('id', 'secret')}}}}
    data, token = send('POST', config['auth_url'].rstrip('/') + '/auth/tokens', body=body)
    auth = data['token']
    roles = {row['name'] for row in auth['roles']}
    accepted = [{'reader'}] if profile == 'reader' else [{'member'}, {'member', 'reader'}]
    if auth['project']['id'] != config['project_id'] or roles not in accepted:
        raise Rejected()
    # Return only the project/roles/expiry needed for the API's independent check.
    return {'token': {k: auth[k] for k in ('project', 'roles', 'expires_at')}}, token


def checked_request(config, request):
    profile, method, url = request['profile'], request['method'], request['url']
    parsed = urlsplit(url)
    if parsed.username or parsed.password or parsed.fragment or '%' in parsed.path or '..' in parsed.path or '\\' in url:
        raise Rejected()
    compute, network = config['compute_url'].rstrip('/'), config['network_url'].rstrip('/') + '/v2.0'
    if url.startswith(compute + '/'):
        relative = parsed.path[len(urlsplit(compute).path):]
        if method != 'GET' or not re.fullmatch(r'/servers(?:/detail|/[a-f0-9-]{36}(?:/os-interface)?)?', relative):
            raise Rejected()
    elif url.startswith(network + '/'):
        relative = parsed.path[len(urlsplit(network).path):]
        if method == 'GET':
            if not re.fullmatch(r'/(?:ports(?:/[a-f0-9-]{36})?|floatingips|security-groups(?:/[a-f0-9-]{36})?|extensions/revision-if-match)', relative):
                raise Rejected()
        elif method == 'PUT' and profile == 'quarantine' and re.fullmatch(r'/ports/[a-f0-9-]{36}', relative):
            body, revision = request.get('body'), request.get('revision')
            if not isinstance(body, dict) or set(body) != {'port'} or set(body['port']) != {'security_groups'} or type(revision) is not int or revision < 0:
                raise Rejected()
            groups = body['port']['security_groups']
            if not isinstance(groups, list) or len(groups) > 64 or len(groups) != len(set(groups)):
                raise Rejected()
            for group in groups:
                if str(UUID(group)) != group:
                    raise Rejected()
            port = send('GET', url, token=request['token'])[0]['port']
            if port.get('project_id', port.get('tenant_id')) != config['project_id'] or not port.get('device_owner', '').startswith('compute:'):
                raise Rejected()
            if not config.get('project_wide') and port.get('device_id') not in config['allowed_server_ids']:
                raise Rejected()
        else:
            raise Rejected()
    else:
        raise Rejected()
    if method == 'GET' and (request.get('body') is not None or request.get('revision') is not None):
        raise Rejected()
    version = request.get('nova_version')
    if version is not None and not re.fullmatch(r'2\.[0-9]{1,3}', version):
        raise Rejected()
    return send(method, url, body=request.get('body'), token=request.get('token'),
        revision=request.get('revision'), nova_version=version)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--automatic-response-only', action='store_true')
    args = parser.parse_args()
    result = {}
    try:
        raw = sys.stdin.buffer.read(65537)
        if len(raw) > 65536:
            raise Rejected()
        request = json.loads(raw, object_pairs_hook=unique_object)
        automatic_request = request['op'] in {'auto_status', 'auto_journal', 'auto_restore'}
        if args.automatic_response_only and (not automatic_request or request['profile'] != 'quarantine'):
            raise Rejected()
        config = json.loads(args.config.read_bytes(), object_pairs_hook=unique_object)
        if request['profile'] not in config['profiles']:
            raise Rejected()
        if automatic_request:
            if request['op'] == 'auto_restore' and request['profile'] != 'quarantine':
                raise Rejected()
            allowed = {'op', 'profile', 'server_id'} | ({'actor_id', 'operation_id', 'request_id'} if request['op'] == 'auto_restore' else set())
            if set(request) - allowed:
                raise Rejected()
            cfg = config['automatic_response']
            command = [cfg['python'], '-m', 'app.auto_response', '--config', cfg['config'], 'rpc']
            completed = subprocess.run(command, input=json.dumps({k: v for k, v in request.items() if k != 'profile'}).encode(),
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=75,
                env={**os.environ, 'PYTHONPATH': cfg['source']})
            if completed.returncode or len(completed.stdout) > MAX_BYTES:
                raise Rejected()
            result = json.loads(completed.stdout, object_pairs_hook=unique_object)
            print(json.dumps(result, separators=(',', ':')))
            return
        elif request['op'] == 'authenticate':
            data, token = authenticate(config, request['profile'])
        elif request['op'] == 'request':
            data, token = checked_request(config, request)
        else:
            raise Rejected()
        result = {'data': data, 'subject_token': token, 'error': None}
    except HTTPError as exc:
        code = 'OPENSTACK_AUTH_REJECTED' if exc.code == 401 else 'OPENSTACK_READ_FORBIDDEN' if exc.code == 403 else 'OPENSTACK_HTTP_ERROR'
        result = {'error': {'code': code, 'http_status': exc.code}}
        exc.close()
    except (URLError, TimeoutError):
        result = {'error': {'code': 'OPENSTACK_CONNECTION_FAILED'}}
    except Exception:
        result = {'error': {'code': 'OPENSTACK_RELAY_REQUEST_REJECTED'}}
    print(json.dumps(result, separators=(',', ':')))


if __name__ == '__main__':
    main()
