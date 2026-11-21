import importlib.util
from pathlib import Path
from threading import Lock
from types import SimpleNamespace

import pytest

from app.openstack_inventory import InventoryError
from app.ssh_openstack import SSHTransport

spec = importlib.util.spec_from_file_location('relay', Path(__file__).parents[1] / 'integrations/openstack_ssh_relay.py')
relay = importlib.util.module_from_spec(spec)
spec.loader.exec_module(relay)

CONFIG = dict(compute_url='http://nova/v2.1', network_url='http://neutron', project_id='TEST-project',
    project_wide=False, allowed_server_ids=['TEST-vm'])
PORT = '30000000-0000-4000-8000-000000000001'
SG = '20000000-0000-4000-8000-000000000001'


@pytest.mark.parametrize('profile,method,url,body', [
    ('reader', 'PUT', 'http://neutron/v2.0/ports/' + PORT, {'port': {'security_groups': [SG]}}),
    ('quarantine', 'DELETE', 'http://neutron/v2.0/ports/' + PORT, None),
    ('quarantine', 'POST', 'http://nova/v2.1/servers/123/action', {'os-stop': None}),
    ('reader', 'GET', 'http://unconfigured/secret', None),
    ('reader', 'GET', 'http://nova/v2.1/servers/../os-services', None),
])
def test_relay_rejects_unconfigured_urls_and_non_sg_mutations(profile, method, url, body, monkeypatch):
    calls = []
    monkeypatch.setattr(relay, 'send', lambda *args, **kwargs: calls.append(args))
    with pytest.raises(relay.Rejected):
        relay.checked_request(CONFIG, dict(profile=profile, method=method, url=url, body=body))
    assert calls == []


@pytest.mark.parametrize('project,vm', [('OTHER-project', 'TEST-vm'), ('TEST-project', 'OTHER-vm')])
def test_relay_checks_live_port_scope_before_put(project, vm, monkeypatch):
    calls = []
    def send(method, url, **kwargs):
        calls.append(method)
        return {'port': {'project_id': project, 'device_id': vm, 'device_owner': 'compute:nova'}}, None
    monkeypatch.setattr(relay, 'send', send)
    with pytest.raises(relay.Rejected):
        relay.checked_request(CONFIG, dict(profile='quarantine', method='PUT', url='http://neutron/v2.0/ports/' + PORT,
            body={'port': {'security_groups': [SG]}}, revision=1, token='TEST-only-token'))
    assert calls == ['GET']


def test_uncertain_ssh_put_is_never_retried():
    transport = SSHTransport.__new__(SSHTransport)
    transport.lock, transport.profile = Lock(), 'quarantine'
    transport.config = {'helper_path': '/TEST/relay.py', 'remote_config_path': '/TEST/config.json'}
    calls = []
    def execute(*args, **kwargs):
        calls.append(args)
        raise TimeoutError()
    transport.client = SimpleNamespace(exec_command=execute)
    transport.connect = lambda: None
    with pytest.raises(InventoryError, match='OPENSTACK_SSH_RELAY_UNAVAILABLE'):
        transport.send('PUT', 'http://neutron/v2.0/ports/' + PORT, body={'port': {'security_groups': [SG]}}, revision=1)
    assert len(calls) == 1
    assert transport.client is None
