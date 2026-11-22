"""Pinned SSH transport for credential-local OpenStack access.

App credentials remain on the relay host. Short-lived project tokens travel only
inside SSH and process memory. Mutations are sent once; transport failures never
silently retry a PUT or imply successful cloud state.
"""
import base64
from contextlib import suppress
import ctypes
from ctypes import wintypes
import hashlib
import io
import json
import os
from pathlib import Path
import shlex
from threading import Lock

from .source_json import unique_object


def private_key_text(path):
    raw = path.read_bytes()
    if path.suffix == '.dpapi':
        if os.name != 'nt':
            raise ValueError('DPAPI identity requires Windows')
        class Blob(ctypes.Structure):
            _fields_ = [('size', wintypes.DWORD), ('data', ctypes.POINTER(ctypes.c_ubyte))]
        buffer = (ctypes.c_ubyte * len(raw)).from_buffer_copy(raw)
        source, output = Blob(len(raw), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte))), Blob()
        unprotect = ctypes.windll.crypt32.CryptUnprotectData
        unprotect.argtypes = [ctypes.POINTER(Blob), ctypes.c_void_p, ctypes.c_void_p,
            ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(Blob)]
        unprotect.restype = wintypes.BOOL
        if not unprotect(ctypes.byref(source), None, None, None, None, 1, ctypes.byref(output)):
            raise ValueError('Identity unavailable')
        try:
            raw = ctypes.string_at(output.data, output.size)
        finally:
            ctypes.windll.kernel32.LocalFree(output.data)
    return raw.decode('ascii')


class SSHTransport:
    def __init__(self, config_path, profile):
        if profile not in {'reader', 'quarantine', 'console'}:
            raise ValueError('Unsupported credential profile')
        raw = Path(config_path).read_bytes()
        if len(raw) > 16384:
            raise ValueError('Relay configuration too large')
        self.config = json.loads(raw, object_pairs_hook=unique_object)
        self.profile, self.client, self.lock = profile, None, Lock()

    def connect(self):
        import paramiko
        if self.client and self.client.get_transport() and self.client.get_transport().is_active():
            return
        if self.client:
            self.client.close()
        expected = self.config['host_key_sha256']
        class PinnedHost(paramiko.MissingHostKeyPolicy):
            def missing_host_key(self, client, hostname, key):
                actual = 'SHA256:' + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip('=')
                if actual != expected:
                    raise paramiko.SSHException('Host key mismatch')
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(PinnedHost())
        text = private_key_text(Path(self.config['identity_file']))
        key = paramiko.Ed25519Key.from_private_key(io.StringIO(text))
        try:
            client.connect(self.config['host'], username=self.config['user'], pkey=key,
                look_for_keys=False, allow_agent=False, timeout=8, auth_timeout=8, banner_timeout=8)
        except Exception:
            client.close()
            raise
        finally:
            del text, key
        client.get_transport().set_keepalive(15)
        self.client = client

    def rpc(self, request):
        from .openstack_inventory import InventoryError
        with self.lock:
            try:
                self.connect()
                command = 'python3 ' + shlex.quote(self.config['helper_path']) + ' --config ' + shlex.quote(self.config['remote_config_path'])
                timeout = {'auto_restore': 85, 'inventory_export': 35}.get(request.get('op'), 20)
                stdin, stdout, stderr = self.client.exec_command(command, timeout=timeout)
                stdin.write(json.dumps({**request, 'profile': self.profile}))
                stdin.channel.shutdown_write()
                raw = stdout.read(4 * 1024 * 1024 + 65537)
                stderr.read(4096)
                if stdout.channel.recv_exit_status() or len(raw) > 4 * 1024 * 1024 + 65536:
                    raise ValueError('Invalid relay response')
                result = json.loads(raw, object_pairs_hook=unique_object)
                if result.get('error'):
                    code, status = result['error'].get('code'), result['error'].get('http_status')
                    if code not in {'OPENSTACK_AUTH_REJECTED', 'OPENSTACK_READ_FORBIDDEN', 'OPENSTACK_HTTP_ERROR',
                        'OPENSTACK_CONNECTION_FAILED', 'OPENSTACK_RELAY_REQUEST_REJECTED', 'OPENSTACK_RELAY_SCOPE_REJECTED',
                        'AUTO_RESPONSE_REJECTED', 'RESTORE_OPERATION_CHANGED', 'RESTORE_PORT_CHANGED',
                        'RESTORE_VERIFICATION_FAILED', 'QUARANTINE_BUSY'}:
                        code = 'OPENSTACK_RELAY_FAILED'
                    raise InventoryError(code, status if type(status) is int else None)
                if not isinstance(result.get('data'), dict):
                    raise ValueError('Invalid relay data')
                return result['data'], result.get('subject_token')
            except InventoryError:
                raise
            except Exception:
                with suppress(Exception):
                    self.client.close()
                self.client = None
                raise InventoryError('OPENSTACK_SSH_RELAY_UNAVAILABLE') from None

    def authenticate(self):
        return self.rpc({'op': 'authenticate'})

    def send(self, method, url, *, body=None, token=None, nova_version=None, revision=None):
        return self.rpc({'op': 'request', 'method': method, 'url': url, 'body': body,
            'token': token, 'nova_version': nova_version, 'revision': revision})
