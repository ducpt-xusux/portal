# Full local Portal runtime

The normal FastAPI backend runs locally, with the same SessionGate, role checks,
CSRF/origin checks, audit journal and durable quarantine/restore service used by
Proxy. Source observations remain separate from Portal business records.

The prepared local runtime now uses one active account, `portal-admin`, with its
unchanged password and full Portal permissions. The two old LAB accounts are
disabled; their old operations remain attributable to their original actor IDs.
Proxy authentication is unchanged by this local profile.

The November 21 automatic-response service is now deployed on Controller and
connected to the restricted evidence feed on Proxy. Its real clone-only test and
manual Portal restore completed successfully (Neutron revision 81 → 82 → 83).
See [automatic-response.md](automatic-response.md) for the policy, deployment,
evidence scope and the independent recovery watchdog. Local configuration sets
`PORTAL_AUTOMATIC_RESPONSE_REMOTE=true` alongside the existing SESSION settings.

## Configuration

Use a reviewed, ignored environment file. The prepared workspace has
`.local-preview/full.env`; no credentials or account store are included in Git.

```text
PORTAL_SESSION_AUTH=true
PORTAL_SESSION_LOCAL_HTTP=true
PORTAL_SINGLE_ACCOUNT_USERNAME=portal-admin
PORTAL_BUSINESS_DATABASE=<absolute private local business SQLite path>
P17_LOCAL_READONLY=false
PORTAL_EVIDENCE_LOCAL_READONLY=false
OPENSTACK_INVENTORY_ENABLED=true
OPENSTACK_SSH_RELAY_CONFIG=<absolute private relay JSON path>
OPENSTACK_AUTH_URL=<configured Keystone v3 URL>
OPENSTACK_COMPUTE_URL=<configured Nova v2.1 URL>
OPENSTACK_NETWORK_URL=<configured Neutron URL>
OPENSTACK_PROJECT_ID=<project ID>
OPENSTACK_QUARANTINE_SG_ID=<empty quarantine SG ID>
PORTAL_QUARANTINE_PROJECT_WIDE=<same reviewed target scope as Proxy>
PORTAL_QUARANTINE_TTL_SECONDS=0
```

`PORTAL_SESSION_LOCAL_HTTP` permits only loopback HTTP and exact configured
loopback origins. Bind the local backend/frontend to 127.0.0.1. A deployment on a
network host must use HTTPS and secure cookies instead of the loopback exception.
TTL 0 preserves manual restore semantics; it does not silently remove quarantine.

The single-account option is restricted to explicit local SESSION mode. It does
not grant permissions on its own: the retained account must already have the
actual stored roles and administrator flag. Existing stores can be converted by
an operator from `backend/`:

```powershell
python -m app.n91_business.local_profile --database <private-local-business-db> --username portal-admin
```

The command backs up the private store beside the original, preserves passwords,
disables the two reviewed LAB accounts and revokes their sessions. Backups contain
authentication records and must remain ignored/private. The local single-account
profile blocks API account creation and changes, while retaining login, review,
export, audit, quarantine and restore behind the existing session/CSRF/cloud gates.

## SSH transport

Install `backend/integrations/openstack_ssh_relay.py` as a private operator-owned
file on Controller. It has no network listener. SSH exec runs one bounded request
with JSON on stdin; no request/credential/token is printed to application logs.

The private local relay configuration contains these fields:

```json
{
  "host": "<Controller SSH address>",
  "user": "<authorized SSH user>",
  "host_key_sha256": "SHA256:<verified host fingerprint>",
  "identity_file": "<local Ed25519 identity path or Windows .dpapi path>",
  "helper_path": "<absolute remote relay script path>",
  "remote_config_path": "<absolute remote private configuration path>"
}
```

The private Controller configuration selects the actual endpoints, project,
target scope and existing credential files:

```json
{
  "project_id": "<project ID>",
  "auth_url": "<Keystone v3 URL>",
  "compute_url": "<Nova v2.1 URL>",
  "network_url": "<Neutron URL>",
  "project_wide": false,
  "allowed_server_ids": ["<reviewed VM UUID>"],
  "profiles": {
    "reader": "<server-local reader app-credential file>",
    "quarantine": "<server-local dedicated Member app-credential file>"
  }
}
```

Credential files contain the established OpenStack app-credential `id`, `secret`
and `project_id`. Their content stays on Controller, in files mode 0600 within a
0700 directory. Reader and Member profiles are independently checked against the
Keystone token's roles and project. No admin credential is used by this runtime.
Short-lived cloud tokens travel through SSH and process memory only.

The relay rejects arbitrary URLs, shell execution, redirects and non-SG cloud
mutations. SG writes require a numeric Neutron revision and a fresh port read
matching project/target scope. Application checks additionally verify the VM,
attachments, empty quarantine SG, per-port baseline and post-write readback.
An uncertain PUT is never retried automatically. Recovery uses the persisted
baseline and rejects changed port revisions/configuration.

## Accounts and local state

The prepared local store retains the three actual Proxy account IDs and existing
password verifiers. The local profile leaves only `portal-admin` active with full
permissions; the two old LAB accounts are disabled. Existing sessions/cursor secrets were excluded;
the user signs in normally. This store is private runtime state, not a source or
review-package artifact. Account/review changes made here stay local. There is no
default password, simulated user, role header or loopback authentication bypass.

On a separate installation, initialize a dedicated business store with the
operator CLI `python -m app.n91_business.bootstrap`; enter its password interactively.
Do not copy another instance's active sessions.

## Running and verification

Install Python 3.12, backend/SSH requirements and frontend dependencies. Start
the authorized source collector first, then run:

```powershell
powershell -File scripts/start-local-preview.ps1 -BackendEnvFile C:\path\to\full.env
```

`-PythonPath C:\path\to\python.exe` reuses an existing environment. `-Stop` stops
only processes matching this launcher's recorded IDs and start times.

Unauthenticated API requests return 401. Viewer/Analyst mutation attempts and
missing/wrong CSRF/origin return 403. Executor can apply quarantine and restore
the exact saved SGs; portal administration is a separate permission. SESSION
Console remains disabled according to the existing access contract.

The real November 20 clone test recorded revision 77 → 78 → 79 and successful
restore after a backend restart. Its metadata/screenshots are review outputs,
not startup fixtures. Source freshness must be checked again after reconnection.

SSH authorization is operator-managed. The transport does not extend keys or
weaken host verification; after expiry/failure it reports unavailable/stale state.
