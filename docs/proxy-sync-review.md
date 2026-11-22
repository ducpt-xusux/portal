# N91 Proxy source integration — local review

Base: `92c3c75512121097908d54ffbbba59f98ee16d56`.
Branch: `sync/proxy-live-20261117`. The checkout has uncommitted changes; no push,
merge or production Portal frontend deployment has been performed.

## Reconciliation

The generated audit archive was retrieved from Proxy and compared with the
current live files. The November 17 audit described 20 assets / 18 overlays.
The subsequently inspected live index uses 22 assets / 20 N91 overlays, including
the Single Toggle CSS/JS. Those active assets were read as references, never
executed as installers. The source comparison found 3 semantic backend changes
(`main.py`, `p17_api.py`, `p17_vnext_api.py`) and 62 Python files differing only
in newline representation. The reported count of changed files is not a count
of independently changed backend features.

The frontend now implements the compact dashboard, seven-column Galera table,
service observations, five primary routes, native VNext analysis, source-aware
Event details, Incident membership, one compact/full detail toggle, VM network
history and SG action journal in React/CSS. `index.html` does not inject the ZIP
DOM overlays. The build does not depend on MutationObserver patches.

## Current local session mode

The local instance now runs SESSION authentication, not the initial observation
preview. The three existing Proxy accounts were imported with their unchanged
password verifiers, roles, active state and IDs into a separate, ignored local
business store. No existing sessions, login tokens or cursor secret were copied.
Local account/review/audit changes belong to this local store.

A dedicated SSH transport executes bounded OpenStack requests on Controller.
Reader and quarantine Member credentials remain in private server-local files.
The host fingerprint is pinned; the task SSH key is encrypted with Windows DPAPI.
Cloud tokens exist only in SSH/process memory. The relay permits configured
Nova/Neutron reads and revision-guarded port-SG PUTs for the configured scope;
it rejects other destinations and cloud mutations. PUTs are never auto-retried.
Live reader-role Neutron readback refreshes the UI after an action; inventory
exports supply only display hints for compute host. Session role, CSRF, origin,
project, port attachment and SG/revision checks remain active.

On November 20, the user logged in as `lab-executor` and both buttons were tested
on the real clone VM. Original SGs at revision 77 changed to the quarantine SG
at revision 78. Backend was restarted while quarantined. The same session and
operation survived; manual restore reinstated the exact original SGs at revision
79. All stages were persisted in the local audit/journal. No other VM was changed.
Windows and POSIX recovery locks prevent concurrent workers on one business store.

## Real source flow

The local frontend uses the standard FastAPI application. A pinned SSH poller
collects bounded, read-only projections every 15 seconds:

* Proxy: Canonical reader HEALTH/RECENT, committed P17 SQLite rows, fresh VNext
  export, service observations, Galera snapshots and public action/network history.
  It never uses reader POLL/ACK and does not copy the authentication database.
* Controller: credential-local Nova/Neutron inventory for the selected project.
  An explicit Nova field projection supplies compute hosts by matching exact
  server and project IDs. Credentials remain on Controller.
* RealSourceCache validates stream identity, upstream Canonical envelope hashes,
  P17 membership, VNext schema and the Galera batch before replacing source files.
  Poll failure or expiry becomes STALE; reading a cache does not renew the remote
  observation time. A recent successful empty read remains a successful read.

The local `.local-preview/` configuration/cache is ignored by Git. It contains
real source records and the separately protected local business store; no fabricated
users or source observations are created. The task's SSH private key is held with
user-scoped DPAPI encryption outside the repository. The current preview relies
on the active SSH poller and the temporary authorization window; after it ends,
the source status must become stale until an authorized collector reconnects.

Reusable source adapters are in `app.proxy_live_export`, `app.openstack_export`
and `app.real_source_cache`. Their input paths and project scope must be configured
for the target deployment. Task-specific SSH authorization and runtime captures
are intentionally excluded from the source patch.

## Producer correction and real validation

The user approved the P17 worker change and controlled read-only SQL validation.
Source and SQLite backups remain on Proxy at
`/home/ubuntu/n91-source-sync-backups/p17-capture-20261120T142414Z`.
The worker was briefly stopped, its baseline hash checked, and the evidence hook
installed atomically before restarting it. The helper adds two tables inside the
existing transaction and records the exact Event/request/sequence/hash members,
trigger, detector version and worker/core digest. It does not commit, ACK, change
correlation rules, backfill legacy membership or execute cloud actions.
The reviewable hook/helper live under `backend/integrations/p17/`.

Real app validation run `N91_REAL_SYNC_20261120T151557Z`, from `10.0.0.30`:

* One allowed SELECT returned 4 products; five read-only injection SELECTs were
  blocked with MariaDB error 1142. No business writes were executed.
* P17 advanced to 1004 events / 19 incidents. Four capture snapshots contain
  17 member rows (successive snapshots share members).
* New CORR-001 and CORR-002 incidents each have five directly persisted members.
  Their Canonical envelope hashes validate and match P17. Detector provenance
  is available. Reader cursor/checkpoint agreement and pending=0 were checked.
* The first preliminary query from the clone was blocked by CTX-006 because
  the policy permits the application source. The policy was kept intact and
  the successful validation was rerun from the actual app VM.

The user approved starting Galera 2/3. Galera 1 rejoined with a normal MariaDB
start after quorum existed; no database bootstrap was used. All three nodes
now return real Primary / size 3 / Synced / ready ON / connected ON observations.
The app and clone VMs were returned to their original SHUTOFF state after testing.

## Report fields and supporting evidence

The Canonical Event detail retains all 16 Table 3.6 fields, including sequence,
score zero, risk breakdown, policy, hash and masking status. A source-confirmed
absent default database is distinct from a failed read. P17 remains a separately
labelled projection; its missing Canonical fields are never fabricated.

VM/port output includes project and device identity, fixed/floating IPs, every
subnet/network, SG IDs/names, Neutron revision and observation times. Persisted
operations supply SG before/quarantine/restore stages and their actual audit
readbacks. Current network state comes from fresh Neutron observations, not
from a historical restore record. Nova has no authoritative business-role
metadata; this optional field is not inferred from a VM name.

The System report-evidence endpoint/UI presents bounded reviewed observations:
App–Proxy TLS 1.3 / TLS_AES_256_GCM_SHA384 with CA/IP verification; independent
Proxy–Galera TLS verification for all three nodes; sanitized effective SQL grants;
current table counts/checksums; server-local doan_db backup metadata; historical
G07 restore/RPO LAB measurements; and the real ALLOW/BLOCK validation run.
The new doan_db logical archive remains protected on Galera 1 (0600); only its
ID, times, size, hash and scope were exported. It has not been restore-tested.

## Validation

* Backend: 71 passed, 1 pre-existing skip. Transaction, identity, hash rejection,
  source freshness, historical scope and cross-project journal isolation checked.
* Frontend logic: 97 passed; investigation/workbench: 22 passed; business/session client: 11 passed.
* React integration: 3 passed. Vite production build passed on Windows with
  `--configLoader native` (the existing >500 kB chunk warning remains).
* Linux candidate-worker smoke: exact membership, replay, VNext coexistence and
  rollback before ACK passed before deployment.
* November 20 live API acceptance: all six configured source readers fresh; 8 actual VMs;
  3 healthy Galera observations; five direct evidence members with matching
  Canonical hashes; 8 clone action records; 7 reviewed report artifacts.
* Browser review uses the real sources, including Incident detection, Event
  fields, VM SG journal, report evidence and dashboard. Screenshots accompany
  the local review package.

## Scope that remains explicit

Canonical retention is partial. Seventeen pre-patch incidents lack persisted
membership, and their historic links cannot be established by inventing data.
The local SESSION instance enables authorized review/export, user administration
and real VM isolation/restore. Viewer and Analyst cannot execute quarantine; the
Executor role and valid CSRF/origin/session are required. The Console remains
disabled in SESSION mode, matching the existing Proxy access contract. The existing
production authentication and mutation gates remain in force.
G07 RPO/RTO results describe their measured LAB scopes; production full-system
RPO/RTO were not measured. No result is relabelled to imply such a measurement.

## Visual design

The VM detail was redesigned first, followed by the dashboard, Event and Incident
lists/details, behavior analysis, workload inventory, System/services/Galera/source
panels, report evidence, login and administration. Shared typography, teal/navy
palette, cards, tables, filter bars and tabs use native React/CSS. Every report
field remains accessible; long port identifiers and artifact facts use disclosure
panels. Status color still follows actual source state. No source sample, trend
percentage, capability or cloud result is fabricated for presentation.

## Local startup

With an existing reviewed source collector/configuration:

```powershell
powershell -File scripts/start-local-preview.ps1 -BackendEnvFile C:\path\to\reviewed-real.env
```

FE: `http://127.0.0.1:5173/`; BE: `http://127.0.0.1:8000/`. SESSION protects API routes; Swagger is not a public bypass.
The launcher requires real-source settings and does not generate sample data.
It records owned process IDs/start times for its `-Stop` operation. Use Python
3.12 and the backend requirements; SSH transport additionally uses
`backend/requirements-ssh.txt`. Configure source paths and collectors before
using a separately started preview. No secrets or DB archives belong in Git.

For this prepared workspace use `.local-preview/full.env` and, if desired, pass
`-PythonPath` to the existing Python 3.12 executable. SSH-enabled configurations
require `backend/requirements-ssh.txt`; the launcher checks the transport dependency.
The local business store, SSH config and runtime evidence must stay out of Git.
See `docs/full-local-runtime.md` for the relay configuration contract. Expired SSH
authorization or unavailable VMs means STALE/unavailable sources until restored;
no cached observation is relabelled as fresh.

## November 21 local account simplification

At the user's request, the prepared local runtime now keeps only `portal-admin`
active, with the existing password and all Portal operational permissions.
`lab-viewer` and `lab-executor` are disabled and their sessions revoked. The local
profile rejects other account names and prevents creating/reactivating accounts
through the API. This does not change Proxy accounts or its cloud credentials.
The UI displays one account type, “Quản trị viên”, without role selectors.

An operator-only migration validates the existing store and active administrator,
backs up the private database locally, preserves password verifiers/IDs/history,
and records each permission/account-state change in the local audit trail.
The backend audit projection also wraps the quarantine service's historical port
arrays in a `ports` object, so its strict response DTO can display real SG history.

Browser checks covered dashboard, Event list/detail, Incident list/detection,
behavior analysis, VM inventory/detail, services, Galera, source status, report
evidence and the real administrator account table/audit. Desktop and phone
breakpoints were checked; table overflow stays within its scroll container.
The temporary viewport override was reset after QA.

## November 21 automatic response and presentation update

The independently running Controller service has now completed its real,
clone-only end-to-end test. A single blocked query did not isolate; an unapproved
CORR-001 incident was rejected; three distinct, hash-verified CORR-002 requests
were authorized by the separate policy engine. The clone was isolated at
15:52:05 UTC. App still read four products. `portal-admin` then restored through
the local Portal at 15:56:22 UTC, with exact original SG readback and revision
81 → 82 → 83. One automatic operation was persisted; no other VM was targeted.
The active clone remains restored and ACTIVE. Successful containment has manual
restore; the independent watchdog only handles partial/failed operations.

See [automatic-response.md](automatic-response.md) for the deployment and evidence
scope, including both failed attempts and their corrections. Current backend
checks: 113 passed, 1 skipped. Frontend suites total 134 passed; Vite build passed.
The new VM integration regression covers the formerly misplaced automatic-status
block that raised `ReferenceError: operation is not defined` in the port panel.

User-facing stage codes were replaced with Vietnamese function names: policy
enforcement, risk assessment, normalized audit logging, behavior detection and
response control. The lab VM has a clear display alias; its UUID and API values
remain the authoritative identity. Source labels and schema descriptions use the
same terminology, while original evidence exports remain reproducible.
