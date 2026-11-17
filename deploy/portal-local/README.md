# Portal-local deployment source

This directory captures the launcher and observation tools used by Proxy on
2026-11-17. The source hashes are in import-manifest.json. Application source
is in backend; the separate worker source is in components/p17-worker.

## Build and verify

Use Node 22.23.5 and Python 3.13 to reproduce the captured environment.
From the repository root:

    python3.13 -m venv .venv
    .venv/bin/python -m pip install -r backend/requirements-runtime.lock
    .venv/bin/python -m pip install -r backend/requirements-test.txt
    cd fe-api-staging
    npm ci
    npm test
    npm run build -- --outDir ../deploy/.proxy-web-build --emptyOutDir
    cd ..
    PYTHONPATH=backend .venv/bin/python -m pytest backend components/p17-worker/tests
    .venv/bin/python deploy/portal-local/verify_import.py --web deploy/.proxy-web-build
    python3 deploy/build_proxy_bundle.py --output /tmp/portal-new-release.tar.gz

The runtime lock records versions installed on Proxy. Test requirements add
development dependencies. For this initial import, verify_import.py with
--captured-source also checks the captured backend, worker, launcher and base
frontend hashes. Subsequent intentional source changes use their own regression
tests instead of asserting equality with the original capture.

The existing archive checked into deploy/ predates this import. Build a new
archive from the branch being deployed.

## Layout for the local launcher

The bundle includes:

- backend/ and web/: application release.
- portal-local/local_app.py: launcher for the parent runtime directory.
- portal-local/collect_proxy_services.py: systemd status collector.
- portal-local/publish_vnext.py and vnext_detector_manifest.json: optional
  vNext publisher from the matching ZIP package.
- portal-local/systemd/: service and timer templates.
- components/p17-worker/: independently deployed worker source.

For the existing Proxy layout, the application belongs in
/home/ubuntu/portal-local/n91-portal-proxy-linux/{backend,web}; the launcher
belongs in /home/ubuntu/portal-local/local_app.py. The collector belongs in
/home/ubuntu/portal-local/.n91-proxy-health/collect_proxy_services.py.
The optional publisher and detector manifest belong together in
/home/ubuntu/portal-local/vnext_tools.

The local service template explicitly sets PYTHONPATH so Python can import the
release backend. This adjusts the deployment template only. Importing these
files does not modify the installed service or restart port 5188.

Keep openstack.env, .secrets, business databases, audit data, snapshots, locks
and logs in their existing protected runtime locations. The env example
contains paths and feature examples only. Preserve the existing quarantine
project scope, credentials, security group and TTL configuration.

## Release procedure

1. Back up code/configuration. Use SQLite backup facilities if a database
   migration will be performed. Keep private backups outside the checkout.
2. Build a clean commit and unpack its archive into a new directory. Verify
   SHA256SUMS before using it.
3. Exercise the staged release with a separate test configuration, port and
   databases. Check session auth, VM isolation/restoration, quarantine totals,
   Galera and vNext Case/Trace.
4. Schedule the application switch after review. Preserve runtime configuration
   and data, and retain the prior release for rollback. A backend code switch
   needs a controlled process restart.
5. Deploy the P17 worker separately using its own state/migration procedure.
   Portal updates must not overwrite its database or restart that worker.

The source import does not switch the live application. Publisher units are
optional templates; they were absent on Proxy during capture. Installing or
enabling them is a separate operational change.
