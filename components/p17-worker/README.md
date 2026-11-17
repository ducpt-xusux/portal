# Captured P17 worker source

The five p17_*.py files are copied byte-for-byte from
/opt/db-firewall/p17-incident-g03-dual-v3-20261104 on Proxy, 2026-11-17.
Their hashes and original paths are recorded in
deploy/portal-local/import-manifest.json.

vnext_report.py is an additional offline report tool from the matching
N91_P17_VNEXT_REAL_PATCH_FIXED ZIP. Tests originate from
N91_P17_PORTAL_INTEGRATED; their import paths were adjusted to this repository.

The worker runs on Linux/Python 3.13 and uses standard-library SQLite and fcntl.
It persists review-only vNext cases alongside the existing P17 authority.
The Portal adapter/publisher are under backend/app/p17_vnext_api.py and
deploy/portal-local.

Run isolated tests from the repository root:

    PYTHONPATH=backend .venv/bin/python -m pytest components/p17-worker/tests

Deploy this component separately from the Portal application. Preserve the
existing service configuration, source markers, stream identity and SQLite
state. This directory contains no production database, audit events,
credentials or activation markers. Copying source to Git does not apply a
database migration or change the running worker.
