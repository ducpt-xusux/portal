#!/usr/bin/env bash
set -euo pipefail
umask 022

if [[ ${EUID} != 0 ]]; then
    printf '%s\n' 'Run with sudo: sudo bash install.sh' >&2
    exit 1
fi

cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
sha256sum --check --quiet SHA256SUMS
command -v nginx >/dev/null
command -v systemctl >/dev/null
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else "Python 3.10+ is required")'
if [[ ! -d /run/systemd/system || ! -d /etc/nginx/conf.d ]]; then
    printf '%s\n' 'This installer requires systemd and /etc/nginx/conf.d.' >&2
    exit 1
fi
if getent passwd n91-portal >/dev/null || getent group n91-portal >/dev/null; then
    printf '%s\n' 'The n91-portal service account already exists. Use the upgrade instructions in README.md.' >&2
    exit 1
fi

for target in /opt/n91-portal /var/lib/n91-portal /etc/n91-portal \
    /etc/nginx/conf.d/n91-portal.conf /etc/systemd/system/n91-portal.service \
    /etc/systemd/system/n91-portal-p17.service /etc/systemd/system/n91-portal-p17.timer; do
    if [[ -e "$target" || -L "$target" ]]; then
        printf 'Target already exists: %s\n' "$target" >&2
        exit 1
    fi
done

install -d -m 0755 /opt/n91-portal
cp -R -- backend web /opt/n91-portal/
chmod -R a+rX /opt/n91-portal/backend /opt/n91-portal/web
python3 -m venv /opt/n91-portal/.venv
/opt/n91-portal/.venv/bin/python -m pip install -r /opt/n91-portal/backend/requirements.txt

useradd --system --user-group --home-dir /var/lib/n91-portal --shell /usr/sbin/nologin n91-portal
install -d -m 0700 -o n91-portal -g n91-portal /var/lib/n91-portal
install -d -m 0750 -o root -g n91-portal /etc/n91-portal
seed=/dev/null
if [[ -f seed/p16h-import.jsonl ]]; then
    seed=seed/p16h-import.jsonl
fi
install -m 0640 -o root -g n91-portal "$seed" /var/lib/n91-portal/p16h-import.jsonl
install -m 0600 portal.env.example /etc/n91-portal/portal.env
install -m 0644 n91-portal.service n91-portal-p17.service n91-portal-p17.timer /etc/systemd/system/
install -m 0644 n91-portal.nginx.conf /etc/nginx/conf.d/n91-portal.conf
systemctl daemon-reload
nginx -t

printf '%s\n' 'Portal files installed. Continue with account setup and service startup in README.md.'
