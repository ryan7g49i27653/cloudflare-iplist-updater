#!/usr/bin/env bash
# Set up cf-iplist-updater on the server. Run from the cloned repo:
#
#   sudo deploy/install.sh
#
# Optional helper for running as a dedicated service user (README "Option A").
# Idempotent: creates the service user, private state/logs directories,
# config.toml (from the example, if missing) and the cron.d entry. To run as an
# existing account instead, follow README "Option B" and skip this script.
set -euo pipefail

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SERVICE_USER="${SERVICE_USER:-cfipupdater}"
CRON_FILE=/etc/cron.d/cloudflare-iplist-updater

if [[ $EUID -ne 0 ]]; then
    echo "run with sudo" >&2
    exit 1
fi

if ! id "$SERVICE_USER" &>/dev/null; then
    useradd --system --no-create-home --home-dir /nonexistent \
        --shell /usr/sbin/nologin "$SERVICE_USER"
    echo "created system user $SERVICE_USER"
fi

install -d -m 0700 -o "$SERVICE_USER" -g "$SERVICE_USER" "$APP_DIR/state" "$APP_DIR/logs"

if [[ ! -e "$APP_DIR/config.toml" ]]; then
    install -m 0600 -o "$SERVICE_USER" -g "$SERVICE_USER" \
        "$APP_DIR/config.example.toml" "$APP_DIR/config.toml"
    echo "created $APP_DIR/config.toml from the example"
else
    chown "$SERVICE_USER:$SERVICE_USER" "$APP_DIR/config.toml"
    chmod 0600 "$APP_DIR/config.toml"
fi

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT
sed -e "s#@APP_DIR@#$APP_DIR#g" -e "s#@USER@#$SERVICE_USER#g" \
    "$APP_DIR/deploy/cron.d.template" > "$tmp"
install -m 0644 -o root -g root "$tmp" "$CRON_FILE"
echo "installed $CRON_FILE"

cat <<EOF

Next steps:
  sudoedit $APP_DIR/config.toml
  cd $APP_DIR && sudo -u $SERVICE_USER python3 -m cf_iplist_updater --check
  cd $APP_DIR && sudo -u $SERVICE_USER python3 -m cf_iplist_updater --dry-run
EOF
