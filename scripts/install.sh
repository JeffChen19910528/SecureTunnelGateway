#!/usr/bin/env bash
#
# SecureTunnel Gateway - Installation script
#
# Purpose:
#   Creates the Linux deployment layout (directories + permissions), installs the
#   published Gateway Agent binary and helper scripts, and installs (but does not
#   enable/start) the systemd unit. Does NOT install wireguard-tools/nftables, generate
#   keys, or write a real gateway.yaml - those are separate, deliberate steps (see
#   docs/installation-guide.md) so this script's blast radius is limited to "lay out the
#   directories and binary", not "make irreversible security decisions on your behalf".
#
# Requires root (creates system directories and installs a systemd unit).
#
# Usage:
#   sudo ./scripts/install.sh --publish-dir <path-to-dotnet-publish-output> [--dry-run]
#
# Idempotency: safe to re-run. Existing config/data files are never overwritten; only the
# binary and systemd unit are replaced (that is the point of an upgrade - see
# docs/operations-guide.md "Upgrade and Rollback").

set -euo pipefail
IFS=$'\n\t'

BIN_DIR="/usr/lib/securetunnel-gateway"
CONFIG_DIR="/etc/securetunnel-gateway"
KEYS_DIR="${CONFIG_DIR}/keys"
DATA_DIR="/var/lib/securetunnel-gateway"
BACKUP_DIR="${DATA_DIR}/backups"
LOG_DIR="/var/log/securetunnel-gateway"
SYSTEMD_UNIT_SRC="deploy/systemd/securetunnel-gateway.service"
SYSTEMD_UNIT_DEST="/etc/systemd/system/securetunnel-gateway.service"

PUBLISH_DIR=""
DRY_RUN=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --publish-dir) PUBLISH_DIR="$2"; shift 2 ;;
    --dry-run) DRY_RUN=1; shift ;;
    -h|--help)
      echo "Usage: sudo $0 --publish-dir <path> [--dry-run]"
      exit 0
      ;;
    *) echo "Unknown argument: $1" >&2; exit 2 ;;
  esac
done

if [[ -z "$PUBLISH_DIR" ]]; then
  echo "ERROR: --publish-dir is required (output of:" >&2
  echo "  dotnet publish src/SecureTunnel.GatewayAgent -c Release -r linux-x64 --self-contained true -o <path>)" >&2
  exit 2
fi

if [[ ! -f "${PUBLISH_DIR}/SecureTunnel.GatewayAgent" ]]; then
  echo "ERROR: '${PUBLISH_DIR}/SecureTunnel.GatewayAgent' not found. Point --publish-dir at a dotnet publish output directory." >&2
  exit 1
fi

if [[ "$DRY_RUN" -eq 1 ]]; then
  echo "[DRY-RUN] Would create directories:"
  for d in "$BIN_DIR" "$CONFIG_DIR" "$KEYS_DIR" "$DATA_DIR" "$BACKUP_DIR" "$LOG_DIR"; do
    echo "  $d"
  done
  echo "[DRY-RUN] Would copy '${PUBLISH_DIR}' contents to '${BIN_DIR}'."
  echo "[DRY-RUN] Would copy scripts/*.sh to '${BIN_DIR}/scripts/'."
  echo "[DRY-RUN] Would install systemd unit to '${SYSTEMD_UNIT_DEST}' and run 'systemctl daemon-reload'."
  echo "[DRY-RUN] Would NOT enable or start the service, NOT install wireguard-tools/nftables, NOT generate keys."
  exit 0
fi

if [[ "$(id -u)" -ne 0 ]]; then
  echo "ERROR: this script must be run as root (it writes to /usr/lib, /etc, /var/lib, /var/log and installs a systemd unit)." >&2
  echo "Re-run as: sudo $0 --publish-dir '${PUBLISH_DIR}'" >&2
  exit 1
fi

echo "Creating directories..."
install -d -m 0755 "$BIN_DIR"
install -d -m 0750 "$CONFIG_DIR"
install -d -m 0700 "$KEYS_DIR"
install -d -m 0750 "$DATA_DIR"
install -d -m 0700 "$BACKUP_DIR"
install -d -m 0750 "$LOG_DIR"

echo "Installing binary to ${BIN_DIR}..."
cp -a "${PUBLISH_DIR}/." "$BIN_DIR/"
chmod 0755 "${BIN_DIR}/SecureTunnel.GatewayAgent"

echo "Installing helper scripts to ${BIN_DIR}/scripts..."
install -d -m 0755 "${BIN_DIR}/scripts"
cp scripts/*.sh "${BIN_DIR}/scripts/"
chmod 0755 "${BIN_DIR}"/scripts/*.sh

if [[ -f "$SYSTEMD_UNIT_SRC" ]]; then
  echo "Installing systemd unit to ${SYSTEMD_UNIT_DEST}..."
  cp "$SYSTEMD_UNIT_SRC" "$SYSTEMD_UNIT_DEST"
  chmod 0644 "$SYSTEMD_UNIT_DEST"
  systemctl daemon-reload
else
  echo "WARNING: ${SYSTEMD_UNIT_SRC} not found next to this script; skipping systemd unit installation." >&2
fi

echo ""
echo "Installation complete. The service was installed but NOT enabled or started."
echo "Remaining manual steps:"
echo "  1. sudo apt-get install -y wireguard-tools nftables   # if not already installed"
echo "  2. Create ${CONFIG_DIR}/gateway.yaml (copy from config/gateway.example.yaml and edit)"
echo "  3. sudo ${BIN_DIR}/SecureTunnel.GatewayAgent wireguard generate-keys --config ${CONFIG_DIR}/gateway.yaml --yes"
echo "  4. sudo systemctl enable --now securetunnel-gateway"
echo "  5. ${BIN_DIR}/SecureTunnel.GatewayAgent gateway status --config ${CONFIG_DIR}/gateway.yaml"
