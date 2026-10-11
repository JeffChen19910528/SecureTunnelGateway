#!/usr/bin/env bash
#
# SecureTunnel Gateway - Uninstallation script
#
# Purpose:
#   Stops/disables the systemd service and removes the installed binary and systemd
#   unit. By default it PRESERVES all state under /etc/securetunnel-gateway and
#   /var/lib/securetunnel-gateway (config, peer/resource/policy registries, keys,
#   configuration history, backups) and /var/log/securetunnel-gateway, because that
#   data cannot be regenerated and deleting it silently would violate the project's
#   "never silently delete recoverable state" rule.
#   Pass --purge-data to explicitly also remove that state - this is the ONLY way
#   uninstall.sh will ever delete it, and it requires a separate, explicit --yes-i-am-sure
#   confirmation flag as well, since it is irreversible (private keys, peer registry).
#
# Firewall/interface cleanup: removes ONLY `table inet securetunnel` (nftables) and brings
# down ONLY the Gateway's own WireGuard interface, by exact name - never a blanket
# `nft flush ruleset` and never any other interface. This runs regardless of --purge-data
# (it releases kernel/runtime state, not persisted data) and is always best-effort: a
# missing `nft`/`wg-quick`, an already-down interface, or an already-absent table are not
# errors.
#
# Requires root.
#
# Usage:
#   sudo ./scripts/uninstall.sh [--dry-run]
#   sudo ./scripts/uninstall.sh --purge-data --yes-i-am-sure   # also deletes all state

set -euo pipefail
IFS=$'\n\t'

BIN_DIR="/usr/lib/securetunnel-gateway"
CONFIG_DIR="/etc/securetunnel-gateway"
DATA_DIR="/var/lib/securetunnel-gateway"
LOG_DIR="/var/log/securetunnel-gateway"
SYSTEMD_UNIT="/etc/systemd/system/securetunnel-gateway.service"
SERVICE_NAME="securetunnel-gateway"
GATEWAY_YAML="${CONFIG_DIR}/gateway.yaml"
NFT_TABLE="inet securetunnel"

# Extracts wireGuard.interfaceName from gateway.yaml with a plain grep/sed (no YAML parser
# dependency in a shell script) - good enough for this single, simple, well-known key.
get_interface_name() {
  [[ -f "$GATEWAY_YAML" ]] || return 1
  grep -E '^\s*interfaceName:' "$GATEWAY_YAML" 2>/dev/null | head -n1 | sed -E 's/^\s*interfaceName:\s*"?([^"[:space:]]+)"?\s*$/\1/'
}

DRY_RUN=0
PURGE_DATA=0
CONFIRM_PURGE=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) DRY_RUN=1; shift ;;
    --purge-data) PURGE_DATA=1; shift ;;
    --yes-i-am-sure) CONFIRM_PURGE=1; shift ;;
    -h|--help)
      echo "Usage: sudo $0 [--dry-run] [--purge-data --yes-i-am-sure]"
      exit 0
      ;;
    *) echo "Unknown argument: $1" >&2; exit 2 ;;
  esac
done

if [[ "$PURGE_DATA" -eq 1 && "$CONFIRM_PURGE" -ne 1 ]]; then
  echo "ERROR: --purge-data requires --yes-i-am-sure as well (this permanently deletes" >&2
  echo "the WireGuard private key, peer/resource/policy registries, configuration" >&2
  echo "history, and all backups under ${DATA_DIR} and ${CONFIG_DIR})." >&2
  exit 2
fi

if [[ "$DRY_RUN" -eq 1 ]]; then
  echo "[DRY-RUN] Would run: systemctl disable --now ${SERVICE_NAME} (ignoring errors if not installed/running)"
  iface="$(get_interface_name || true)"
  if [[ -n "$iface" ]]; then
    echo "[DRY-RUN] Would run: wg-quick down ${iface} (best-effort, ignoring errors)"
  else
    echo "[DRY-RUN] No interfaceName found in ${GATEWAY_YAML} (or file missing) - would skip wg-quick down."
  fi
  echo "[DRY-RUN] Would run: nft delete table ${NFT_TABLE} (best-effort, ONLY this exact table, ignoring errors)"
  echo "[DRY-RUN] Would remove: ${SYSTEMD_UNIT}"
  echo "[DRY-RUN] Would run: systemctl daemon-reload"
  echo "[DRY-RUN] Would remove: ${BIN_DIR}"
  if [[ "$PURGE_DATA" -eq 1 ]]; then
    echo "[DRY-RUN] --purge-data given: would ALSO remove ${CONFIG_DIR}, ${DATA_DIR}, ${LOG_DIR}"
  else
    echo "[DRY-RUN] Would PRESERVE ${CONFIG_DIR}, ${DATA_DIR}, ${LOG_DIR} (pass --purge-data to remove them too)"
  fi
  exit 0
fi

if [[ "$(id -u)" -ne 0 ]]; then
  echo "ERROR: this script must be run as root." >&2
  exit 1
fi

echo "Stopping and disabling ${SERVICE_NAME} (if installed)..."
systemctl disable --now "${SERVICE_NAME}" 2>/dev/null || true

iface="$(get_interface_name || true)"
if [[ -n "$iface" ]] && command -v wg-quick >/dev/null 2>&1; then
  echo "Bringing down WireGuard interface '${iface}' (best-effort)..."
  wg-quick down "$iface" 2>/dev/null || true
fi

if command -v nft >/dev/null 2>&1; then
  echo "Removing nftables table '${NFT_TABLE}' (best-effort; no other table is touched)..."
  nft delete table ${NFT_TABLE} 2>/dev/null || true
fi

if [[ -f "$SYSTEMD_UNIT" ]]; then
  echo "Removing systemd unit ${SYSTEMD_UNIT}..."
  rm -f "$SYSTEMD_UNIT"
  systemctl daemon-reload
fi

if [[ -d "$BIN_DIR" ]]; then
  echo "Removing binary directory ${BIN_DIR}..."
  rm -rf "$BIN_DIR"
fi

if [[ "$PURGE_DATA" -eq 1 ]]; then
  echo "Purging data (--purge-data --yes-i-am-sure was given)..."
  [[ -d "$CONFIG_DIR" ]] && rm -rf "$CONFIG_DIR"
  [[ -d "$DATA_DIR" ]] && rm -rf "$DATA_DIR"
  [[ -d "$LOG_DIR" ]] && rm -rf "$LOG_DIR"
  echo "All SecureTunnel Gateway data has been permanently removed."
else
  echo ""
  echo "Uninstall complete. The following were PRESERVED (not deleted):"
  echo "  ${CONFIG_DIR}  (config, keys)"
  echo "  ${DATA_DIR}    (peer/resource/policy registries, configuration history, backups)"
  echo "  ${LOG_DIR}     (nothing written here directly - logs live in journald)"
  echo "Re-run with --purge-data --yes-i-am-sure to remove them permanently."
fi
