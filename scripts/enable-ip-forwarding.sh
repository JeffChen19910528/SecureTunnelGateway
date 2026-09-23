#!/usr/bin/env bash
#
# SecureTunnel Gateway - Enable IPv4 forwarding
#
# Purpose:
#   Enable net.ipv4.ip_forward persistently via a dedicated file under
#   /etc/sysctl.d/, WITHOUT touching /etc/sysctl.conf or any other existing
#   sysctl configuration.
#
# Requires root. This script does NOT run automatically as part of any CLI
# command - it must be invoked manually by an operator who has reviewed it.
# It does not enable IPv6 forwarding (out of scope; see docs/security-model.md
# 第十五節 IPv6 洩漏) and it does not touch nftables.
#
# Usage:
#   sudo ./scripts/enable-ip-forwarding.sh --dry-run   # show what would change
#   sudo ./scripts/enable-ip-forwarding.sh              # apply
#   sudo ./scripts/enable-ip-forwarding.sh --revert     # restore previous state
#
# Persistence: writes /etc/sysctl.d/99-securetunnel-gateway.conf, which is
# applied automatically on every boot by systemd-sysctl. A reboot is not
# required; this script applies the change immediately via `sysctl -p`.

set -euo pipefail
IFS=$'\n\t'

SYSCTL_DROPIN="/etc/sysctl.d/99-securetunnel-gateway.conf"
BACKUP_PATH="${SYSCTL_DROPIN}.securetunnel-backup"
DRY_RUN=0
REVERT=0

for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY_RUN=1 ;;
    --revert) REVERT=1 ;;
    -h|--help)
      echo "Usage: $0 [--dry-run|--revert]"
      exit 0
      ;;
    *) echo "Unknown argument: $arg" >&2; exit 2 ;;
  esac
done

require_root() {
  if [[ "$(id -u)" -ne 0 ]]; then
    echo "ERROR: this script must be run as root (it modifies kernel network settings)." >&2
    echo "Re-run as: sudo $0 $*" >&2
    exit 1
  fi
}

if [[ "$REVERT" -eq 1 ]]; then
  require_root
  if [[ -f "$BACKUP_PATH" ]]; then
    echo "Restoring previous sysctl drop-in from $BACKUP_PATH"
    mv "$BACKUP_PATH" "$SYSCTL_DROPIN"
  elif [[ -f "$SYSCTL_DROPIN" ]]; then
    echo "No backup found; removing $SYSCTL_DROPIN (no prior version was recorded)"
    rm -f "$SYSCTL_DROPIN"
  else
    echo "Nothing to revert: $SYSCTL_DROPIN does not exist."
    exit 0
  fi
  sysctl --system >/dev/null
  echo "Current status:"
  sysctl net.ipv4.ip_forward
  exit 0
fi

CURRENT="$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo unknown)"
echo "Current net.ipv4.ip_forward = ${CURRENT}"

if [[ "$DRY_RUN" -eq 1 ]]; then
  echo "[DRY-RUN] Would write the following to ${SYSCTL_DROPIN}:"
  echo "----------------------------------------------------------"
  echo "# Managed by SecureTunnel Gateway - scripts/enable-ip-forwarding.sh"
  echo "net.ipv4.ip_forward = 1"
  echo "----------------------------------------------------------"
  echo "[DRY-RUN] Would then run: sysctl --system"
  echo "[DRY-RUN] No changes made. Re-run without --dry-run (as root) to apply."
  exit 0
fi

require_root

if [[ -f "$SYSCTL_DROPIN" ]]; then
  cp -p "$SYSCTL_DROPIN" "$BACKUP_PATH"
  echo "Backed up existing ${SYSCTL_DROPIN} to ${BACKUP_PATH}"
fi

cat > "$SYSCTL_DROPIN" <<'EOF'
# Managed by SecureTunnel Gateway - scripts/enable-ip-forwarding.sh
# Do not edit /etc/sysctl.conf for this setting; this file takes precedence
# and keeps the change isolated and revertible (see --revert).
net.ipv4.ip_forward = 1
EOF

sysctl --system >/dev/null

NEW="$(cat /proc/sys/net/ipv4/ip_forward)"
echo "Applied. net.ipv4.ip_forward is now: ${NEW}"

if [[ "$NEW" != "1" ]]; then
  echo "ERROR: verification failed - forwarding is not enabled after apply." >&2
  echo "Rollback: sudo $0 --revert" >&2
  exit 1
fi

echo "Persistence: enabled on every boot via ${SYSCTL_DROPIN} (systemd-sysctl)."
echo "To revert: sudo $0 --revert"
