#!/usr/bin/env bash
#
# SecureTunnel Gateway - IP Forwarding status check (read-only)
#
# Purpose: report current IPv4/IPv6 forwarding status. Never modifies the system.
#
# Usage:
#   ./scripts/check-ip-forwarding.sh
#   ./scripts/check-ip-forwarding.sh --json

set -euo pipefail
IFS=$'\n\t'

JSON_OUTPUT=0
for arg in "$@"; do
  case "$arg" in
    --json) JSON_OUTPUT=1 ;;
    -h|--help) echo "Usage: $0 [--json]"; exit 0 ;;
    *) echo "Unknown argument: $arg" >&2; exit 2 ;;
  esac
done

read_status() {
  local path="$1"
  if [[ -r "$path" ]]; then
    cat "$path"
  else
    echo "UNKNOWN"
  fi
}

IPV4_STATUS="$(read_status /proc/sys/net/ipv4/ip_forward)"
IPV6_STATUS="$(read_status /proc/sys/net/ipv6/conf/all/forwarding)"

ipv4_result="WARN"
ipv4_msg="IPv4 forwarding is disabled (expected before Gateway is configured)"
if [[ "$IPV4_STATUS" == "1" ]]; then
  ipv4_result="PASS"
  ipv4_msg="IPv4 forwarding is enabled"
elif [[ "$IPV4_STATUS" == "UNKNOWN" ]]; then
  ipv4_result="BLOCKED"
  ipv4_msg="Could not read /proc/sys/net/ipv4/ip_forward"
fi

ipv6_result="PASS"
ipv6_msg="IPv6 forwarding is disabled (expected default; see docs/security-model.md 第十五節)"
if [[ "$IPV6_STATUS" == "1" ]]; then
  ipv6_result="WARN"
  ipv6_msg="IPv6 forwarding is ENABLED. SecureTunnel Gateway does not enable this by default; verify this is intentional."
elif [[ "$IPV6_STATUS" == "UNKNOWN" ]]; then
  ipv6_result="BLOCKED"
  ipv6_msg="Could not read /proc/sys/net/ipv6/conf/all/forwarding (IPv6 may be disabled on this host)"
fi

if [[ "$JSON_OUTPUT" -eq 1 ]]; then
  cat <<EOF
{
  "ipv4Forwarding": {"status": "${ipv4_result}", "message": "${ipv4_msg}"},
  "ipv6Forwarding": {"status": "${ipv6_result}", "message": "${ipv6_msg}"}
}
EOF
else
  echo "SecureTunnel Gateway - IP Forwarding Status (read-only)"
  echo "========================================================"
  printf '[%-7s] IPv4 forwarding: %s\n' "$ipv4_result" "$ipv4_msg"
  printf '[%-7s] IPv6 forwarding: %s\n' "$ipv6_result" "$ipv6_msg"
fi

exit 0
