#!/usr/bin/env bash
#
# SecureTunnel Gateway - Environment Validation
#
# Purpose:
#   Read-only inspection of the host environment to determine whether it is
#   suitable for running SecureTunnel Gateway. This script NEVER installs
#   packages, modifies sysctl, touches firewall state, starts WireGuard, or
#   prompts for a password. It only reports PASS / WARN / FAIL / BLOCKED for
#   each check.
#
# Usage:
#   ./scripts/validate-environment.sh
#   ./scripts/validate-environment.sh --json
#
# Exit codes:
#   0 - no FAIL results (WARN/BLOCKED may still be present)
#   1 - at least one FAIL result
#
# Root/sudo:
#   This script does not require root to run. Some checks (e.g. kernel module
#   listing) may report less detail without root; those are marked WARN or
#   BLOCKED rather than silently passing.

set -euo pipefail
IFS=$'\n\t'

JSON_OUTPUT=0
for arg in "$@"; do
  case "$arg" in
    --json) JSON_OUTPUT=1 ;;
    -h|--help)
      echo "Usage: $0 [--json]"
      exit 0
      ;;
    *)
      echo "Unknown argument: $arg" >&2
      exit 2
      ;;
  esac
done

# results: array of "id|status|message"
declare -a RESULTS=()
OVERALL_FAIL=0

add_result() {
  local id="$1" status="$2" message="$3"
  RESULTS+=("${id}|${status}|${message}")
  if [[ "$status" == "FAIL" ]]; then
    OVERALL_FAIL=1
  fi
}

have_cmd() {
  command -v "$1" >/dev/null 2>&1
}

# ---------------------------------------------------------------------------
# 1. OS detection
# ---------------------------------------------------------------------------
if [[ -r /etc/os-release ]]; then
  # shellcheck disable=SC1091
  . /etc/os-release
  add_result "os.detected" "PASS" "OS detected: ${PRETTY_NAME:-unknown}"
else
  add_result "os.detected" "FAIL" "/etc/os-release not found; cannot determine OS"
fi

# ---------------------------------------------------------------------------
# 2. Distribution detection (Ubuntu expected)
# ---------------------------------------------------------------------------
if [[ "${ID:-}" == "ubuntu" ]]; then
  add_result "os.distribution" "PASS" "Distribution is Ubuntu (${VERSION_ID:-unknown})"
  if [[ "${VERSION_ID:-}" != "24.04" ]]; then
    add_result "os.distribution.version" "WARN" "Expected Ubuntu 24.04 LTS, found ${VERSION_ID:-unknown}. Other versions may work but are not the validated target."
  else
    add_result "os.distribution.version" "PASS" "Ubuntu 24.04 LTS confirmed"
  fi
else
  add_result "os.distribution" "WARN" "Distribution is '${ID:-unknown}', not Ubuntu. SecureTunnel Gateway targets Ubuntu Server 24.04 LTS; other distributions are untested."
fi

# ---------------------------------------------------------------------------
# 3. Kernel version
# ---------------------------------------------------------------------------
KERNEL_VERSION="$(uname -r || echo unknown)"
if [[ "$KERNEL_VERSION" == *"microsoft"* ]]; then
  add_result "kernel.version" "WARN" "Kernel is '${KERNEL_VERSION}' (WSL2). This is a development/logic-validation environment, not a production Linux Server."
else
  add_result "kernel.version" "PASS" "Kernel: ${KERNEL_VERSION}"
fi

# ---------------------------------------------------------------------------
# 4. Architecture
# ---------------------------------------------------------------------------
ARCH="$(uname -m || echo unknown)"
if [[ "$ARCH" == "x86_64" ]]; then
  add_result "os.architecture" "PASS" "Architecture: ${ARCH}"
else
  add_result "os.architecture" "WARN" "Architecture is ${ARCH}; SecureTunnel Gateway is primarily validated on x86_64."
fi

# ---------------------------------------------------------------------------
# 5. Root / sudo availability (informational only, never prompts)
# ---------------------------------------------------------------------------
if [[ "$(id -u)" -eq 0 ]]; then
  add_result "privileges.root" "PASS" "Running as root"
elif sudo -n true 2>/dev/null; then
  add_result "privileges.root" "PASS" "Passwordless sudo available"
else
  add_result "privileges.root" "WARN" "Not running as root and passwordless sudo is not available. Operations requiring root must be run manually; this script will not prompt for a password."
fi

# ---------------------------------------------------------------------------
# 6. WireGuard command detection (wg)
# ---------------------------------------------------------------------------
if have_cmd wg; then
  WG_VERSION="$(wg --version 2>/dev/null || echo unknown)"
  add_result "wireguard.wg" "PASS" "wg found: ${WG_VERSION}"
else
  add_result "wireguard.wg" "BLOCKED" "'wg' command not found. Install with: sudo apt-get install -y wireguard-tools (manual step, not performed by this script)."
fi

# ---------------------------------------------------------------------------
# 7. wg-quick detection
# ---------------------------------------------------------------------------
if have_cmd wg-quick; then
  add_result "wireguard.wg-quick" "PASS" "wg-quick found"
else
  add_result "wireguard.wg-quick" "BLOCKED" "'wg-quick' command not found. Provided by the wireguard-tools package."
fi

# ---------------------------------------------------------------------------
# 8. WireGuard kernel module detection
# ---------------------------------------------------------------------------
KERNEL_REL="$(uname -r 2>/dev/null || echo '')"
WG_MODULE_PATH="/lib/modules/${KERNEL_REL}/kernel/drivers/net/wireguard/wireguard.ko"
if [[ -f "$WG_MODULE_PATH" ]]; then
  add_result "wireguard.kernel-module" "PASS" "WireGuard kernel module present at ${WG_MODULE_PATH}"
elif lsmod 2>/dev/null | grep -q '^wireguard'; then
  add_result "wireguard.kernel-module" "PASS" "WireGuard kernel module currently loaded"
else
  add_result "wireguard.kernel-module" "WARN" "WireGuard kernel module not found at expected path and not currently loaded. It may still be available via a different mechanism (e.g. built-in, DKMS); this could not be confirmed without root or modprobe access."
fi

# ---------------------------------------------------------------------------
# 9. nftables command detection
# ---------------------------------------------------------------------------
if have_cmd nft; then
  NFT_VERSION="$(nft --version 2>/dev/null || echo unknown)"
  add_result "nftables.nft" "PASS" "nft found: ${NFT_VERSION}"
else
  add_result "nftables.nft" "BLOCKED" "'nft' command not found. Install with: sudo apt-get install -y nftables (manual step, not performed by this script)."
fi

# ---------------------------------------------------------------------------
# 10. ip command detection
# ---------------------------------------------------------------------------
if have_cmd ip; then
  add_result "networking.ip" "PASS" "'ip' command found"
else
  add_result "networking.ip" "FAIL" "'ip' command not found (usually provided by iproute2). Required for interface/route management."
fi

# ---------------------------------------------------------------------------
# 11. systemctl detection
# ---------------------------------------------------------------------------
if have_cmd systemctl; then
  add_result "systemd.systemctl" "PASS" "'systemctl' command found"
else
  add_result "systemd.systemctl" "WARN" "'systemctl' not found. The Gateway Agent is designed to run as a systemd service; without systemd it must be run/managed manually."
fi

# ---------------------------------------------------------------------------
# 12. systemd availability (PID 1 check)
# ---------------------------------------------------------------------------
if [[ -d /run/systemd/system ]]; then
  add_result "systemd.running" "PASS" "systemd is the running init system"
else
  add_result "systemd.running" "WARN" "systemd does not appear to be the running init system (/run/systemd/system missing). Common in some containers and minimal WSL configurations."
fi

# ---------------------------------------------------------------------------
# 13. IP forwarding status (read-only)
# ---------------------------------------------------------------------------
if [[ -r /proc/sys/net/ipv4/ip_forward ]]; then
  IPV4_FWD="$(cat /proc/sys/net/ipv4/ip_forward)"
  if [[ "$IPV4_FWD" == "1" ]]; then
    add_result "networking.ipv4-forward" "PASS" "IPv4 forwarding is currently enabled"
  else
    add_result "networking.ipv4-forward" "WARN" "IPv4 forwarding is currently disabled (expected before Gateway is configured). Enable later via scripts/enable-ip-forwarding.sh."
  fi
else
  add_result "networking.ipv4-forward" "FAIL" "Cannot read /proc/sys/net/ipv4/ip_forward"
fi

if [[ -r /proc/sys/net/ipv6/conf/all/forwarding ]]; then
  IPV6_FWD="$(cat /proc/sys/net/ipv6/conf/all/forwarding)"
  if [[ "$IPV6_FWD" == "1" ]]; then
    add_result "networking.ipv6-forward" "WARN" "IPv6 forwarding is currently enabled. SecureTunnel Gateway does not enable this by default and does not validate IPv6 paths; verify this is intentional."
  else
    add_result "networking.ipv6-forward" "PASS" "IPv6 forwarding is disabled (expected default)"
  fi
else
  add_result "networking.ipv6-forward" "WARN" "Cannot read IPv6 forwarding status (IPv6 may be disabled on this host)"
fi

# ---------------------------------------------------------------------------
# 14. Network interface discovery
# ---------------------------------------------------------------------------
if have_cmd ip; then
  IFACE_LIST="$(ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | grep -v '^lo$' || true)"
  if [[ -n "$IFACE_LIST" ]]; then
    IFACE_SUMMARY="$(echo "$IFACE_LIST" | tr '\n' ',' | sed 's/,$//')"
    add_result "networking.interfaces" "PASS" "Non-loopback interfaces found: ${IFACE_SUMMARY}"
  else
    add_result "networking.interfaces" "FAIL" "No non-loopback network interfaces found"
  fi
else
  add_result "networking.interfaces" "BLOCKED" "Cannot enumerate interfaces without 'ip' command"
fi

# ---------------------------------------------------------------------------
# 15. Required directory permission check
# ---------------------------------------------------------------------------
declare -A REQUIRED_DIRS=(
  ["config"]="/etc/securetunnel-gateway"
  ["log"]="/var/log/securetunnel-gateway"
)
for label in "${!REQUIRED_DIRS[@]}"; do
  dir="${REQUIRED_DIRS[$label]}"
  if [[ -d "$dir" ]]; then
    if [[ -w "$dir" ]]; then
      add_result "directories.${label}" "PASS" "$dir exists and is writable by current user"
    else
      add_result "directories.${label}" "WARN" "$dir exists but is not writable by current user"
    fi
  else
    add_result "directories.${label}" "WARN" "$dir does not exist yet. It will need to be created (as root) during installation."
  fi
done

# ---------------------------------------------------------------------------
# 16. .NET runtime / SDK detection
# ---------------------------------------------------------------------------
if have_cmd dotnet; then
  DOTNET_VERSION="$(dotnet --version 2>/dev/null || echo unknown)"
  if [[ "$DOTNET_VERSION" == 10.* ]]; then
    add_result "dotnet.version" "PASS" ".NET SDK/Runtime ${DOTNET_VERSION} found"
  else
    add_result "dotnet.version" "WARN" ".NET found but version is ${DOTNET_VERSION}, expected 10.x. Do not downgrade the project without explicit confirmation."
  fi
else
  add_result "dotnet.version" "BLOCKED" "'dotnet' command not found on this host. The Gateway Agent requires the .NET 10 runtime to execute on the target Linux server."
fi

# ---------------------------------------------------------------------------
# 17. Docker detection (informational only; NOT required for WireGuard)
# ---------------------------------------------------------------------------
if have_cmd docker; then
  if docker version >/dev/null 2>&1; then
    add_result "docker.available" "PASS" "Docker CLI found and daemon reachable (used only for test-lab, never required for WireGuard/nftables)"
  else
    add_result "docker.available" "WARN" "Docker CLI found but daemon not reachable. Docker is only used for test-lab protected services, not for WireGuard/nftables."
  fi
else
  add_result "docker.available" "WARN" "Docker not found. Not required for WireGuard/nftables."
fi

# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------
if [[ "$JSON_OUTPUT" -eq 1 ]]; then
  printf '{\n  "checks": [\n'
  total=${#RESULTS[@]}
  i=0
  for entry in "${RESULTS[@]}"; do
    i=$((i+1))
    IFS='|' read -r id status message <<< "$entry"
    esc_message="${message//\\/\\\\}"
    esc_message="${esc_message//\"/\\\"}"
    comma=","
    if [[ "$i" -eq "$total" ]]; then comma=""; fi
    printf '    {"id": "%s", "status": "%s", "message": "%s"}%s\n' "$id" "$status" "$esc_message" "$comma"
  done
  printf '  ],\n  "overallFail": %s\n}\n' "$([[ $OVERALL_FAIL -eq 1 ]] && echo true || echo false)"
else
  echo "SecureTunnel Gateway - Environment Validation"
  echo "=============================================="
  for entry in "${RESULTS[@]}"; do
    IFS='|' read -r id status message <<< "$entry"
    printf '[%-7s] %-32s %s\n' "$status" "$id" "$message"
  done
  echo "=============================================="
  if [[ "$OVERALL_FAIL" -eq 1 ]]; then
    echo "Result: FAIL present - environment is not fully ready."
  else
    echo "Result: no FAIL. WARN/BLOCKED items still require manual attention before production use."
  fi
fi

exit "$OVERALL_FAIL"
