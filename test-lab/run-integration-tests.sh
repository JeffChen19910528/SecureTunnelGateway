#!/usr/bin/env bash
#
# SecureTunnel Gateway - Real Linux integration test lab (Phase 7).
#
# See README.md in this directory for full context, honest status, and the mapping from
# each check here to the Phase 7 spec's 15-item list. THIS SCRIPT HAS NOT BEEN EXECUTED -
# it is prepared for a real Ubuntu Server, not run in this project's WSL2 dev environment
# (which lacks wireguard-tools/nftables/sudo). Read its output, don't assume it.
#
# Usage: sudo GATEWAY_BIN=/path/to/SecureTunnel.GatewayAgent ./run-integration-tests.sh [--with-packet-flow-test] [--keep-artifacts]

set -uo pipefail
IFS=$'\n\t'

WITH_PACKET_FLOW=0
KEEP_ARTIFACTS=0
for arg in "$@"; do
  case "$arg" in
    --with-packet-flow-test) WITH_PACKET_FLOW=1 ;;
    --keep-artifacts) KEEP_ARTIFACTS=1 ;;
    -h|--help) echo "Usage: sudo GATEWAY_BIN=<path> $0 [--with-packet-flow-test] [--keep-artifacts]"; exit 0 ;;
    *) echo "Unknown argument: $arg" >&2; exit 2 ;;
  esac
done

GATEWAY_BIN="${GATEWAY_BIN:-/usr/lib/securetunnel-gateway/SecureTunnel.GatewayAgent}"
WORKDIR="$(mktemp -d /tmp/securetunnel-lab.XXXXXX)"
CONFIG_PATH="${WORKDIR}/gateway.yaml"
IFACE="wgtest0"
PASS_COUNT=0
FAIL_COUNT=0
BLOCKED_COUNT=0
BLOCKED_ITEMS=()

pass() { echo "  PASS    - $1"; PASS_COUNT=$((PASS_COUNT + 1)); }
fail() { echo "  FAIL    - $1"; FAIL_COUNT=$((FAIL_COUNT + 1)); }
blocked() { echo "  BLOCKED - $1"; BLOCKED_COUNT=$((BLOCKED_COUNT + 1)); BLOCKED_ITEMS+=("$1"); }

cleanup() {
  if [[ "$KEEP_ARTIFACTS" -eq 1 ]]; then
    echo "Artifacts kept at: ${WORKDIR}"
    return
  fi
  wg-quick down "$IFACE" >/dev/null 2>&1 || true
  nft delete table inet securetunnel >/dev/null 2>&1 || true
  ip netns del st-peer-ns >/dev/null 2>&1 || true
  ip netns del st-resource-ns >/dev/null 2>&1 || true
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

echo "=== SecureTunnel Gateway - Real Linux Integration Test Lab ==="
echo "Working directory: ${WORKDIR}"
echo "Gateway binary: ${GATEWAY_BIN}"
echo ""

# ---------------------------------------------------------------------------
# Prerequisites - fail closed and BLOCKED, never silently continue.
# ---------------------------------------------------------------------------
if [[ "$(id -u)" -ne 0 ]]; then
  echo "FATAL: this script must run as root (wg-quick/nft/systemctl all require it)." >&2
  exit 1
fi
if [[ ! -x "$GATEWAY_BIN" ]]; then
  echo "FATAL: GATEWAY_BIN '${GATEWAY_BIN}' not found or not executable. Publish it first (see docs/installation-guide.md)." >&2
  exit 1
fi
for tool in wg wg-quick nft; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    blocked "prerequisite: '$tool' not installed - ALL checks below are BLOCKED"
    echo ""
    echo "=== Summary: 0 PASS, 0 FAIL, ${BLOCKED_COUNT} BLOCKED ==="
    exit 0
  fi
done

gw() { "$GATEWAY_BIN" "$@" --config "$CONFIG_PATH"; }

# ---------------------------------------------------------------------------
# Setup: keys + a minimal, real gateway.yaml
# ---------------------------------------------------------------------------
mkdir -p "${WORKDIR}/keys"
cat > "$CONFIG_PATH" << YAML
gatewayId: "gw-lab-test"
wireGuard:
  interfaceName: "${IFACE}"
  listenPort: 51900
  privateKeyPath: "${WORKDIR}/keys/server.key"
  publicKeyPath: "${WORKDIR}/keys/server.pub"
  address: "10.250.0.1/24"
  configOutputPath: "${WORKDIR}/${IFACE}.conf"
network:
  vpnCidr: "10.250.0.0/24"
  gatewayVpnAddress: "10.250.0.1"
  clientAddressPoolStart: "10.250.0.10"
  clientAddressPoolEnd: "10.250.0.200"
  lanInterface: "eth0"
  protectedNetworks:
    - name: "lab-protected-net"
      cidr: "10.20.0.0/24"
security:
  failClosed: true
peerStorePath: "${WORKDIR}/peers.json"
resourceStorePath: "${WORKDIR}/resources.json"
policyStorePath: "${WORKDIR}/policies.json"
firewallRulesetPath: "${WORKDIR}/ruleset.conf"
configurationHistoryPath: "${WORKDIR}/history.json"
operationLockPath: "${WORKDIR}/op.lock"
YAML

echo "--- wireguard generate-keys ---"
if gw wireguard generate-keys --yes >/dev/null 2>&1; then
  pass "server key pair generated"
else
  fail "wireguard generate-keys did not succeed"
fi

# ---------------------------------------------------------------------------
# 1, 2, 4: WireGuard interface creation, address, status
# ---------------------------------------------------------------------------
test_wireguard_interface_up() {
  echo "--- Checks 1, 2, 4: WireGuard interface ---"
  if ! gw config apply --yes >/dev/null 2>&1; then
    fail "config apply did not succeed (needed before the interface can come up)"
    return
  fi
  if wg show "$IFACE" >/dev/null 2>&1; then
    pass "WireGuard interface '${IFACE}' exists after config apply"
  else
    fail "WireGuard interface '${IFACE}' does not exist after config apply"
    return
  fi
  if ip addr show "$IFACE" 2>/dev/null | grep -q "10.250.0.1/24"; then
    pass "Gateway interface address is 10.250.0.1/24 as configured"
  else
    fail "Gateway interface address does not match configured 10.250.0.1/24"
  fi
  if gw wireguard status --json 2>/dev/null | grep -qi '"up"\|"Up"'; then
    pass "'wireguard status' reports the interface up"
  else
    fail "'wireguard status' does not report the interface up"
  fi
}

# ---------------------------------------------------------------------------
# 3: Peer configuration
# ---------------------------------------------------------------------------
PEER_ID=""
PEER_PRIVATE_KEY=""
test_peer_config() {
  echo "--- Check 3: Peer configuration ---"
  PEER_PRIVATE_KEY="$(wg genkey)"
  local peer_public_key
  peer_public_key="$(echo "$PEER_PRIVATE_KEY" | wg pubkey)"

  local add_output
  add_output="$(gw peer add --name lab-peer --public-key "$peer_public_key" --yes --json 2>&1)"
  if echo "$add_output" | grep -q '"Success":true\|"Success": true'; then
    pass "peer add succeeded"
  else
    fail "peer add did not succeed: ${add_output}"
    return
  fi
  PEER_ID="$(echo "$add_output" | grep -o '"PeerId":"[^"]*"\|"PeerId": "[^"]*"' | head -1 | sed -E 's/.*"([^"]+)"$/\1/')"
  if [[ -n "$PEER_ID" ]]; then
    pass "peer id resolved: ${PEER_ID}"
  else
    fail "could not resolve peer id from 'peer add' output"
  fi
}

# ---------------------------------------------------------------------------
# 5, 6: nftables table/chain creation, default-deny
# ---------------------------------------------------------------------------
test_nftables_table() {
  echo "--- Checks 5, 6: nftables table, chain, default-deny ---"
  if ! gw firewall apply --yes >/dev/null 2>&1; then
    fail "firewall apply did not succeed"
    return
  fi
  local rules
  rules="$(nft list table inet securetunnel 2>&1)"
  if [[ -z "$rules" ]]; then
    fail "'nft list table inet securetunnel' returned nothing"
    return
  fi
  pass "table inet securetunnel exists"
  if echo "$rules" | grep -q "chain forward" && echo "$rules" | grep -q "chain securetunnel_vpn_access" && echo "$rules" | grep -q "chain postrouting"; then
    pass "all three expected chains (forward, securetunnel_vpn_access, postrouting) are present"
  else
    fail "one or more expected chains are missing"
  fi
  if echo "$rules" | grep -A2 "chain forward" | grep -q "policy drop"; then
    pass "forward chain policy is drop (default-deny)"
  else
    fail "forward chain policy is NOT drop"
  fi
}

# ---------------------------------------------------------------------------
# 12, 13: config apply / rollback
# ---------------------------------------------------------------------------
test_config_apply_rollback() {
  echo "--- Checks 12, 13: config apply / rollback ---"
  local before_version
  before_version="$(gw config status --json 2>/dev/null | grep -o '"ActiveVersion":[0-9]*\|"ActiveVersion": [0-9]*' | grep -o '[0-9]*$')"

  if [[ -n "$PEER_ID" ]] && gw peer disable --id "$PEER_ID" --yes >/dev/null 2>&1 && gw config apply --yes >/dev/null 2>&1; then
    pass "config apply after a registry change created a new version"
  else
    fail "config apply after a registry change did not succeed"
    return
  fi

  local after_version
  after_version="$(gw config status --json 2>/dev/null | grep -o '"ActiveVersion":[0-9]*\|"ActiveVersion": [0-9]*' | grep -o '[0-9]*$')"
  if [[ -n "$before_version" && -n "$after_version" && "$after_version" -gt "$before_version" ]]; then
    pass "Active version incremented (${before_version} -> ${after_version})"
  else
    fail "Active version did not increment as expected"
  fi

  if [[ -n "$before_version" ]] && gw config rollback --version "$before_version" --yes >/dev/null 2>&1; then
    pass "config rollback to version ${before_version} succeeded"
  else
    fail "config rollback did not succeed"
  fi
}

# ---------------------------------------------------------------------------
# 14: Daemon startup and shutdown
# ---------------------------------------------------------------------------
test_daemon_lifecycle() {
  echo "--- Check 14: Daemon startup and shutdown ---"
  "$GATEWAY_BIN" gateway serve --config "$CONFIG_PATH" --interval-seconds 5 &
  local daemon_pid=$!
  sleep 2
  if kill -0 "$daemon_pid" 2>/dev/null; then
    pass "daemon started and is running (pid ${daemon_pid})"
  else
    fail "daemon exited immediately after starting"
    return
  fi

  kill -TERM "$daemon_pid"
  local waited=0
  while kill -0 "$daemon_pid" 2>/dev/null && [[ $waited -lt 15 ]]; do
    sleep 1
    waited=$((waited + 1))
  done
  if kill -0 "$daemon_pid" 2>/dev/null; then
    fail "daemon did not stop within 15s of SIGTERM"
    kill -KILL "$daemon_pid" 2>/dev/null || true
  else
    pass "daemon stopped gracefully after SIGTERM (within ${waited}s)"
  fi
}

# ---------------------------------------------------------------------------
# 15: Service restart behavior (only if the systemd unit is actually installed)
# ---------------------------------------------------------------------------
test_systemd_restart() {
  echo "--- Check 15: Service restart behavior ---"
  if ! systemctl list-unit-files securetunnel-gateway.service >/dev/null 2>&1; then
    blocked "systemd unit 'securetunnel-gateway.service' is not installed (run scripts/install.sh first to test this)"
    return
  fi
  if systemctl restart securetunnel-gateway 2>/dev/null && systemctl is-active --quiet securetunnel-gateway; then
    pass "systemctl restart securetunnel-gateway succeeded and the service is active"
  else
    fail "systemctl restart did not leave the service active"
  fi
}

# ---------------------------------------------------------------------------
# 7-11: Authorized/unauthorized access, disabled peer/resource, NAT - opt-in,
# uses network namespaces to simulate a peer and a protected resource on this
# single host. See README.md "Scope decision" for why this is opt-in.
# ---------------------------------------------------------------------------
test_packet_flow() {
  echo "--- Checks 7-11: Peer -> Resource authorization + NAT (netns-based) ---"
  if ! command -v ip >/dev/null 2>&1 || ! command -v nc >/dev/null 2>&1; then
    blocked "'ip' or 'nc' not available - cannot run the packet-flow test"
    return
  fi

  ip netns add st-resource-ns || { blocked "could not create network namespace 'st-resource-ns'"; return; }
  ip link add veth-res type veth peer name veth-res-ns
  ip link set veth-res-ns netns st-resource-ns
  ip addr add 10.20.0.254/24 dev veth-res
  ip link set veth-res up
  ip netns exec st-resource-ns ip addr add 10.20.0.10/24 dev veth-res-ns
  ip netns exec st-resource-ns ip link set veth-res-ns up
  ip netns exec st-resource-ns ip link set lo up
  ip netns exec st-resource-ns bash -c 'while true; do echo "resource-reachable" | nc -l -p 8443 -q1; done' &
  local nc_pid=$!
  sleep 1

  # Register the resource + an authorized policy for the peer created in test_peer_config.
  gw resource add --name lab-resource --destination 10.20.0.10 --protocol tcp --port 8443 --yes >/dev/null 2>&1
  local resource_id
  resource_id="$(gw resource list --json 2>/dev/null | grep -o '"ResourceId":"[^"]*"\|"ResourceId": "[^"]*"' | head -1 | sed -E 's/.*"([^"]+)"$/\1/')"

  if [[ -z "$PEER_ID" || -z "$resource_id" ]]; then
    blocked "peer or resource id unavailable - skipping the rest of the packet-flow test"
  else
    gw peer enable --id "$PEER_ID" --yes >/dev/null 2>&1
    gw policy add --peer-id "$PEER_ID" --resource-id "$resource_id" --yes >/dev/null 2>&1
    gw config apply --yes >/dev/null 2>&1

    # NOTE: fully connecting the peer's own WireGuard endpoint (a second netns running its
    # own `wg-quick` interface, peered to this Gateway's) is the remaining piece needed for
    # a true encrypted-tunnel, source-IP-preserved packet test; that setup is intentionally
    # left as a manual follow-up (see README.md) rather than scripted further here, since it
    # depends on kernel WireGuard module behavior inside network namespaces that varies by
    # host and is best validated interactively the first time, not blindly automated.
    blocked "full authorized/unauthorized/NAT packet-flow assertions require a second, manually-configured WireGuard peer namespace - infrastructure (resource netns + listener) is up, but the encrypted-tunnel leg is not scripted (see README.md)"
  fi

  kill "$nc_pid" 2>/dev/null || true
  ip link del veth-res 2>/dev/null || true
  ip netns del st-resource-ns 2>/dev/null || true
}

test_wireguard_interface_up
test_peer_config
test_nftables_table
test_config_apply_rollback
test_daemon_lifecycle
test_systemd_restart
if [[ "$WITH_PACKET_FLOW" -eq 1 ]]; then
  test_packet_flow
else
  blocked "packet-flow test (checks 7-11) skipped - pass --with-packet-flow-test to run it"
fi

echo ""
echo "=== Summary: ${PASS_COUNT} PASS, ${FAIL_COUNT} FAIL, ${BLOCKED_COUNT} BLOCKED ==="
if [[ "$BLOCKED_COUNT" -gt 0 ]]; then
  echo "Blocked items:"
  for item in "${BLOCKED_ITEMS[@]}"; do
    echo "  - ${item}"
  done
fi

[[ "$FAIL_COUNT" -eq 0 ]]
