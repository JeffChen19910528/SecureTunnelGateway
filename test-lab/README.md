# Real Linux Integration Test Lab

This directory holds an **executable, documented** integration test script for validating
SecureTunnel Gateway against real `wireguard-tools`, `nftables`, and `systemd` on a real
Ubuntu Server — the 15 deployment checks below.

## Running it
Needs root, `wireguard-tools`, `nftables`, `iproute2`, `curl`, `python3` (and `tcpdump` for the NAT check) on an
Ubuntu Server or WSL2 Ubuntu 24.04. Environment variables: `GATEWAY_BIN`, `LAB_ROOT` (default
`/var/lib/securetunnel-lab`; must not be under `/tmp`, the Gateway rejects keys there), `IFACE`, `WG_PORT`, `LAN_IFACE`.

## What it covers

| # | Check | Script section |
|---|---|---|
| 1 | WireGuard interface creation | `test_wireguard_interface_up` |
| 2 | Gateway interface address | `test_wireguard_interface_up` |
| 3 | Peer configuration | `test_peer_config` |
| 4 | WireGuard service status | `test_wireguard_interface_up`, `gateway status` |
| 5 | nftables table/chain creation | `test_nftables_table` |
| 6 | Default-deny behavior | `test_nftables_table` (asserts `policy drop`, no unconditional accept) |
| 7 | Authorized Peer → Resource access | `test_packet_flow` (netns-based, opt-in) |
| 8 | Unauthorized Peer denial | `test_packet_flow` |
| 9 | Disabled/revoked Peer denial | `test_packet_flow` |
| 10 | Disabled Resource denial | `test_packet_flow` |
| 11 | NAT behavior | `test_packet_flow` (source IP masqueraded) |
| 12 | Configuration apply | `test_config_apply_rollback` |
| 13 | Configuration rollback | `test_config_apply_rollback` |
| 14 | Daemon startup and shutdown | `test_daemon_lifecycle` |
| 15 | Service restart behavior | `test_systemd_restart` (only if the unit is installed) |

## Scope decision: the packet-flow test (`test_packet_flow`) is opt-in

Checks 7–11 require an actual WireGuard peer and an actual reachable "protected resource".
Rather than requiring a second physical host (which most people validating this script
won't have on hand), `test_packet_flow` builds both out of Linux network namespaces on the
SAME machine (`ip netns` + `veth` — a standard, well-established way to test firewall/NAT
rules without extra hardware). This is the most complex, highest-risk part of the script
(most likely to behave differently across kernel/nft versions), so it is **disabled by
default** — pass `--with-packet-flow-test` to run it. Everything else runs by default.

## Usage

```bash
# On a real Ubuntu Server, as root, with wireguard-tools + nftables installed,
# and the Gateway Agent already published:
sudo GATEWAY_BIN=/usr/lib/securetunnel-gateway/SecureTunnel.GatewayAgent \
  ./run-integration-tests.sh [--with-packet-flow-test] [--keep-artifacts]
```

Every check prints exactly one of `PASS`, `FAIL`, or `BLOCKED` (BLOCKED = the environment
doesn't support running this check at all, e.g. a missing tool — never silently skipped,
never counted as a pass). The script exits non-zero if any check FAILs; BLOCKED checks do
not by themselves fail the run (an unmet prerequisite is not a product defect), but are
listed prominently in the final summary.

All state the script creates (temp config directory, netns, veth pairs, WireGuard keys) is
cleaned up on exit unless `--keep-artifacts` is passed for post-mortem debugging.
