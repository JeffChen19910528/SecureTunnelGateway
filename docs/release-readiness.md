# Release Readiness Report — Phase 8

> **Phase 8 status: BLOCKED (not COMPLETED).** Per the Phase 8 spec's own explicit completion
> criteria ("If the environment remains unavailable, mark this phase BLOCKED rather than
> COMPLETED"), this phase cannot be marked COMPLETED: no real Ubuntu Server with
> `wireguard-tools`/`nftables`/passwordless-root access was available in this session, and
> per standing project instruction this Gateway Agent does not install packages or acquire
> passwordless sudo on its own initiative. This report documents exactly what that means,
> what already-completed work from Phases 1–7 it does NOT invalidate, and what is required
> to actually close this phase out.

## 1. Required Environment — Documented and Verified

The environment actually available in this session was probed directly (not assumed) on
2026-09-23:

| Item | Required (per spec) | Actual (this session) |
|---|---|---|
| OS | Ubuntu Server 22.04/24.04 LTS | Ubuntu 24.04.4 LTS — but running **inside WSL2**, not a standalone server install |
| Kernel | A real Linux kernel with the WireGuard module available | `6.6.87.2-microsoft-standard-WSL2` — a Microsoft-built WSL2 kernel; WireGuard kernel module availability under this specific kernel build was not checked further since `wg`/`wg-quick` aren't installed to test it with |
| systemd | Available, real unit lifecycle | systemd 255 (255.4-1ubuntu8.17) — present and previously used for real `systemd-analyze verify` (Phase 6/6A), but never for a real `systemctl start`/`stop`/`restart` cycle of this project's own unit |
| root/sudo | Passwordless or interactively available for genuine testing | `sudo -n true` → "a password is required": **not passwordless**. The invoking user (`owner`) is in the `sudo` group, so interactive `sudo` would work if a human typed the password — but this agent does not attempt to acquire or bypass that, per standing instruction |
| wireguard-tools (`wg`, `wg-quick`) | Installed | **NOT installed** (`command -v wg`/`wg-quick` both failed) |
| nftables (`nft`) | Installed | **NOT installed** |
| iproute2 (`ip`) | Installed | Installed — `iproute2-6.1.0` |
| Network namespace support | Available (`ip netns`) | `ip netns list` runs and exits 0 (kernel/tooling support present); actual namespace creation requires root, not tested |
| Firewall environment | Documented (ufw/iptables presence) | Neither `ufw` nor `iptables` is installed on this host — nftables would be the only firewall layer once installed, consistent with this project's design choice (see docs/firewall-model.md §1) |
| Interfaces / routes | Documented | `eth0` (172.23.13.160/20, WSL2 NAT'd network), default route via 172.23.0.1; no interface resembling a real LAN-facing/protected-network NIC is present |
| Hardware | N/A | 20 vCPU, 31 GiB RAM available to the WSL2 VM — resource-wise more than sufficient, not a constraint |

**Conclusion: this environment does not meet Phase 8's stated requirements.** It is the same
WSL2 development environment used (and honestly reported as insufficient for real
`nft`/`wg` execution) throughout Phases 1–7 — nothing changed. A genuine standalone Ubuntu
Server (bare metal, cloud VM, or a "real" VM with its own kernel — not WSL2) with root
access and `wireguard-tools`/`nftables` installed is required to actually execute Phase 8.

## 2. Test Lab Execution

`test-lab/run-integration-tests.sh` was **not executed** this session (its prerequisite
check — `wg`, `wg-quick`, `nft` all present — would itself immediately report every check
BLOCKED and exit, per the script's own fail-fast prerequisite gate; running it here would
have produced a report that says nothing more than section 1 above already says, so it was
not run redundantly). `--with-packet-flow-test` was likewise not attempted.

No packet-flow validation table (source/destination IP, protocol, port, expected vs.
actual result, responsible nftables rule, NAT observation, packet capture) exists for this
session, because no packet ever traversed a real WireGuard tunnel or nftables ruleset here.
Fabricating such a table would violate the project's standing "never claim a test passed
unless the real command or packet flow was actually executed" rule — none is presented.

## 3. Apply/Rollback, Daemon, and Uninstall — Validated Against MOCKED State Only

All of the following were exercised in this session **only** through the xUnit test suite
(`MockSystemCommandExecutor` standing in for `wg`/`wg-quick`/`nft`) and are therefore
**command-success / configuration-state** validation, not **actual WireGuard
state / actual nftables state / actual packet-flow** validation (the four categories the
Phase 8 spec explicitly asks to be kept distinct):

- Successful apply, invalid candidate, WireGuard-fails/nftables-succeeds and vice versa,
  verification failure, rollback to a known-good version: all covered by
  `tests/LifecycleTests`, `tests/IntegrationTests` (mocked).
- Daemon startup/shutdown, crash-recovery classification: covered by `tests/DaemonTests`
  (mocked/faked dependencies, not real `wg`/`nft`, not a real `systemctl` lifecycle).
- Uninstall (normal, preserved-data, purge, scoped WireGuard/nftables cleanup, missing
  interface/table): `scripts/uninstall.sh`'s logic was verified via `bash -n` and a real
  `--dry-run` execution in WSL2 (Phase 7), including correctly parsing `interfaceName` from
  a real `gateway.yaml` file — but the actual `wg-quick down`/`nft delete table` lines have
  never executed for real (no interface/table exists to clean up in this environment), and
  "unrelated nftables table preservation" has never been observed against a real second
  table.

None of this is new information relative to Phases 6/6A/7's own completion reports; it is
restated here because Phase 8 specifically asks for state-consistency claims to be kept
separate from command-success claims, and that separation is worth making explicit once
more in a dedicated release document.

## 4. Privilege Validation

Not newly tested this session (would require the same missing root + tools). Restated from
Phase 6/7: the systemd unit runs `User=root` by default; a documented,
**explicitly-still-unverified** `CAP_NET_ADMIN`-only alternative is present as a commented-out
block in `deploy/systemd/securetunnel-gateway.service` with its own verification checklist.
This project has never claimed non-root operation works — that claim remains correctly
unmade.

## 5. Security Review — Classified

Per the Phase 8 spec's four-way classification (Fixed / Accepted Risk / Deferred / Failed),
carrying forward Phase 7's findings (see docs/security-model.md §25) with no new findings
from this session (no new code was exercised against a real environment):

| Finding | Classification |
|---|---|
| Default-deny firewall behavior | **Fixed** (Phase 4; structural via `policy drop`, not a deny rule) |
| No allow-all fallback | **Fixed** (Phase 1–7, reconfirmed every phase, see security-model.md "重新確認" sections) |
| IPv6 behavior | **Fixed** — denied by construction (`inet` family + IPv4-only accept matchers), regression-tested (Phase 7). Real-packet IPv6 rejection: **Deferred** (needs real environment) |
| Routed Mode rejection | **Fixed** (Phase 1/2 validator rejection, unchanged) |
| Unauthorized Peer behavior | **Fixed** in rule-generation logic (Phase 4); real-packet observation: **Deferred** |
| Revoked Peer behavior | **Fixed** in rule-generation logic (Phase 3/4); real-packet observation: **Deferred** |
| Restore failure handling | **Fixed** (Phase 7 partial-restore hardening) |
| Secret leakage | **Fixed** — reviewed, no known path (Phase 7); not re-tested against real journald output in this session |
| nftables ownership boundaries | **Fixed** (single named table, never touches others; Phase 4/7) |
| Uninstall cleanup scope | **Fixed** in logic (Phase 7 scoped cleanup); real execution against a live table: **Deferred** |
| systemd privilege model | **Accepted Risk** — root-by-default is a documented, deliberate choice pending real `CAP_NET_ADMIN` verification, not a defect |
| Configuration History integrity | **Accepted Risk** — reviewed in Phase 7, no cryptographic signing added; judged proportionate given equivalent local-write-access threat model |
| Gateway host input-chain responsibility | **Accepted Risk** — deliberately left to the operator's own OS firewall (Phase 4/7 reviewed and reaffirmed) |

No item is classified **Failed** — nothing was found broken; the unresolved items are
**Deferred** because they require an environment this session does not have, not because a
test was run and failed.

## 6. Release Readiness Summary

| Category | Status |
|---|---|
| Functional validation (unit/integration, mocked) | ✅ Complete — 372/372 xUnit tests passing |
| Real Linux validation | ❌ Not performed this session (environment unavailable) |
| Packet-flow validation | ❌ Not performed (no real tunnel ever established) |
| Firewall validation | ⚠️ Rule generation/syntax validated on real Linux (Phase 4); real enforcement not validated |
| NAT validation | ❌ Not performed (no real packet ever traversed the postrouting chain) |
| Apply/rollback validation | ⚠️ Validated against mocked WireGuard/nftables state only |
| Daemon validation | ⚠️ Validated in isolation (Phase 6A) and via a real linux-x64 binary run (`--once`, correctly detected missing tools) — never under a real `systemctl` lifecycle |
| Backup/restore validation | ✅ Thoroughly validated (real file I/O, real tar/gzip, genuine corruption/partial-failure/path-traversal test cases) — this category does not depend on `wg`/`nft` |
| Uninstall validation | ⚠️ Logic verified (dry-run, real parsing); real cleanup execution not performed |
| Security findings | ✅ Reviewed this phase and Phase 7 (see §5 above); nothing outstanding classified as unresolved-and-unacceptable |
| Known limitations | Documented throughout docs/security-model.md's "Known Limitations" list, carried forward unchanged |
| Operational prerequisites | Documented in docs/installation-guide.md; requires a real Ubuntu Server with `wireguard-tools`+`nftables`+root to actually operate (not just to test) |
| Remaining blockers | See §1 — a real, non-WSL2 Ubuntu Server environment |

**Release recommendation: DO NOT release as "production-validated" on the basis of this
session's work alone.** The codebase, tests, and documentation represent a thorough,
honestly-scoped implementation with strong mocked-level and static/syntax-level real-Linux
evidence (see Phase 4/6/6A's genuine `systemd-analyze verify` and published-binary runs),
but the specific, real, end-to-end behaviors Phase 8 was designed to gate on — actual
packet acceptance/denial, actual NAT, actual systemd service lifecycle — remain unverified.
This is not a new problem introduced by Phase 8; it is the same limitation every prior
phase's report has honestly carried forward, now stated as the dedicated release gate it
always was.

## 7. Recommended Next Step

Obtain a real, standalone Ubuntu Server 22.04/24.04 environment (bare metal, a cloud VM, or
a full VM — not WSL2) with root access, then either:

1. Run `sudo apt-get install -y wireguard-tools nftables`, publish the Gateway Agent
   (`dotnet publish src/SecureTunnel.GatewayAgent -c Release -r linux-x64 --self-contained
   true`), and execute `test-lab/run-integration-tests.sh --with-packet-flow-test` there,
   then bring the real PASS/FAIL/BLOCKED output back for a genuine Phase 8 completion
   report; or
2. If such an environment cannot be provided, keep Phase 8 formally BLOCKED and treat
   Phases 1–7's mocked/static validation as the project's practical ceiling for this
   development context — a legitimate, explicitly-scoped stopping point, not a failure.
