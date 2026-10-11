# SecureTunnel Gateway Guide

**English** | [繁體中文](GUIDE.zh-TW.md)

Install, configure, and operate the Gateway on a Linux server. Back to [README](README.md).

## Requirements

| Item | Requirement |
|---|---|
| OS | Ubuntu Server 22.04 / 24.04 LTS (x86_64) |
| Privileges | root or sudo |
| Packages | `wireguard-tools`, `nftables` |
| Network | WireGuard UDP port (default `51820`) reachable from clients; a route to the protected network |
| .NET | .NET 10 SDK to build; the published self-contained binary needs no runtime |

## 1. Build and install

```bash
dotnet publish src/SecureTunnel.GatewayAgent -c Release -r linux-x64 --self-contained true -o publish/linux-x64
sudo ./scripts/install.sh --publish-dir publish/linux-x64 [--dry-run]
```

`install.sh` is idempotent. It creates the directory layout, copies the binary and scripts, and installs (but does not enable or start) the systemd unit.

| Directory | Content |
|---|---|
| `/usr/lib/securetunnel-gateway/` | Binary and helper scripts |
| `/etc/securetunnel-gateway/` | `gateway.yaml`, `keys/` |
| `/var/lib/securetunnel-gateway/` | Peer / resource / policy registries, configuration history, backups |

Logs go to journald: `journalctl -u securetunnel-gateway`.

## 2. Prepare the host

```bash
sudo apt-get update && sudo apt-get install -y wireguard-tools nftables
./scripts/validate-environment.sh                 # no root needed
sudo ./scripts/enable-ip-forwarding.sh --dry-run  # preview, then run without --dry-run
```

Copy `config/gateway.example.yaml` to `/etc/securetunnel-gateway/gateway.yaml` and edit it. Never commit private keys; `privateKeyPath` is only a path.

## 3. Configure the Gateway

In the commands below, `securetunnel-gateway` is the installed binary. Every command takes `--config <path>`, and every state-changing command takes `--dry-run` (preview) or `--yes` (confirm).

```bash
# Server keys and WireGuard config
securetunnel-gateway wireguard generate-keys --dry-run
securetunnel-gateway wireguard generate-keys
securetunnel-gateway config generate --dry-run

# Register a client (the Gateway only ever stores the client public key)
securetunnel-gateway peer add --name alice --public-key <client-public-key> --yes

# Define a protected resource and grant the peer access
securetunnel-gateway resource add --name intranet-web --destination 10.0.10.5 --protocol tcp --port 443 --yes
securetunnel-gateway policy add --peer-id <peer-id> --resource-id <resource-id> --yes

# Validate, then apply WireGuard + nftables together
securetunnel-gateway config apply --dry-run
securetunnel-gateway config apply --yes
```

`peer config --id <id> --output client.conf` produces a client configuration **template**; the client fills in its own private key.

## 4. Run

```bash
sudo systemctl enable --now securetunnel-gateway
securetunnel-gateway gateway status
securetunnel-gateway health
securetunnel-gateway doctor
```

The service runs `gateway serve`, which periodically evaluates state and logs it. It never applies configuration by itself; use `config apply`.

## 5. Day-to-day operations

| Task | Command |
|---|---|
| Temporarily block a client | `peer disable` / `peer enable` |
| Permanently block a client | `peer revoke` |
| Pause a resource or policy | `resource disable`, `policy disable` |
| Inspect the firewall | `firewall status`, `firewall show` |
| Review configuration history | `config list`, `config diff`, `config show` |
| Check actual vs. recorded state | `config verify` |
| Roll back | `config rollback --version <n> --yes` |
| Back up / restore | `gateway backup`, `gateway restore` (restore never activates data; run `config apply` afterward) |

Run `securetunnel-gateway <command> --help` for all options.

## 6. Verify on a real server

`test-lab/run-integration-tests.sh` checks the real WireGuard interface, nftables default-deny, apply/rollback, the daemon, and service restart. Run it as root on an Ubuntu Server; add `--with-packet-flow-test` for the network-namespace test of authorized/unauthorized access and NAT. Every check reports `PASS`, `FAIL`, or `BLOCKED`. See [test-lab/README.md](test-lab/README.md).

> This script has not yet been run on a real Ubuntu Server. Please run it in your environment before relying on the Gateway in production.

## 7. Uninstall

```bash
sudo ./scripts/uninstall.sh [--dry-run]
sudo ./scripts/uninstall.sh --purge-data --yes-i-am-sure   # also deletes config and state
```

By default the `inet securetunnel` nftables table and the configured WireGuard interface are removed, while `/etc` and `/var/lib` data is kept.
