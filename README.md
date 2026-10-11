# SecureTunnel Gateway

**English** | [繁體中文](README.zh-TW.md)

SecureTunnel Gateway is the Linux-based VPN Gateway / VPN Server of the **SecureTunnel private resource access control platform**.

> **Currently this project covers only the VPN Server / Gateway itself**: it does not include a Windows Client, Linux Client, full Admin Portal, or full backend Control Plane. These are future work, and the architecture already leaves room to integrate them.

## What problem does it solve

Without SecureTunnel, internal resources (websites, APIs, databases and other TCP services) are often exposed on the corporate network or even the public internet, so anyone with network access may connect.

The goal of SecureTunnel Gateway is simple:

> **Only users who connect through the SecureTunnel VPN Gateway can access designated internal or protected resources.**

Specifically:

- Users must first establish a WireGuard VPN connection and pass the Gateway's Peer authentication.
- Only authorized VPN Clients (Peers) can access the protected resources configured on the Gateway.
- Sources that are not connected to the VPN, have disconnected, or whose Peer has been disabled/revoked are always denied (fail-closed, default deny).
- All access control is enforced by the Linux firewall (nftables) on the Gateway and never relies on client behavior or trust.

This is **not** a tool for traffic anonymization or evading network monitoring; it is a "zero-trust" style gateway for private resources.

## Roles: VPN Server, VPN Client, Gateway

| Term | Description |
|---|---|
| **VPN Server / Gateway** (this project) | A service running on a Linux host that builds the WireGuard VPN network, manages Peers, and enforces access control through nftables. |
| **VPN Client** | The WireGuard client on a user's device (Windows / Linux) used to connect to the Gateway. A dedicated SecureTunnel client is **not** developed yet; use a standard WireGuard client. |
| **Peer** | The Gateway's name for each authorized VPN Client (in WireGuard terms, the server and each client are peers of one another). A Peer has its own VPN IP, public key, and access rules. |
| **Protected Resource** | An internal service whose access the Gateway controls, such as a website, HTTP API, or TCP service (e.g. a database). |
| **Control Plane (future)** | A future backend for centrally managing Users / Groups / Devices / Gateways / Resources / Access Policies. Out of scope for now. |

## Architecture (overview)

```
VPN Client (Windows/Linux, standard WireGuard)
        │  WireGuard (UDP)
        ▼
┌─────────────────────────── Linux Gateway Host ───────────────────────────┐
│                                                                           │
│   WireGuard Interface (wg-securetunnel)                                 │
│            │                                                            │
│            ▼                                                            │
│   nftables Forward Chain  ── default deny / allow-list ──►  Protected   │
│            ▲                                                 Resources  │
│            │                                                            │
│   SecureTunnel Gateway Agent (.NET, systemd service)                    │
│     ├─ WireGuard config / peer management                              │
│     ├─ nftables rule generation & apply                                │
│     ├─ Configuration validation / versioning / rollback                │
│     ├─ Health check & diagnostics                                      │
│     └─ Structured logging & audit                                      │
└───────────────────────────────────────────────────────────────────────┘
```

## Features

- **WireGuard management**: generates server configuration and keys, manages the WireGuard interface.
- **Peer management**: registers VPN Clients with an Active / Disabled / Revoked / Removed lifecycle, automatic VPN IP allocation, and client config template generation (`securetunnel-gateway peer *`).
- **Protected resources and access policies**: defines Protected Resources and Peer-to-Resource authorization policies (`resource` / `policy` commands).
- **nftables firewall**: generates `table inet securetunnel` rules (default-deny, NAT-aware) with a full generate → validate → apply → verify flow (`firewall *`).
- **Configuration lifecycle**: versioned configuration history, atomic apply, Last-Known-Good tracking, one-step rollback, and a single-writer lock (`config apply|rollback|diff|verify`).
- **Deployment and operations**: `install.sh` / `uninstall.sh`, systemd service, `gateway status` diagnostics, `gateway backup` / `restore`, logging delegated to journald.
- **Daemon mode**: `gateway serve` periodically evaluates state and logs to journald (it never applies configuration automatically).

`test-lab/run-integration-tests.sh` is an integration test script meant to run on a real Ubuntu Server (root, `wireguard-tools`, and `nftables` required); see [test-lab/README.md](test-lab/README.md).

## Project layout

```
SecureTunnel-Gateway/
├── config/                  # Example configs (gateway / peers / resources / policies)
├── src/SecureTunnel.GatewayAgent/   # .NET 10 Gateway Agent source
├── scripts/                 # Bash scripts for install, environment validation, etc.
├── deploy/                  # systemd service
├── tests/                   # Unit and integration tests
└── test-lab/                # Real Linux integration test script
```

## Quick start

1. Prepare a Linux host (Ubuntu 22.04 / 24.04 LTS recommended) with `wireguard-tools` and `nftables` installed.
2. Copy `config/gateway.example.yaml` to `/etc/securetunnel-gateway/gateway.yaml` and fill in real values.
3. Validate the environment: `./scripts/validate-environment.sh`.
4. Publish and install: `dotnet publish src/SecureTunnel.GatewayAgent -c Release -r linux-x64 --self-contained true -o publish/linux-x64`, then `sudo ./scripts/install.sh --publish-dir publish/linux-x64`.
5. After generating keys and configuring Peers/Resources/Policies, apply with `securetunnel-gateway config apply --yes`; check overall state with `securetunnel-gateway gateway status`.

## License

The license has not been decided yet; a `LICENSE` file will be added once it is.
