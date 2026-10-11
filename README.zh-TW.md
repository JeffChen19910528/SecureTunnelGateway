# SecureTunnel Gateway

[English](README.md) | **繁體中文**

SecureTunnel Gateway 是 **SecureTunnel 私有資源存取控管平台** 的 Linux-based VPN Gateway / VPN Server。

> **目前只涵蓋 VPN Server / Gateway 本身**：不包含 Windows Client、Linux Client、完整 Admin Portal 或完整後端 Control Plane。這些是未來的工作，本專案已在架構上為它們預留整合空間。

## 這個專案解決什麼問題

在導入 SecureTunnel 之前，內部資源（網站、API、資料庫等 TCP 服務）通常暴露在公司網路甚至公網上，任何拿到網路存取權的人都可能連線。

SecureTunnel Gateway 的目標很單純：

> **只有通過 SecureTunnel VPN Gateway 的使用者，才能存取指定的內部或受保護資源。**

具體來說：

- 使用者必須先透過 WireGuard 建立 VPN 連線，並通過 Gateway 的 Peer 驗證。
- 只有已授權的 VPN Client（Peer）才能存取 Gateway 上設定的受保護資源。
- 未連線 VPN、VPN 已斷線、或 Peer 已被停用/撤銷的來源，一律無法存取受保護資源（fail-closed，預設拒絕）。
- 所有存取控制由 Gateway 上的 Linux Firewall（nftables）實際強制執行，不依賴 Client 端的行為或信任。

這**不是**一個追求流量匿名化或繞過網路監管的工具，而是一個「零信任式」的私有資源存取閘道。

## 角色說明：VPN Server、VPN Client、Gateway

| 名詞 | 說明 |
|---|---|
| **VPN Server / Gateway**（本專案） | 執行在 Linux 主機上的服務，負責建立 WireGuard VPN 網路、管理 Peer、透過 nftables 強制執行存取控制。 |
| **VPN Client** | 使用者的裝置（Windows / Linux）上執行的 WireGuard client，用來連線到 Gateway。目前**不開發** SecureTunnel 自有 Client，使用標準 WireGuard client 即可。 |
| **Peer** | Gateway 對每一個已授權 VPN Client 的稱呼（在 WireGuard 概念中，Server 與每個 Client 互為 peer）。Peer 有自己的 VPN IP、公鑰與存取規則。 |
| **受保護資源（Protected Resource）** | Gateway 管制存取的內部服務，例如網站、HTTP API、TCP 服務（如資料庫）。 |
| **Control Plane（未來）** | 未來用來集中管理 Users / Groups / Devices / Gateways / Resources / Access Policies 的後端系統，目前不在範圍內。 |

## 系統架構（概覽）

```
VPN Client (Windows/Linux, 標準 WireGuard)
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

## 主要功能

- **WireGuard 管理**：產生伺服器設定與金鑰，管理 WireGuard 介面。
- **Peer 管理**：註冊 VPN Client，支援 Active / Disabled / Revoked / Removed 生命週期、VPN IP 自動配發與 Client 設定範本產生（`securetunnel-gateway peer *`）。
- **受保護資源與存取政策**：定義 Protected Resource 與 Peer-to-Resource 的授權政策（`resource` / `policy` 指令）。
- **nftables 防火牆**：自動產生 `table inet securetunnel` 規則（default-deny、NAT-aware），提供產生 → 驗證 → 套用 → 檢查的完整流程（`firewall *`）。
- **設定生命週期**：版本化的設定歷史、原子化套用、Last-Known-Good 追蹤、一鍵回滾與單一寫入者鎖（`config apply|rollback|diff|verify`）。
- **部署與維運**：`install.sh` / `uninstall.sh`、systemd service、`gateway status` 綜合診斷、`gateway backup` / `restore`，日誌交由 journald。
- **常駐模式**：`gateway serve` 以 daemon 方式定期評估狀態並寫入 journald（不會自動套用設定）。

`test-lab/run-integration-tests.sh` 提供可在真實 Ubuntu Server（需 root、`wireguard-tools`、`nftables`）上執行的整合驗證腳本，詳見 [test-lab/README.md](test-lab/README.md)。

## 專案結構

```
SecureTunnel-Gateway/
├── config/                  # 設定檔範例（gateway / peers / resources / policies）
├── src/SecureTunnel.GatewayAgent/   # .NET 10 Gateway Agent 原始碼
├── scripts/                 # 安裝、環境驗證等 Bash 腳本
├── deploy/                  # systemd service
├── tests/                   # 單元測試與整合測試
└── test-lab/                # 真實 Linux 整合測試腳本
```

## 使用說明

完整流程見 [GUIDE.zh-TW.md](GUIDE.zh-TW.md)。簡短版（Ubuntu 22.04/24.04，root）：

```bash
apt-get install -y wireguard-tools nftables
dotnet publish src/SecureTunnel.GatewayAgent -c Release -r linux-x64 --self-contained true -o publish/linux-x64
G=publish/linux-x64/SecureTunnel.GatewayAgent; C="--config /etc/securetunnel-gateway/gateway.yaml"
$G wireguard generate-keys --yes $C                                  # 產生伺服器金鑰
$G peer add --name alice --public-key <用戶端公鑰> --yes $C          # 會印出 peer id 與 VPN IP
$G resource add --name web --destination 10.20.0.5 --protocol tcp --port 8443 --yes $C
$G policy add --peer-id <peer-id> --resource-id <resource-id> --yes $C
$G config apply --yes $C                                             # 套用 WireGuard + nftables（預設拒絕）
$G peer config --id <peer-id> --output alice.conf $C                 # 範本；私鑰由用戶端自行填入
```

實務上要注意：
- `wireGuard.configOutputPath` 必須是 `/etc/wireguard/<interfaceName>.conf`（`wg-quick` 只讀這個路徑）。
- 金鑰不能放在 `/tmp`（Gateway 會拒絕任何人可寫的位置），請用 `/etc/securetunnel-gateway/keys`。
- `network.lanInterface` 是面向受保護網段的網卡；請對用戶端開放 UDP `listenPort`（預設 51820）。
- 要快速撤銷：`peer disable --id <id> --yes`，再 `config apply --yes`。

### 驗證部署
以 root 執行 `test-lab/run-integration-tests.sh --with-packet-flow-test`，它用 network namespace 建出 peer 與受保護資源，經真實 WireGuard 隧道檢查：握手、授權存取、預設拒絕、NAT、停用 peer、停用資源、apply／rollback 與 daemon。

單元測試：`TMPDIR=<非 /tmp 的目錄> dotnet test SecureTunnelGateway.slnx`。在 Linux 上 `TMPDIR` 不能是 `/tmp`，因為測試會寫私鑰，而 Gateway 會拒絕 `/tmp`。

**驗證結果**：整合實驗 20/20 通過（未安裝 systemd 單元時會略過重啟檢查）、單元測試全數通過，並已用 Windows 用戶端完成端到端連線（握手、授權資源 HTTP 200、未授權被擋、中斷後再被擋）。

## 快速開始（完整說明見 [GUIDE.zh-TW.md](GUIDE.zh-TW.md)）

1. 準備 Linux 主機（建議 Ubuntu 22.04 / 24.04 LTS），並安裝 `wireguard-tools` 與 `nftables`。
2. 複製 `config/gateway.example.yaml` 為 `/etc/securetunnel-gateway/gateway.yaml` 並填入實際值。
3. 執行環境驗證：`./scripts/validate-environment.sh`。
4. 發佈並安裝：`dotnet publish src/SecureTunnel.GatewayAgent -c Release -r linux-x64 --self-contained true -o publish/linux-x64` 後 `sudo ./scripts/install.sh --publish-dir publish/linux-x64`。
5. 產生金鑰、設定 Peer/Resource/Policy 後，`securetunnel-gateway config apply --yes` 套用；`securetunnel-gateway gateway status` 查看整體狀態。

## 授權

本專案以 [MIT License](LICENSE) 授權。
