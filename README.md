# SecureTunnel Gateway

SecureTunnel Gateway 是 **SecureTunnel 私有資源存取控管平台** 的 Linux-based VPN Gateway / VPN Server。

> **目前開發階段（MVP）只涵蓋 VPN Server / Gateway 本身**：不包含 Windows Client、Linux Client、完整 Admin Portal 或完整後端 Control Plane。這些是未來階段的工作，本專案已在架構上為它們預留整合空間（見 [docs/architecture.md](docs/architecture.md#十六未來整合control-plane)）。

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
| **VPN Server / Gateway**（本專案） | 執行在 Linux 主機上的服務，負責建立 WireGuard VPN 網路、管理 Peer、透過 nftables 強制執行存取控制。是本階段唯一的開發範圍。 |
| **VPN Client** | 使用者的裝置（Windows / Linux）上執行的 WireGuard client，用來連線到 Gateway。本階段**不開發** SecureTunnel 自有 Client，先使用標準 WireGuard client 進行測試。 |
| **Peer** | Gateway 對每一個已授權 VPN Client 的稱呼（在 WireGuard 概念中，Server 與每個 Client 互為 peer）。Peer 有自己的 VPN IP、公鑰與存取規則。 |
| **受保護資源（Protected Resource）** | Gateway 管制存取的內部服務，例如網站、HTTP API、TCP 服務（如資料庫）。 |
| **Control Plane（未來）** | 未來用來集中管理 Users / Groups / Devices / Gateways / Resources / Access Policies 的後端系統，目前不在本階段範圍內。 |

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

詳細架構、Data Plane / Management Plane 的分離方式，見 [docs/architecture.md](docs/architecture.md)。
網路拓撲與位址規劃見 [docs/network-topology.md](docs/network-topology.md)。

## 目前開發狀態

本專案採分階段開發（Phase 0–8），目前狀態：

- ✅ Phase 0：Environment Inspection（環境檢查，已完成）
- ✅ Phase 1：Documentation and Architecture（已完成）
- ✅ Phase 2：WireGuard Bootstrap（已完成，92 個 xUnit 測試）
- ✅ Phase 3：Peer Management & Client Configuration（已完成，170 個 xUnit 測試）
- ✅ Phase 4：Firewall & Protected Resource Access Control（已完成，274 個 xUnit 測試）
- ✅ Phase 5：Configuration Lifecycle, Atomic Apply & Rollback（已完成，318 個 xUnit 測試）
- ✅ Phase 6：Deployment, Systemd & Gateway Operations（已完成，343 個 xUnit 測試）
- ✅ Phase 6A：Gateway Daemon / Serve Mode（已完成，全專案共 363 個 xUnit 測試）
- ✅ Phase 7：Integration & Security Hardening（已完成，全專案共 372 個 xUnit 測試）
- 🚫 Phase 8：Real Linux Gateway Acceptance & Release Readiness（**BLOCKED**，非 COMPLETED——需要真實 Ubuntu Server 環境，見下方說明與 [docs/release-readiness.md](docs/release-readiness.md)）

Phase 8 狀態：**BLOCKED**。本階段的目的是在真實 Ubuntu Server（有 root、`wireguard-tools`、`nftables`）上實際執行 `test-lab/run-integration-tests.sh`，取得真正的封包層級（authorized/unauthorized access、NAT、rollback 後狀態一致性）驗證結果。本開發環境（WSL2 Ubuntu 24.04.4 LTS，kernel `6.6.87.2-microsoft-standard-WSL2`）沒有 `sudo` 免密碼權限，也沒有安裝 `wireguard-tools`/`nftables`——依專案既有規則，Gateway Agent 開發過程不會自行安裝套件或取得免密碼 sudo。這不是新問題，是 Phase 1–7 一路誠實記錄的同一個環境限制，Phase 8 規格本身也明確允許在環境不可用時將本階段標記為 BLOCKED 而非 COMPLETED（而非把限制包裝成「通過」）。完整的環境探測結果、發布就緒度總結與安全發現分類見 [docs/release-readiness.md](docs/release-readiness.md)。

Phase 7 新增：**橫向安全審查與強化，並補上 Phase 7 規格要求的真實 Linux 整合測試腳本**——不重新設計架構，只針對具體發現的問題修正或明確記錄。修正：`Backup/BackupService.cs` 還原流程中途失敗時，不再未經處理地拋出例外，而是明確回報哪些檔案已被還原、哪些沒有；`Services/DryRunSystemCommandExecutor.cs` 新增 `wg genkey`/`wg pubkey`/`wg set` 的 dry-run 防禦深度；`scripts/uninstall.sh` 新增範圍精確（僅 `inet securetunnel` table、僅設定檔中指定的介面）的防火牆/WireGuard 介面清理。審查並確認已經安全（無需修改）：backup restore 的路徑穿越防護、symlink 處理、私鑰是否曾外洩於命令列/日誌、nftables table ownership 邊界、IPv6 是否可能繞過（`inet` combined family 結構性拒絕，補上迴歸測試）、Registry Consistency（既有 content-hash 機制已足夠，不需要新增 revision identifier）。新增 `test-lab/run-integration-tests.sh`：一支已撰寫、可在真實 Ubuntu Server 上執行的整合驗證腳本，涵蓋 Phase 7 規格的 15 項「Real Linux Integration Validation」檢查中的大部分（**尚未在真實 Ubuntu Server 上執行過**，本開發環境缺 `wireguard-tools`/`nftables`）。詳見 [docs/security-model.md](docs/security-model.md#二十五phase-7-安全審查結果integration--security-hardening) 與 `test-lab/README.md`。

Phase 6A 新增：**真正的常駐 daemon 執行模式**——補上 Phase 6 報告中明確列出的已知限制（Gateway Agent 過去只是一次性 CLI 工具，systemd `ExecStart` 曾指向一個佔位指令）。新增 `securetunnel-gateway gateway serve`（`Daemon/GatewayDaemonService.cs`）：啟動時載入並驗證設定、執行 Phase 5 crash-recovery 偵測、評估 Desired/Active/Effective 狀態，之後進入常駐迴圈，依固定週期（`--interval-seconds`，預設 60 秒）重複評估並寫入 journald；`--once` 可只跑一次診斷後結束（供腳本化驗證與測試使用）。daemon **絕不**自動呼叫 `config apply`（Option A：只記錄 Desired 已落後 Active 的警告），也不開放任何網路查詢/管理介面——`gateway status` 仍是操作者另外執行的一次性查詢指令。SIGTERM（`systemctl stop`）與 SIGINT 皆能觸發優雅關閉。`deploy/systemd/securetunnel-gateway.service` 的 `ExecStart` 已改為呼叫 `gateway serve`，並重新以 `systemd-analyze verify` 真實驗證通過（exit code 0，零警告）。詳見 [docs/operations-guide.md](docs/operations-guide.md#gateway-daemon)。

Phase 6 新增：**部署與維運**——FHS 相容的目錄佈局（`/etc` 靜態設定 vs `/var/lib` 可變狀態）、`scripts/install.sh`/`scripts/uninstall.sh`、`deploy/systemd/securetunnel-gateway.service`（已用 `systemd-analyze verify` 真實驗證通過）、`gateway status`（Configured/Desired/Active/Effective 綜合診斷）、`gateway backup`/`gateway restore`（含完整性雜湊驗證、絕不自動套用）、日誌全面委由 journald。詳見 [docs/installation-guide.md](docs/installation-guide.md) 與 [docs/operations-guide.md](docs/operations-guide.md)。

Phase 5 新增：**版本化的設定生命週期**——把「Registry 變更後需要手動 generate+apply」這個已知限制補上。新增 Configuration History（每次 apply 都是一個不可變版本，記錄 Peer/Resource/Policy 快照、驗證/套用/驗證結果）、`config apply` 一次到位完成 WireGuard + nftables 的驗證→套用→驗證、Active/Last-Known-Good 追蹤、`config rollback` 回到任一先前成功版本、單一寫入者鎖（防止並發 apply 互相干擾）、crash recovery 偵測（process 中斷偵測）。詳見 [docs/architecture.md](docs/architecture.md) 與 [docs/operations-guide.md](docs/operations-guide.md)。

Phase 3 新增：Peer（VPN Client）註冊與生命週期管理（Active/Disabled/Revoked/Removed）、VPN IP 自動配發、Client 設定範本產生、對應的 `securetunnel-gateway peer *` CLI 指令。

Phase 4 新增：**本專案的核心價值主張**——「只有通過授權的 Peer 才能存取指定的受保護資源」——在此階段真正落地。新增 Protected Resource 模型、Access Policy（Peer-to-Resource 授權）模型、nftables 規則產生器（`table inet securetunnel`，default-deny、NAT-aware）、完整的 apply 生命週期（產生 → 語法驗證 → 套用 → 驗證），以及 `securetunnel-gateway resource|policy|firewall *` CLI 指令。詳見 [docs/firewall-model.md](docs/firewall-model.md) 與 [docs/operations-guide.md](docs/operations-guide.md)。

**目前的開發/驗證環境是 WSL2 Ubuntu 24.04**，這不是一台正式的 Linux Server，網路與權限模型都有限制。所有文件與功能都會清楚標示哪些是「邏輯已驗證」、哪些是「需要正式 Linux Server 才能驗證」。詳見 [docs/troubleshooting.md](docs/troubleshooting.md#wsl2-環境限制) 與各文件中的「已知限制」章節。

## 專案結構

```
SecureTunnel-Gateway/
├── docs/                    # 架構、安裝、操作、安全等文件
├── config/                  # 設定檔範例（gateway / peers / protected-resources）
├── src/SecureTunnel.GatewayAgent/   # .NET 10 Gateway Agent 原始碼
├── scripts/                 # 安裝、環境驗證、金鑰產生等 Bash 腳本
├── deploy/                  # systemd service、nftables、WireGuard 部署範例
├── tests/                   # 單元測試與整合測試
└── test-lab/                # Docker Compose 測試用受保護服務（僅供開發測試）
```

## 快速開始

1. 閱讀 [docs/installation-guide.md](docs/installation-guide.md) 確認環境需求與 Linux 部署佈局。
2. 依 [docs/configuration-guide.md](docs/configuration-guide.md) 準備 `/etc/securetunnel-gateway/gateway.yaml`。
3. 執行環境驗證：`./scripts/validate-environment.sh`。
4. 發佈並安裝：`dotnet publish src/SecureTunnel.GatewayAgent -c Release -r linux-x64 --self-contained true -o publish/linux-x64` 後 `sudo ./scripts/install.sh --publish-dir publish/linux-x64`。
5. 產生金鑰、設定 Peer/Resource/Policy 後，`securetunnel-gateway config apply --yes` 套用；`securetunnel-gateway gateway status` 查看整體狀態。

完整步驟見 [docs/installation-guide.md](docs/installation-guide.md)、[docs/operations-guide.md](docs/operations-guide.md)。

## 授權

尚未決定授權條款，`LICENSE` 檔案將於確定授權方式後補上。

## 安全性回報

如果你發現安全性問題，請**不要**直接開 public issue，請參考 [SECURITY.md](SECURITY.md) 的回報方式。

## 貢獻

見 [CONTRIBUTING.md](CONTRIBUTING.md)。
