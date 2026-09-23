# Installation Guide

> **Phase 7 狀態**：`scripts/validate-environment.sh`、`scripts/check-ip-forwarding.sh`、`scripts/enable-ip-forwarding.sh` 已實作並在 WSL2 Ubuntu 24.04 實際執行驗證過。Gateway Agent（`securetunnel-gateway` CLI）已可建置與執行，涵蓋 Phase 2-6A 全部指令群組（`version`/`doctor`/`health`/`validate`/`config *`/`wireguard *`/`peer *`/`resource *`/`policy *`/`gateway *`，含 Phase 6A 新增的 `gateway serve`）。`scripts/install.sh`、`scripts/uninstall.sh` 與 `deploy/systemd/securetunnel-gateway.service` 已於 Phase 6 提供並完成靜態語法驗證（見第二 C 節）；`deploy/systemd/securetunnel-gateway.service` 的 `ExecStart` 已於 Phase 6A 改為呼叫真正的常駐 daemon `gateway serve`，並重新驗證通過。**Phase 7** 為 `uninstall.sh` 補上範圍精確的 nftables/WireGuard 介面清理（見第二 C 節），並新增 `test-lab/run-integration-tests.sh`——一支已撰寫、可在真實 Ubuntu Server 上執行的整合驗證腳本（見 [testing-guide.md](testing-guide.md)）。`scripts/install-wireguard.sh`、`scripts/generate-client-config.sh`、`scripts/configure-firewall.sh` 這幾支早期規劃中的獨立腳本並未各自實作，其功能已改由 Gateway Agent CLI 本身提供（`wireguard generate-keys`、`config generate`、`config apply` 等）。

## 一、安裝前需求

### 1.1 目標正式環境

| 項目 | 需求 |
|---|---|
| 作業系統 | Ubuntu Server 24.04 LTS（x86_64） |
| 權限 | 具備 root 或 sudo 權限的帳號 |
| 網路 | 至少兩個網路介面概念：一個面向 VPN Client（可為同一張卡）、一個面向受保護網路；具備可路由到受保護網路的能力 |
| 開放的對外 port | WireGuard UDP port（預設 `51820`），需在雲端安全群組/防火牆/路由器上開放 |
| .NET | .NET 10 Runtime（Gateway Agent 執行需求） |
| WireGuard | 核心模組（Ubuntu 24.04 內建於 kernel，或可透過 `wireguard-tools` 提供的 DKMS 補齊）+ `wireguard-tools`（提供 `wg` / `wg-quick`） |
| nftables | `nftables` 套件 |

### 1.2 本階段開發/驗證環境（WSL2）

目前所有指令都是在 **WSL2 Ubuntu 24.04** 上準備與驗證邏輯，這不是正式部署環境。差異見 [architecture.md 第十四節](architecture.md#十四開發測試環境與正式環境的差異重要)。WSL2 上：

- 沒有免密 sudo，本文件所有需要 root 的指令都需要你手動在具備權限的終端機執行。
- 無法驗證外部真實 Client 連線（見 [troubleshooting.md](troubleshooting.md#wsl2-環境限制)）。

## 二、安裝步驟（預計流程）

### Step 1：環境驗證（已實作，可執行）

```bash
./scripts/validate-environment.sh
./scripts/validate-environment.sh --json
```

不需要 root。實際檢查項目（共 20 項，PASS/WARN/FAIL/BLOCKED）：OS/發行版/kernel/架構、root/sudo 可用性、`wg`/`wg-quick`/`nft`/`ip`/`systemctl` 是否存在、WireGuard kernel module、IPv4/IPv6 forwarding 目前狀態、非 loopback 網路介面、`/etc/securetunnel-gateway`、`/var/log/securetunnel-gateway` 目錄狀態、.NET SDK/Runtime 版本、Docker（僅供 test-lab 用，非 WireGuard 必要條件）。**不會**安裝套件、修改 sysctl、修改 Firewall、啟動 WireGuard，也不會要求輸入密碼。

`securetunnel-gateway doctor` 會呼叫同一支腳本並疊加 Gateway Agent 自己的 health check 結果（configuration-validity、key-file-permissions、active-configuration），輸出範例見 [operations-guide.md](operations-guide.md)。

### Step 2：安裝 WireGuard（尚未提供自動化腳本）

```bash
# scripts/install-wireguard.sh 尚未實作（Phase 2 後段），目前請手動執行：
sudo apt-get update
sudo apt-get install -y wireguard-tools nftables
```

**風險與所需權限**：需要 root 安裝套件與載入 kernel module。`validate-environment.sh` 會在裝完後將 `wireguard.wg`／`wireguard.wg-quick`／`nftables.nft` 由 `BLOCKED` 轉為 `PASS`，可用來確認安裝結果。

### Step 3：啟用 IP Forwarding（已實作，可執行）

```bash
./scripts/check-ip-forwarding.sh          # 唯讀，隨時可執行，不需 root
./scripts/check-ip-forwarding.sh --json

sudo ./scripts/enable-ip-forwarding.sh --dry-run   # 預覽將寫入的 sysctl drop-in，不需 root 也不修改系統
sudo ./scripts/enable-ip-forwarding.sh              # 實際套用（需要 root）
sudo ./scripts/enable-ip-forwarding.sh --revert     # 還原（需要 root）
```

實作內容：只寫入 `/etc/sysctl.d/99-securetunnel-gateway.conf`（不觸碰 `/etc/sysctl.conf` 或其他既有設定），套用前備份既有的同名 drop-in 檔案（若存在），套用後立即用 `sysctl --system` 生效並讀回驗證，失敗會回報非 0 exit code。只啟用 IPv4 forwarding，**不會**啟用 IPv6 forwarding（見 [security-model.md](security-model.md#十五ipv6-洩漏)）。持久性：透過 systemd-sysctl 在每次開機時自動套用，不需重開機立即生效。

### Step 4：產生 Server 金鑰（已實作，可執行）

```bash
securetunnel-gateway wireguard generate-keys --config /etc/securetunnel-gateway/gateway.yaml --dry-run   # 預覽，不寫入任何檔案
securetunnel-gateway wireguard generate-keys --config /etc/securetunnel-gateway/gateway.yaml              # 實際產生
```

實作內容：呼叫 `wg genkey` / `wg pubkey`（私鑰經由 stdin 傳給 `wg pubkey`，不會出現在命令列參數或 `ps` 輸出中），將 private key 寫入 `wireGuard.privateKeyPath`（見 configuration-guide.md）並在 Linux 上設定 `0600` 權限（Windows 開發機上會警告無法設定 Unix 權限，需在正式 Linux 主機上另行確認）。**私鑰不會出現在終端機輸出、log 或錯誤訊息中**（`tests/WireGuardTests/KeyManagementServiceTests.cs` 有專門測試涵蓋這點）。若私鑰檔案已存在，預設拒絕覆蓋；需要更換金鑰時必須明確加上 `--force --yes`（會清楚提示這會讓所有既有 Peer 斷線）。若 `wg` 指令不存在，回報 `BLOCKED` 而非假裝成功。

### Step 4b：產生 WireGuard 介面設定（已實作，可執行）

```bash
securetunnel-gateway config generate --config /etc/securetunnel-gateway/gateway.yaml --dry-run   # 預覽，PrivateKey 永遠顯示為 <loaded from ...>
securetunnel-gateway config generate --config /etc/securetunnel-gateway/gateway.yaml              # 實際寫入 /etc/wireguard/<interfaceName>.conf
securetunnel-gateway wireguard start  --config /etc/securetunnel-gateway/gateway.yaml --yes        # wg-quick up（需要 root；--yes 為必要的明確確認）
securetunnel-gateway wireguard status --config /etc/securetunnel-gateway/gateway.yaml
```

`config generate` 會先執行與 `validate` 相同的驗證，失敗（例如 `security.failClosed = false`）不會產生檔案。若目的檔案已存在，預設拒絕覆蓋，需 `--force`。`wireguard start/stop/restart` 屬於危險操作，未加 `--yes` 或 `--dry-run` 會直接拒絕執行。

### Step 5：設定 nftables（已實作，可執行）

```bash
securetunnel-gateway resource add --config /etc/securetunnel-gateway/gateway.yaml --name <name> --cidr <cidr> --yes
securetunnel-gateway policy add   --config /etc/securetunnel-gateway/gateway.yaml --peer <peer-id> --resource <resource-id> --yes
securetunnel-gateway config apply --config /etc/securetunnel-gateway/gateway.yaml --yes
```

`config apply`（Phase 5）會把 Peer/Resource/Policy 的目前狀態轉譯為 nftables 規則並與 WireGuard 設定一起原子套用；nftables 規則產生邏輯與資料模型見 [firewall-model.md](firewall-model.md)。本節不再單獨提供 `scripts/configure-firewall.sh`——這支腳本從未實作，其功能已由 CLI 的 `config apply` 取代。

### Step 6：安裝並啟動 Gateway Agent（systemd，已實作）

```bash
# 於目標 Ubuntu Server（需要 root）：
dotnet publish src/SecureTunnel.GatewayAgent -c Release -r linux-x64 --self-contained true -o /tmp/publish
sudo ./scripts/install.sh --publish-dir /tmp/publish
# 手動步驟見「Gateway Agent 建置與執行」與下方「Linux 部署佈局」
sudo systemctl enable --now securetunnel-gateway
securetunnel-gateway gateway status --config /etc/securetunnel-gateway/gateway.yaml
```

`scripts/install.sh` 會建立目錄佈局、複製執行檔與腳本、安裝（但不啟用/啟動）systemd unit；詳見下方「Linux 部署佈局」一節。

### Step 7：驗證健康狀態（已實作，可執行）

```bash
securetunnel-gateway health --config /etc/securetunnel-gateway/gateway.yaml
securetunnel-gateway doctor --config /etc/securetunnel-gateway/gateway.yaml
securetunnel-gateway health --config /etc/securetunnel-gateway/gateway.yaml --json
```

`health` 回傳 `Healthy` / `Degraded` / `Unhealthy` / `Unknown` 其中之一，並以對應 exit code（Healthy/Degraded=0、Unhealthy/Unknown=1）供腳本判斷。`doctor` 額外附上完整的 `validate-environment.sh` 原始檢查項目。

## 二 B、Gateway Agent 建置與執行

原始碼位於 `src/SecureTunnel.GatewayAgent/`（.NET 10 Console 專案），測試位於 `tests/`（xUnit，共 343 個測試，見 [testing-guide.md](testing-guide.md)）。

```bash
# 於任一裝有 .NET 10 SDK 的環境（Windows/Linux/macOS 開發機皆可）
dotnet build                                 # 建置整個 solution（SecureTunnelGateway.slnx）
dotnet test                                  # 執行全部 343 個單元/整合測試
dotnet run --project src/SecureTunnel.GatewayAgent -- version

# 部署到目標 Ubuntu Server：發布 self-contained linux-x64 執行檔（目標機不需另裝 .NET runtime）
dotnet publish src/SecureTunnel.GatewayAgent -c Release -r linux-x64 --self-contained true -o publish/linux-x64
# 將 publish/linux-x64/ 整個目錄（含 scripts/ 子目錄，需自行複製 scripts/*.sh 進去）複製到目標主機後執行：
./SecureTunnel.GatewayAgent doctor --config /etc/securetunnel-gateway/gateway.yaml
```

上述 self-contained 發佈方式已在 WSL2 Ubuntu 24.04 實際驗證過（`doctor`、`validate`、`config generate --dry-run`、`wireguard generate-keys`、`wireguard start/status --dry-run` 皆執行成功，且在 `wg`/`nft` 未安裝時正確回報 `BLOCKED` 而非假裝成功）。

## 二 C、Linux 部署佈局（Phase 6，FHS-compliant）

Gateway Agent 遵循 FHS（Filesystem Hierarchy Standard），依資料的「靜態/可變」性質分開存放：

| 目錄 | 內容 | 性質 |
|---|---|---|
| `/usr/lib/securetunnel-gateway/` | `SecureTunnel.GatewayAgent` 執行檔、`scripts/` 輔助腳本 | 唯讀（升級時整批取代） |
| `/etc/securetunnel-gateway/` | `gateway.yaml`、`keys/server.key`、`keys/server.pub` | 靜態設定 + 機密 |
| `/var/lib/securetunnel-gateway/` | `peers.json`、`resources.json`、`policies.json`、`config-history.json`、`operation.lock`、`backups/` | 可變狀態（Registry、版本歷史、備份） |
| `/var/log/securetunnel-gateway/` | （保留，目前未直接寫入） | 實際日誌透過 journald，見 [operations-guide.md](operations-guide.md#日誌logging) |

這是 Phase 6 對 Phase 1-5 預設路徑的一次非破壞性調整：`GatewayConfiguration` 中 `peerStorePath`／`resourceStorePath`／`policyStorePath`／`firewallRulesetPath`／`configurationHistoryPath`／`operationLockPath` 的**預設值**已從 `/etc/securetunnel-gateway/*` 改為 `/var/lib/securetunnel-gateway/*`（可變狀態不該放在 `/etc`），既有 `gateway.yaml` 若已明確指定這些路徑則不受影響。新增欄位 `backupDirectory`（預設 `/var/lib/securetunnel-gateway/backups`）見 [configuration-guide.md](configuration-guide.md)。

### 安裝／解除安裝腳本

```bash
sudo ./scripts/install.sh --publish-dir <dotnet-publish-輸出目錄> [--dry-run]
sudo ./scripts/uninstall.sh [--dry-run]
sudo ./scripts/uninstall.sh --purge-data --yes-i-am-sure   # 額外刪除 /etc 與 /var/lib 下的所有狀態
```

- `install.sh`：需要 root，冪等（可重複執行）。建立上表所有目錄並設定權限、複製執行檔與腳本、安裝（不啟用/啟動）systemd unit 並執行 `systemctl daemon-reload`。**不會**安裝 `wireguard-tools`/`nftables`、不會產生金鑰、不會寫入真正的 `gateway.yaml`——這些仍是後續手動步驟（Step 1-4）。
- `uninstall.sh`：需要 root。預設只停用/移除 systemd unit 與 `/usr/lib/securetunnel-gateway` 執行檔，**保留** `/etc/securetunnel-gateway`、`/var/lib/securetunnel-gateway`、`/var/log/securetunnel-gateway` 下的所有資料（私鑰、Peer/Resource/Policy Registry、Configuration History、備份都無法重新產生，預設不刪除是刻意的 fail-closed 設計）。需要同時加上 `--purge-data` **與** `--yes-i-am-sure` 兩個旗標才會實際刪除這些資料。
- ✅ **（Phase 7）`uninstall.sh` 現在會執行範圍精確的防火牆/介面清理**：解除安裝流程一律（不受 `--purge-data` 影響，因為這是釋放 kernel/執行期狀態，不是刪除持久化資料）嘗試（a）從仍存在的 `gateway.yaml` 讀出設定的 `interfaceName`，對**該精確介面名稱**執行 `wg-quick down`；（b）執行 `nft delete table inet securetunnel`——**只**刪除這一個 table，絕不執行 `nft flush ruleset` 或任何會影響其他 nftables table 的指令。兩者都是 best-effort：`wg-quick`/`nft` 不存在、介面已經是 down、table 已經不存在，皆視為正常情況而非錯誤，不會讓 `uninstall.sh` 失敗。詳見 security-model.md 第二十節。

### systemd Unit（`deploy/systemd/securetunnel-gateway.service`）

`install.sh` 會將此檔複製到 `/etc/systemd/system/securetunnel-gateway.service`，但**不會**自動 `enable`/`start`（需要操作者明確執行 `systemctl enable --now`）。

**已完成的真實驗證**：此 unit 檔已在 WSL2 Ubuntu 24.04（真實執行 systemd 的環境）中以 `systemd-analyze verify` 實際驗證，過程中發現並修正兩個問題（`Documentation=` 曾誤填非 URI 的自由文字、`StartLimitIntervalSec` 曾誤放在 `[Service]` 而非 `[Unit]`）；修正後在 `ExecStart` 指向的路徑放置一個假的可執行檔重新驗證，`systemd-analyze verify` 回傳 exit code `0`，**零警告、零錯誤**。這是工具實際跑出的驗證結果，不是推測。**Phase 6A** 把 `ExecStart` 從 `config status` 佔位指令改為 `gateway serve`（見下方「Gateway Daemon（Phase 6A）」）後，同樣重新以 `systemd-analyze verify` 驗證過，一樣是 exit code `0`、零警告。

### Gateway Daemon（Phase 6A，`ExecStart` 實際執行的指令）

`ExecStart` 現在執行 `securetunnel-gateway gateway serve --config /etc/securetunnel-gateway/gateway.yaml`——真正的常駐執行模式（`Daemon/GatewayDaemonService.cs`），取代了 Phase 6 原本的 `config status` 佔位指令。常用旗標：

- `--interval-seconds <n>`：常駐迴圈的檢查週期，預設 `60` 秒。
- `--once`：只執行一次啟動診斷後結束，不進入常駐迴圈（systemd 部署**不會**使用這個旗標；用於腳本化驗證/測試，見 [operations-guide.md](operations-guide.md#二十gateway-daemon--gateway-serve-phase-6a-已實作) 第二十節的完整行為說明，包含四種狀態分類、exit code 對照表、`Option A`（絕不自動 `config apply`）等設計細節）。

unit 預設以 `User=root` 執行；一個文件化但**未經驗證**的 `CAP_NET_ADMIN`-only 非 root 替代方案以註解形式保留在檔案中，啟用前需先在真實 Ubuntu Server 上驗證 `wg-quick`/`nft` 能否在該權限下正常運作。真實的 `systemctl start`/`enable --now` 生命週期本身在本開發環境（無 sudo、無系統安裝目標）仍未實際跑過——已驗證的是 unit 檔語法本身（`systemd-analyze verify`）與 daemon 二進位在真實 WSL2 Ubuntu 24.04 上直接執行 `gateway serve --once` 的行為（見 operations-guide.md 第二十節）。

## 三、Client 端安裝（本階段範圍外，僅供 Lab 測試）

本階段不開發 SecureTunnel 自有 Client。Lab 測試階段請使用標準 WireGuard client：

- Windows：[WireGuard for Windows](https://www.wireguard.com/install/)
- Linux：發行版對應的 `wireguard-tools` 套件

Client 設定檔內容由 Gateway 在 Bootstrap/Lab 情境下產生（見 [security-model.md](security-model.md#一wireguard-key-management)），正式環境建議 Client 自行產生金鑰對後，只把公鑰提供給 Gateway 管理者新增為 Peer。

## 四、Root/Sudo 權限需求彙整

| 操作 | 是否需要 root | 原因 |
|---|---|---|
| 安裝 `wireguard-tools` / `nftables` | 是 | 系統套件安裝 |
| 載入 WireGuard kernel module | 是 | Kernel 層操作 |
| 設定 `ip_forward` sysctl | 是 | Kernel 網路參數 |
| 建立/設定 WireGuard 介面 | 是 | 網路介面管理 |
| 套用 nftables 規則 | 是 | Netfilter 規則管理，需要 `CAP_NET_ADMIN` 等同等級權限 |
| 產生 WireGuard 金鑰對 | 否（`wg genkey` 本身不需 root） | 純使用者空間運算，但寫入的檔案路徑通常需要 root 才能設定正確權限與擁有者 |
| Gateway Agent 日常運作（讀取設定、health check 查詢） | 視部署而定 | 若採用 systemd + 適當 capabilities，可望降低到不需完整 root（見 security-model.md 第三節），本階段先以 root 執行 |

## 五、Known Limitations

- `scripts/install-wireguard.sh`、`scripts/generate-client-config.sh` 這兩支早期規劃的獨立腳本並未實作；Step 2（安裝 `wireguard-tools`/`nftables`）仍需手動執行 apt 指令，Client 設定改由 `securetunnel-gateway peer add`/`client-config` 相關 CLI 指令產生。
- `scripts/install.sh`/`scripts/uninstall.sh` 在本開發環境（WSL2，無 sudo/無系統安裝目標）**無法以真正的 root 身份完整執行**；已完成的是程式碼審閱、`bash -n` 語法檢查，以及兩支腳本自身的 `--dry-run` 模式在真實 WSL2 Ubuntu 24.04 上實際跑過（`uninstall.sh --dry-run` 也已驗證能從一份真實構造的 `gateway.yaml` 正確解析出 `interfaceName` 並印出對應的 `wg-quick down`/`nft delete table` 計畫指令，見 Phase 7 完成報告）。真正的 root 執行、systemd `enable --now`、以及 `wg-quick`/`nft` 的真實啟動/清理仍待在具備 sudo 的正式 Ubuntu Server 上驗證——`test-lab/run-integration-tests.sh`（見 [testing-guide.md](testing-guide.md)）已準備好在那樣的環境上跑這一整組驗證。
- 在 WSL2 環境下，即使完成上述步驟，也無法完成外部真實 Client 的端對端連線測試（見 troubleshooting.md）。
- .NET 10 Runtime 在目標 Ubuntu 24.04 上的官方套件安裝方式（apt / snap / 手動安裝二進位）尚未於正式 Linux Server 上驗證過；本階段的 self-contained 發佈方式（見上）可繞過此需求，因為 self-contained 執行檔已內含 runtime，不需目標機另裝 .NET。
- 日誌全面委由 journald（見 operations-guide.md），不再規劃獨立的 `logging.applicationLogPath`/`auditLogPath` 檔案 log sink。
- WSL2 上執行 `wireguard generate-keys`／`wireguard start` 等指令時，因 WSL2 未安裝 `wireguard-tools`，會如預期回報 `BLOCKED`；這是環境限制的正確反映，不是程式錯誤。
- ✅ **（Phase 6A 已解決）** ~~Gateway Agent 目前是一次性 CLI，非常駐 daemon；systemd unit 的 `ExecStart` 是文件化的佔位符~~ —— `ExecStart` 現在執行真正的常駐模式 `gateway serve`（見上方「Gateway Daemon（Phase 6A）」）。仍未驗證的是真實 `systemctl start`/`enable --now` 生命週期本身（同樣受限於本開發環境無 sudo）。
