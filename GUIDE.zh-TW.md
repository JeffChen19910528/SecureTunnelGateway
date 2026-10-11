# SecureTunnel Gateway 使用指南

[English](GUIDE.md) | **繁體中文**

在 Linux 伺服器上安裝、設定與維運 Gateway。回到 [README](README.zh-TW.md)。

## 環境需求

| 項目 | 需求 |
|---|---|
| 作業系統 | Ubuntu Server 22.04 / 24.04 LTS（x86_64） |
| 權限 | root 或 sudo |
| 套件 | `wireguard-tools`、`nftables` |
| 網路 | Client 可連到 WireGuard UDP port（預設 `51820`）；可路由到受保護網路 |
| .NET | 建置需 .NET 10 SDK；發佈的 self-contained 執行檔不需另裝 runtime |

## 1. 建置與安裝

```bash
dotnet publish src/SecureTunnel.GatewayAgent -c Release -r linux-x64 --self-contained true -o publish/linux-x64
sudo ./scripts/install.sh --publish-dir publish/linux-x64 [--dry-run]
```

`install.sh` 可重複執行。它會建立目錄佈局、複製執行檔與腳本、安裝（但不啟用也不啟動）systemd unit。

| 目錄 | 內容 |
|---|---|
| `/usr/lib/securetunnel-gateway/` | 執行檔與輔助腳本 |
| `/etc/securetunnel-gateway/` | `gateway.yaml`、`keys/` |
| `/var/lib/securetunnel-gateway/` | Peer / 資源 / 政策登錄檔、設定歷史、備份 |

日誌交由 journald：`journalctl -u securetunnel-gateway`。

## 2. 準備主機

```bash
sudo apt-get update && sudo apt-get install -y wireguard-tools nftables
./scripts/validate-environment.sh                 # 不需 root
sudo ./scripts/enable-ip-forwarding.sh --dry-run  # 先預覽，再去掉 --dry-run 實際執行
```

將 `config/gateway.example.yaml` 複製為 `/etc/securetunnel-gateway/gateway.yaml` 並修改。請勿提交私鑰；`privateKeyPath` 只是路徑。

## 3. 設定 Gateway

以下 `securetunnel-gateway` 指已安裝的執行檔。所有指令都可加 `--config <path>`；會改變狀態的指令需加 `--dry-run`（預覽）或 `--yes`（確認）。

```bash
# 伺服器金鑰與 WireGuard 設定
securetunnel-gateway wireguard generate-keys --dry-run
securetunnel-gateway wireguard generate-keys
securetunnel-gateway config generate --dry-run

# 註冊 Client（Gateway 只會儲存 Client 的公鑰）
securetunnel-gateway peer add --name alice --public-key <client-public-key> --yes

# 定義受保護資源，並授權 Peer 存取
securetunnel-gateway resource add --name intranet-web --destination 10.0.10.5 --protocol tcp --port 443 --yes
securetunnel-gateway policy add --peer-id <peer-id> --resource-id <resource-id> --yes

# 驗證後，一次套用 WireGuard + nftables
securetunnel-gateway config apply --dry-run
securetunnel-gateway config apply --yes
```

`peer config --id <id> --output client.conf` 會產生 Client 設定**範本**；私鑰由 Client 自行填入。

## 4. 啟動

```bash
sudo systemctl enable --now securetunnel-gateway
securetunnel-gateway gateway status
securetunnel-gateway health
securetunnel-gateway doctor
```

服務執行 `gateway serve`，會定期評估狀態並寫入日誌，但不會自行套用設定；請使用 `config apply`。

## 5. 日常維運

| 工作 | 指令 |
|---|---|
| 暫時封鎖 Client | `peer disable` / `peer enable` |
| 永久封鎖 Client | `peer revoke` |
| 暫停資源或政策 | `resource disable`、`policy disable` |
| 檢視防火牆 | `firewall status`、`firewall show` |
| 檢視設定歷史 | `config list`、`config diff`、`config show` |
| 比對實際狀態與記錄 | `config verify` |
| 回滾 | `config rollback --version <n> --yes` |
| 備份 / 還原 | `gateway backup`、`gateway restore`（還原不會啟用資料，之後請執行 `config apply`） |

各指令完整選項請用 `securetunnel-gateway <command> --help`。

## 6. 在真實伺服器上驗證

`test-lab/run-integration-tests.sh` 會檢查真實的 WireGuard 介面、nftables 預設拒絕、套用/回滾、daemon 與服務重啟。請在 Ubuntu Server 上以 root 執行；加上 `--with-packet-flow-test` 會以 network namespace 測試授權/未授權存取與 NAT。每項檢查結果為 `PASS`、`FAIL` 或 `BLOCKED`。詳見 [test-lab/README.md](test-lab/README.md)。

## 7. 解除安裝

```bash
sudo ./scripts/uninstall.sh [--dry-run]
sudo ./scripts/uninstall.sh --purge-data --yes-i-am-sure   # 連同設定與狀態一併刪除
```

預設會移除 `inet securetunnel` nftables table 與設定檔指定的 WireGuard 介面，但保留 `/etc` 與 `/var/lib` 的資料。
