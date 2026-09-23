# Troubleshooting

## 一、WSL2 環境限制

目前開發/驗證環境是 **WSL2 Ubuntu 24.04**，以下是已知限制與相對應的症狀，避免被誤判為程式錯誤。

### 1.1 沒有免密 sudo

**症狀**：任何需要 root 的指令（安裝套件、`modprobe`、`nft`、`wg-quick up`）在非互動 shell 中執行會卡住或直接失敗（`sudo: a password is required`）。

**原因**：帳號屬於 `sudo` 群組但未設定免密 sudo，且自動化工具的 shell 是非互動式，無法輸入密碼。

**處理方式**：本專案不會嘗試修改 sudoers 或要求免密設定。需要 root 的操作會產生可審查的 Bash script，請你在互動式終端機（例如 `wsl -d Ubuntu` 後手動輸入密碼）手動執行，並回報結果。

### 1.2 無法從外部連線到 WSL2 內的 WireGuard

**症狀**：即使在 WSL2 內成功啟動 `wg-securetunnel` 介面，外部真實 Windows/Linux 主機仍無法連線 handshake。

**原因**：WSL2 使用 Hyper-V 虛擬網路，預設採 NAT 模式，對外只有動態、非固定的內部 IP（例如 `172.23.x.x/20`），且 Windows Host 不會自動把 UDP port 轉發進 WSL2。

**處理方式**：
- 若只是要驗證 Gateway 內部邏輯（設定產生、驗證、規則內容），不需要解決此問題。
- 若要進行真實連線測試，需要：
  1. 在 Windows 上設定 `netsh interface portproxy`，將 Host 的 UDP port 轉發到 WSL2 的動態 IP（WSL2 重啟後 IP 會變，需要重新設定或用啟動腳本自動化）；或
  2. 改用一台真正的 Ubuntu Server / 雲端 VM 進行測試（建議正式驗證方式，見 [testing-guide.md](testing-guide.md)）。

### 1.3 沒有第二個網段模擬受保護網路

**症狀**：無法在同一台機器上同時架設「VPN 網段」與「受保護網路」並測試真實路由/NAT 行為。

**原因**：WSL2 只有一張虛擬網卡（`eth0`），沒有額外介面可以掛接第二個網段。

**處理方式**：使用 Docker（若已啟用 WSL integration）建立模擬的受保護服務容器，搭配自訂 bridge network 部分模擬路由行為，但這仍**不等於**真實的 Linux Server + 實體/虛擬第二網卡拓撲，測試結果需標註為「容器網路模擬」而非「真實網路驗證」。

### 1.4 Docker 指令在 WSL Ubuntu distro 中找不到

**症狀**：`docker: command not found`。

**原因**：Docker Desktop 已安裝在 Windows，但未對 `Ubuntu` 這個 WSL distro 啟用 WSL Integration。

**處理方式**：在 Docker Desktop 設定 → Resources → WSL Integration 中，手動啟用對 `Ubuntu` distro 的整合，然後重新啟動該 WSL distro（`wsl --shutdown` 後再開啟）。這是需要你在桌面環境手動操作的步驟。

## 一 B、Phase 2 已知環境細節

### 1.5 透過 `wsl.exe` 執行指令時 `$?`／exit code 顯示異常

**症狀**：在某些透過 Git Bash → `wsl.exe -d Ubuntu -- bash -c '...; echo $?'` 這種巢狀呼叫鏈執行的一次性指令中，回報的 exit code 與腳本實際行為不符（甚至連 `false; echo $?` 都會顯示 `0`）。

**原因**：這是 Git Bash（MSYS）呼叫原生 Windows 執行檔（`wsl.exe`）時的路徑/參數轉譯與串流緩衝交互作用造成的展示層級問題，不是 WSL2 本身或腳本邏輯的錯誤。

**處理方式**：不要依賴這種巢狀呼叫鏈裡的 `echo $?` 來判斷腳本正確性。改用下列任一方式驗證：
- `bash -x script.sh` 直接觀察執行流程與最終的 `exit N` 陳述式。
- 讓腳本把結果寫入檔案（例如 `echo "CODE=$?" > /tmp/result.txt`）再用獨立指令讀出。
- 在正式自動化（CI、systemd、Gateway Agent 內部呼叫）中，`ISystemCommandExecutor` 是透過 .NET 的 `Process` API 直接讀取 `ExitCode`，不經過這層巢狀 shell 呼叫，因此不受此問題影響。

### 1.6 在 WSL2 測試 self-contained 發佈的 Gateway Agent

由於 WSL2 未安裝 .NET，若要在 WSL2 上實際執行 `securetunnel-gateway` CLI（而非只在 Windows 端 `dotnet run`），需要用 self-contained 發佈：

```bash
dotnet publish src/SecureTunnel.GatewayAgent -c Release -r linux-x64 --self-contained true -o publish/linux-x64
```

發佈出的執行檔不依賴目標機是否安裝 .NET runtime，這與正式 Ubuntu Server 部署會採用的方式一致（見 [installation-guide.md](installation-guide.md)）。注意 `IEnvironmentChecker` 會嘗試在執行檔旁的 `scripts/` 子目錄尋找 `validate-environment.sh`；若該子目錄不存在，`doctor`／`health` 會回報 `BLOCKED: could not locate scripts/validate-environment.sh`，需手動複製 `scripts/*.sh` 到發佈目錄旁。

## 二、常見設定驗證錯誤（`gateway.yaml` 已於 Phase 2 實作；Resource/Policy 驗證已於 Phase 4 實作）

| 錯誤訊息關鍵字 | 可能原因 | 處理方式 |
|---|---|---|
| `overlaps with` | 網段重疊（VPN/受保護/LAN 網路互相重疊） | 依 [network-topology.md](network-topology.md) 調整 CIDR 規劃 |
| `no allowedPeers and no allowedVpnIps` | Resource Rule 沒有限定存取來源（Phase 4） | 明確填寫 `allowedPeers` 或 `allowedVpnIps` |
| `routing.mode = "routed" is not supported` | 設定了尚未實作的 Routed Mode | 改為 `nat`，或等待未來版本支援 Routed Mode |
| `permissions are 0644, expected 0600` | 私鑰檔案權限過於寬鬆 | `chmod 600` 該檔案 |

## 二 B、常見 Peer 管理問題（✅ Phase 3 已實作，可實際重現）

| 症狀 / 錯誤關鍵字 | 可能原因 | 處理方式 |
|---|---|---|
| `This public key is already registered` | 該公鑰已存在於 Peer Registry 中，**即使**先前那筆紀錄目前是 `Disabled`/`Revoked`/`Removed` 也一樣（刻意設計，見 [security-model.md](security-model.md#peer-生命週期狀態)） | 若確定要重新啟用同一台裝置，對舊紀錄執行 `peer enable`（`Revoked`/`Removed` 無法 enable，需要用新金鑰重新走註冊流程） |
| `Public key looks like a placeholder` | 貼上的是範例文件中的假金鑰（例如全部是同一個字元重複），不是真實產生的金鑰 | 在 Client 裝置上執行 `wg genkey \| wg pubkey` 取得真實公鑰 |
| `does not allow this transition` | 對 Peer 執行了不合法的狀態轉換（例如對已 `Revoked` 的 Peer 執行 `enable`） | 檢查目前狀態（`peer show`），確認轉換是否合法（見 [operations-guide.md](operations-guide.md) 第八節的狀態表） |
| `Peer registry` 相關錯誤（如 `contains invalid JSON`、`duplicate PeerId`） | `peers.json` 檔案損毀或被手動編輯出錯 | 這是刻意的 fail-closed 行為，不會靜默重置。從備份還原（見 [configuration-guide.md](configuration-guide.md#24-備份與復原)），或人工修正 JSON 語法錯誤後重試 |
| `peer add`/`peer revoke` 等成功了，但 Client 仍能/不能連線 | 忘記接著執行 `config generate --force` + `wireguard restart --yes` — Peer 指令只更新 Registry，不會自動套用到執行中的 WireGuard 介面（Phase 5 前的已知限制） | 見 [operations-guide.md](operations-guide.md) 第二節「步驟 3」 |
| `peer config` 回報 `BLOCKED: server public key not found` | 尚未執行 `wireguard generate-keys` | 先產生 Server 金鑰對，見 [installation-guide.md](installation-guide.md) Step 4 |

## 二 C、常見 Firewall / Resource / Policy 問題（✅ Phase 4 已實作，可實際重現）

| 症狀 / 錯誤關鍵字 | 可能原因 | 處理方式 |
|---|---|---|
| `is far too broad for a single resource` | `resource add --destination` 用了 `/8` 或更寬的 CIDR（含 `0.0.0.0/0`） | 改用更窄的 CIDR 或單一 IP；本專案刻意拒絕任何看起來像「繞過限制取得未受限存取」的目的地，見 [firewall-model.md](firewall-model.md#四protected-resource-模型已實作) |
| `looks like an IPv6 address` | `--destination` 填了 IPv6 位址 | Phase 4 僅支援 IPv4；若受保護資源只有 IPv6 位址，需等待未來版本支援 |
| `Unknown peer` / `Unknown resource` | `policy add` 的 `--peer-id`/`--resource-id` 指向不存在的紀錄 | 先用 `peer list`/`resource list` 確認正確的 id |
| `A policy already grants peer ... access to resource ...` | 嘗試新增重複的 (Peer, Resource) 授權 | 用 `policy list` 找到既有規則，如需調整直接 `policy enable`/`disable`，不需要新增重複規則 |
| `firewall generate`/`apply` 顯示 `[WARN] peerId: Peer '...' is currently Disabled` | 引用的 Peer 目前非 Active，規則已建立但不會產生效果 | 這是提示而非錯誤；`peer enable` 該 Peer 後重新產生即可生效 |
| `firewall apply` 回報 `BLOCKED: 'nft' command not available` | `nftables` 套件未安裝（WSL2 預設沒有） | `sudo apt install nftables`；安裝前 `firewall generate`（規則產生）與 `firewall validate` 仍可正常運作，只有涉及 `nft` 指令的步驟受阻 |
| `firewall apply` 回報 `nftables syntax validation failed` | 產生的規則語法有誤（理論上不應發生，`FirewallRuleGenerator` 的輸出經過測試涵蓋），或系統 `nft` 版本過舊不支援某些語法 | 用 `firewall generate` 查看產生的原始規則內容回報問題；檢查 `nft --version` 是否為現代版本（Ubuntu 24.04 內建版本應無此問題） |
| `Applied, but verification failed` | `nft -f` 回報成功但 `nft list table` 查不到 table（少見的環境異常） | 手動執行 `sudo nft list table inet securetunnel` 確認實際狀態；此為刻意的保守回報（寧可回報失敗也不假裝成功），需要人工介入排查底層 `nft`/kernel 狀態 |

## 二 D、常見 Configuration Lifecycle 問題（✅ Phase 5 已實作，可實際重現）

| 症狀 / 錯誤關鍵字 | 可能原因 | 處理方式 |
|---|---|---|
| `Could not acquire operation lock ... another operation appears to be in progress` | 另一個 `config apply`/`config rollback` 正在執行，或前一次執行異常終止留下鎖檔案 | 若確定沒有其他操作在跑，等待約 10 分鐘後鎖會被自動視為過期並回收（見 [security-model.md](security-model.md#二十一concurrency-and-locking已實作)）；緊急情況可手動確認 `operationLockPath` 指定的檔案內容（PID/時間戳），確認該 PID 確實不存在後手動刪除該檔案 |
| `config apply` 回報 `ApplyFailed`，訊息含 `WireGuard apply failed` | WireGuard 私鑰檔案不存在、路徑不安全（位於 `/tmp` 等）、或 `wg-quick` 未安裝/失敗 | 先執行 `securetunnel-gateway validate` 確認 `wireGuard.privateKeyPath` 設定正確；用 `wireguard generate-keys` 確認金鑰存在；`nft`/`wg` 未安裝時會明確回報 `BLOCKED:` 前綴 |
| `config apply` 回報 `EffectiveStateUnknown`，訊息含 `WireGuard applied successfully, but nftables apply failed` | 這是「部分失敗」情境：WireGuard 那一半成功了，nftables 那一半失敗（例如語法檢查失敗） | **不是安全漏洞**——nftables 已自動還原成前一份已知良好規則集，新 Peer 不會意外取得存取權，只是還沒生效；用 `config verify` 確認實際狀態，排除 nftables 問題後重新 `config apply` |
| `config rollback` 回報 `was never successfully applied` | 嘗試回滾到一個當初驗證失敗或套用失敗的版本 | 用 `config list` 找出真正成功過的版本（無 `[ACTIVE]`/`[LAST-KNOWN-GOOD]` 標記也可能曾經是 Active，看 `state` 欄位是否為 `Active`/`Verified`/`RollbackSucceeded`） |
| `config status` 顯示 `[WARNING] Version N was left in state 'Applying'` | 上一次 `config apply`/`config rollback` 執行到一半時行程被中斷（斷電、強制終止等） | 先執行 `config verify` 確認實際系統狀態（不要只看 history），再視情況重新 `config apply` 或 `config rollback` 到已知良好版本；見 [operations-guide.md](operations-guide.md) 第十五節 |
| Configuration History 相關錯誤（如 `contains invalid JSON`、`duplicate version`） | `config-history.json` 檔案損毀或被手動編輯出錯 | 與其他 Registry 相同的 fail-closed 行為，不會靜默重置；需人工修正或從備份還原 |

## 三、Health Check 狀態排解（✅ Phase 2 已實作，可實際重現）

| 狀態 | 可能原因（Phase 2 實際檢查項目） | 建議動作 |
|---|---|---|
| `Degraded` | `wg`/`wg-quick`/`nft` 未安裝（BLOCKED）、非 root/無 sudo、IPv4 forwarding 未啟用、`/etc\|/var/log/securetunnel-gateway` 目錄不存在、設定驗證有 Warning（例如未設定任何 protected network）、私鑰檔案不存在 | 執行 `securetunnel-gateway doctor --config <path>` 查看逐項細節，對照 [installation-guide.md](installation-guide.md) 補齊缺少的套件/目錄 |
| `Unhealthy` | 設定檔不存在或解析失敗、`security.failClosed=false` 等驗證 Error、私鑰檔案權限不是 owner-only（非 Windows 環境才會實際檢查） | 執行 `securetunnel-gateway validate --config <path>` 定位確切錯誤欄位，修正 `gateway.yaml` 後重跑 |
| `Unknown` | Health check 本身丟出未預期例外（已用 try/catch 包住，理論上不會導致 CLI crash，只會回報 Unknown） | 查看 Console 輸出的例外訊息；若持續發生請視為 bug 回報 |
| （尚未實作）磁碟空間、時間偏移警告 | `healthCheck.diskSpaceWarningPercent` / `timeSyncWarningSeconds` 目前只被解析，尚未有對應的實際檢查邏輯 | 屬 Known Limitations，Phase 6 前不會出現在 health 結果中 |

獨立的 `diagnostics` 指令確定不會提供；`doctor`（環境檢查 + health 分項）與 Phase 6 新增的 `gateway status`（Configured/Desired/Active/Effective 綜合狀態，見 [operations-guide.md](operations-guide.md) 第十八節）已涵蓋同樣的用途。

## 三 B、Startup Recovery Scenarios（✅ Phase 6：`gateway status` / `DetectIncompleteOperationAsync`）

每次呼叫 `gateway status`（或 `config status`）都會重新做一次以下判斷；**Phase 6A 起**，`gateway serve`（常駐 daemon，見三 C 節）也會在開機與之後每個檢查週期自動重跑同一套判斷並寫入 journald——不再需要操作者手動呼叫才會發現問題，但下表的判斷邏輯本身完全沒變。下表列出各情境下**實際會發生的行為**，而不是理想化的猜測：

| 情境 | 實際行為 |
|---|---|
| 乾淨的啟動（尚未執行過 `config apply`） | `desiredStale = true`（沒有 Active 版本可比對）；`activeVersion` 為 `null`；`overallStatus` 依 health 結果可能是 `Healthy`/`Degraded`，不會是 `Failed`（沒有失敗的操作可偵測） |
| 成功套用後 | `desiredStale = false`（Registry 雜湊與 Active 快照的 `ContentHash` 相符）；`incompleteOperation` 為 `null` |
| `config apply` 執行到一半被中斷 | `DetectIncompleteOperationAsync` 偵測到最新版本停留在 `Applying` 狀態，回報明確警告（含版本號與開始時間）；`overallStatus = Unknown`（**不會**猜測是成功還是失敗）；建議動作：`config verify` 查實際狀態，再決定 `config apply` 或 `config rollback` |
| `config rollback` 執行到一半被中斷 | 同上，狀態機同樣停留在中間態（`RollbackPending` 等），一樣回報 `Unknown` 而非假設回滾已完成 |
| `wireguard-tools`（`wg`/`wg-quick`）未安裝 | health 對應項目回報 `Blocked`；`gateway status` 的 `overallStatus = Blocked`（除非同時有更高優先權的中斷操作或 Unhealthy 狀態，見 [operations-guide.md](operations-guide.md) 第十八節的優先順序） |
| `nftables`（`nft`）未安裝 | 同上，`nftables-command` 健康項目回報 `Blocked` |
| 設定檔（`gateway.yaml`）不存在或無法載入 | `gateway status` 在載入階段就直接失敗（`overallStatus = "Failed"`），不會嘗試繼續查 health/lifecycle，因為沒有設定就沒有後續查詢的基礎 |
| `config-history.json` 損毀（無效 JSON、重複版本號等） | 拋出 `ConfigurationHistoryCorruptException`；`gateway status` 捕捉此例外並回報 `overallStatus = "Failed"` 與明確錯誤訊息，**不會**靜默視為「沒有歷史記錄」重新開始 |
| Active 指標指向一個實際上不存在的快照版本 | `IsDesiredStaleAsync`／`GetHistoryAsync` 內部視為異常情形（版本歷史邏輯上不一致），回報為 `stale = true`／在回應中明確呈現，不會拿一個不存在的快照假裝當作比對基準 |

**Registry（`peers.json`/`resources.json`/`policies.json`）本身毀損**且需要復原時，`gateway status`/`config verify` 只能告知「目前狀態不可信」，**真正的復原路徑是 `gateway restore`**（從既有備份還原後，人工執行 `config apply`，見 [operations-guide.md](operations-guide.md) 第十一節）——沒有備份可用時，需要人工重建 Registry 內容。

## 三 C、Gateway Daemon（`gateway serve`）狀態排解（✅ Phase 6A 已實作，可實際重現）

`gateway serve` 把上表同一套判斷結果分類成 `Healthy`/`Degraded`/`Blocked`/`Failed` 四種（與 `gateway status` 的五種狀態不完全相同，見 [operations-guide.md](operations-guide.md) 第二十節說明兩者差異的理由）。以 `journalctl -u securetunnel-gateway` 看到對應訊息時的處理方式：

| `journalctl` 訊息關鍵字 | 代表什麼 | 怎麼處理 |
|---|---|---|
| `Gateway state: Failed. Failed to load configuration ...` | 設定檔完全無法載入（YAML 語法錯誤、檔案不存在）；daemon process **已經結束** | 檢查 `--config` 指定的路徑是否正確、用 `securetunnel-gateway validate --config <path>` 確認 YAML 語法，修好後 `systemctl restart securetunnel-gateway` |
| `Gateway state: Blocked. Version N was left in state ...` | 上次 `config apply`/`rollback` 執行到一半被中斷（Phase 5 crash recovery，見三 B 節） | `config verify` 確認實際系統狀態，再決定 `config apply` 或 `config rollback <上個已知良好版本>`；daemon 會持續回報這個 Blocked 狀態，直到操作者處理完才會轉為 `Healthy`/`Degraded` |
| `Gateway state: Blocked. Required tool(s) unavailable: wireguard-command, nftables-command.` | `wg`/`wg-quick`/`nft` 其中之一（或全部）未安裝 | `sudo apt-get install -y wireguard-tools nftables`，安裝完成後不需要重啟 daemon，下個檢查週期就會自動偵測到並轉為其他狀態 |
| `Gateway state: Blocked. WireGuard private key is unavailable or has unsafe permissions.` | 私鑰檔案不存在，或權限不是 `0600` | `securetunnel-gateway gateway status --json` 確認詳細健康檢查項目；私鑰不存在時用 `wireguard generate-keys` 產生；權限錯誤時 `chmod 0600 <私鑰路徑>` |
| `Gateway state: Blocked. Configuration failed validation.` | `gateway.yaml` 能載入但未通過驗證規則（見 [configuration-guide.md](configuration-guide.md) 第六節安全限制摘要） | `securetunnel-gateway validate --config <path>` 看完整錯誤訊息，修正後不需重啟 daemon |
| `Gateway state: Blocked. Effective state cannot be safely determined: ...` | `config verify` 無法判定 WireGuard/nftables 實際狀態（通常也是工具未安裝，或指令執行失敗） | 同上「工具未安裝」處理方式；若工具已安裝仍出現，檢查 `wg show`/`nft list table inet securetunnel` 是否能正常執行 |
| `Gateway state: Degraded. Desired configuration has changed since the last successful \`config apply\` ...` | Registry（Peer/Resource/Policy）已變更但尚未 `config apply`（Option A：daemon 只記錄，絕不自動套用，見第二十節） | `securetunnel-gateway config apply --yes` |
| `Gateway state: Degraded. One or more optional health checks reported a warning ...` | health check 有 Warn 等級項目（非致命） | `gateway status --json` 或 `doctor` 看完整項目，依項目個別處理 |
| `Gateway state: Healthy. All startup checks passed.` | 一切正常 | 不需處理 |
| `Transient error during periodic Gateway state check; will retry in Ns.` | 某次檢查週期評估時發生未預期例外（例如短暫 I/O 錯誤），daemon **不會**因此結束，會在下個週期重試 | 若持續出現，檢查是否為磁碟空間/檔案權限問題；單次出現通常可忽略 |
| `SecureTunnel Gateway daemon stopped gracefully.` | 收到 SIGTERM（`systemctl stop`）或 SIGINT（前景執行時 Ctrl+C），daemon 正常結束，exit code `0` | 預期行為，不是錯誤 |

**驗證真實 exit code 語意時的已知限制**：本專案開發環境透過 Bash 工具巢狀呼叫 `wsl.exe` 觀察到的 `$?` 不可靠（見 1.5 節），因此 `gateway serve --once` 各種分類對應的 exit code（`Healthy`/`Degraded` → `0`；`Blocked`/`Failed` → 非 `0`）是透過 `tests/DaemonTests`（in-process xUnit）驗證，而不是透過巢狀 `wsl.exe` 呼叫觀察到的數值——後者的不可靠是已知的工具鏈問題，不是 daemon 本身的行為缺陷。真實 Linux 上的**啟動行為與日誌內容**（例如上表的 `Gateway state: Blocked. Required tool(s) unavailable...` 訊息）則已用已發佈的 self-contained `linux-x64` 執行檔在 WSL2 Ubuntu 24.04 上實際執行確認過。

## 三 D、`uninstall.sh` 的防火牆/介面清理（✅ Phase 7 已實作）

`scripts/uninstall.sh` 現在會嘗試 best-effort 清理，行為與訊息如下：

| 情境 | 訊息 | 是否視為錯誤 |
|---|---|---|
| `gateway.yaml` 仍存在且能解析出 `interfaceName` | `Bringing down WireGuard interface '<name>' (best-effort)...` | 否——即使 `wg-quick down` 失敗（例如介面本來就沒起來），`uninstall.sh` 仍會繼續往下執行 |
| `gateway.yaml` 已不存在，或找不到 `interfaceName` 欄位 | （dry-run 模式下會印出）`No interfaceName found in ... - would skip wg-quick down.` | 否，屬預期情況（例如已經先 `--purge-data` 過，或設定檔本來就不存在） |
| `nft` 指令存在 | `Removing nftables table 'inet securetunnel' (best-effort; no other table is touched)...` | 否——即使 table 已經不存在，`nft delete table` 失敗也不會讓腳本中止 |
| `wg-quick`/`nft` 未安裝 | 對應的清理步驟直接跳過，不印出錯誤 | 否——`command -v` 檢查不到就直接略過該步驟 |

**這些清理動作是 best-effort、且不受 `--purge-data` 影響**：無論有沒有加 `--purge-data --yes-i-am-sure`，只要 `gateway.yaml` 還在、且 `wg-quick`/`nft` 可用，就會嘗試清理——因為這清的是 kernel/執行期狀態（正在跑的介面、載入的 nftables table），不是需要額外確認才能刪除的持久化資料。清理**只**針對 Gateway Agent 自己管理的那一個 WireGuard 介面（設定檔裡指定的 `interfaceName`）與那一個 nftables table（`inet securetunnel`），絕不會影響主機上其他介面或 table。

`--dry-run` 模式已在真實 WSL2 Ubuntu 24.04 上執行驗證過（含用一份真實構造的 `gateway.yaml` 確認 `interfaceName` 解析邏輯正確），但因本開發環境未安裝 `wireguard-tools`/`nftables` 且無 sudo，**真正刪除一個存在的 table／真正停用一個存在的介面**尚未端到端驗證過，見 `test-lab/run-integration-tests.sh`（[testing-guide.md](testing-guide.md)）。

## 四、一般除錯建議

1. 先確認問題屬於「邏輯/設定層級」還是「真實網路層級」— 目前 WSL2 環境只能可靠地排解前者。
2. 查看 `journalctl -u securetunnel-gateway` 取得事件時間與錯誤訊息（日誌全面委由 journald，見 [operations-guide.md](operations-guide.md) 第十七節；未部署 systemd 時，直接查看 Console/stdout 輸出）。
3. 對照 [security-model.md](security-model.md) 確認觀察到的行為是否為刻意的安全設計（例如 NAT Mode 下看不到真實來源 IP，屬設計行為而非錯誤）。
4. 若懷疑是 Firewall 規則問題，先用 `securetunnel-gateway firewall validate`（唯讀）確認規則本身是否通過驗證，再排查是否為套用階段的問題。
5. 若懷疑是部署/systemd 層級問題（Phase 6），先執行 `securetunnel-gateway gateway status --json` 一次看清 Configured/Desired/Active/Effective 四層狀態，再決定要查 `journalctl`、`config verify` 還是 `gateway restore`。

## 五、Known Limitations

本文件中大部分「處理方式」對應的 CLI/腳本已實作至 Phase 7；`scripts/install.sh`/`scripts/uninstall.sh` 的真實 root 執行、systemd `enable --now`/`start`/`stop` 後的實際生命週期行為、以及任何真實 `wg`/`nft` 呼叫（含 Phase 7 新增的 `uninstall.sh` 防火牆/介面清理，見三 D 節），因本開發環境（WSL2，無 sudo、未安裝 `wireguard-tools`/`nftables`）限制仍未能實測，只完成程式碼審閱與（不需要 root/實際工具的）dry-run 模式驗證。`gateway serve` 本身的啟動行為與日誌內容已在真實 WSL2 Ubuntu 24.04 上以已發佈的 self-contained `linux-x64` 執行檔直接驗證過（見三 C 節），但同樣不是透過 `systemctl` 啟動的。`test-lab/run-integration-tests.sh`（Phase 7）已撰寫並可在真實 Ubuntu Server 上執行完整驗證，但尚未在任何真實環境跑過。
