# Testing Guide

## 一、測試分類

### A. Unit Tests（✅ Phase 2+3+4+5+6+6A+7 已實作，372 個測試全數通過）

```bash
dotnet test   # 於 repo 根目錄，執行 SecureTunnelGateway.sln 內所有測試專案
```

| 專案 | 測試數 | 涵蓋內容 |
|---|---|---|
| `tests/ConfigurationTests` | 10 | YAML 載入、欄位缺省時套用模型預設值、未知欄位不會拋錯、安全預設值（fail-closed/deny/nat 等） |
| `tests/ValidationTests` | 42 | CIDR/IP/Port/介面名稱/金鑰路徑格式驗證、VPN 與受保護網路重疊偵測、routed mode 拒絕、allow-all 拒絕、fail-closed 拒絕停用 |
| `tests/WireGuardTests` | 35 | WireGuard 設定產生（含私鑰遮蔽、既有檔案保護）、`wg`/`wg-quick` 指令組裝、狀態解析、失敗處理、dry-run 攔截、金鑰產生與私鑰絕不外洩、**Phase 3**：Active peers 渲染為 `[Peer]` 區塊、非 Active peer 拒絕、重複公鑰/AllowedIP 拒絕；**Phase 7 新增**：`DryRunSystemCommandExecutorTests`——`wg genkey`/`wg pubkey`/`wg set` 在 dry-run 下絕不觸及真實 executor（defense-in-depth，6 個測試） |
| `tests/PeerTests` | 59 | **Phase 3**：公鑰格式驗證（含佔位金鑰偵測）、VPN IP 配發（自動/明確指定/衝突/耗盡/狀態釋放政策）、Peer Registry 原子寫入與 fail-closed 讀取驗證、Peer 生命週期狀態機（Add/Enable/Disable/Revoke/Remove 全部合法與不合法轉換）、Client 設定範本產生 |
| `tests/FirewallTests` | 94 | **Phase 4**：Resource/Policy 欄位驗證（IPv4/CIDR/port/協定/過廣目的地/IPv6 拒絕）、Resource/Policy Registry 原子寫入與 fail-closed 讀取、Resource/Policy 生命週期服務、**nftables 規則產生器**（Active/Enabled 過濾、default deny、無 allow-all、確定性輸出、NAT 範圍限定、port range/UDP 語法）、**Apply 生命週期**（語法失敗/套用失敗/驗證失敗的還原行為，8 個情境）、`nft` 指令組裝與 dry-run 攔截；**Phase 7 新增**：`GenerateAsync_NeverEmitsAnIpv6AcceptMatcher_Ipv6IsDeniedByConstruction`——鎖定「`inet` combined family + 只使用 `ip`/從不使用 `ip6` 比對式」這個結構性 IPv6 拒絕證明（1 個） |
| `tests/LifecycleTests` | 41 | **Phase 5**：`FileOperationLock`（正常取得/釋放/並發拒絕/過期鎖回收，6 個情境）、`ConfigurationHistory` 原子寫入與 fail-closed 讀取、`SnapshotHasher` 確定性雜湊、**`ConfigurationLifecycleService`**（Desired→Candidate→Active 全流程、驗證失敗不影響 Active、連續 apply 的 Active/LastKnownGood 遞移、WireGuard 失敗/nftables 失敗兩種部分失敗情境、驗證失敗情境、並發鎖拒絕、Rollback 合法性檢查與快照隔離、crash recovery 偵測、版本保留裁剪，共 21 個 apply/rollback/crash-recovery 情境）；**Phase 6**：`IsDesiredStaleAsync`（Registry 即時雜湊 vs Active 快照 `ContentHash` 比對，3 個情境）、`DetectIncompleteOperationAsync` 對中斷 rollback/損毀 history/Active 指向遺失快照三種情境的偵測（3 個情境） |
| `tests/DeploymentTests` | 14 | **Phase 6**：`BackupService`——無檔案可備份時失敗、dry-run 不寫檔、建立後 `ListAsync` 正確顯示、私鑰內容納入備份但絕不出現在 manifest/訊息中、還原 dry-run 不動任何檔案、實際還原寫入新內容並保留舊內容為 `.pre-restore-*`、毀損封存包拒絕還原且不寫入、不支援的 `SchemaVersion` 拒絕還原、封存包不存在時回傳明確錯誤（9 個）；**Phase 6A 新增**：`SystemdUnitFileTests`——`ExecStart` 指向 `gateway serve` 而非舊佔位指令、不殘留「Placeholder ExecStart」文字、`Restart`/日誌指令一致（3 個，純文字比對，非 `systemd-analyze verify` 本身——後者見第一節下方說明）；**Phase 7 新增**：`RestoreAsync_ArchiveWithUnrecognizedEntryName_IsSkipped_NeverWrittenAsALiteralPath`（path-traversal 安全性迴歸測試）、`RestoreAsync_FailurePartwayThrough_ReportsWhichFilesWereAlreadyRestored_NotSilentlySuccess`（還原中途失敗的誠實回報，2 個） |
| `tests/DaemonTests`（新增） | 15 | **Phase 6A**：`GatewayDaemonService` 啟動分類——有效設定達到 Healthy/Degraded（不會是 Blocked/Failed）、設定完全無法載入時 Failed 並以非 0 exit code 結束、設定驗證失敗/必要工具缺失/私鑰不可用時皆為 Blocked（process 不結束）、啟動診斷本身丟出未預期例外時 Failed；crash recovery 情境——偵測到中斷操作、Effective 狀態無法判定、history 讀取失敗、Active 指標指向遺失快照（stale=true）；執行期行為——取消/優雅關閉回傳 exit code 0、`--interval-seconds` 正確傳遞給 ticker、單一週期例外不會讓迴圈崩潰、daemon 全程不曾呼叫 `ApplyAsync`/`RollbackAsync`（Option A 的反向證明）；安全性——私鑰內容絕不出現在任何 log 訊息中 |
| `tests/IntegrationTests` | 62 | Health check 狀態聚合（9 個情境）、CLI 端到端呼叫含 exit code 與 JSON 輸出（**Phase 2**：9 個；**Phase 3**：`peer *` CLI 12 個；**Phase 4**：`resource`/`policy`/`firewall` CLI 11 個；**Phase 5**：`config status/list/show/diff/validate/apply/verify/rollback` CLI 9 個；**Phase 6**：`gateway status/backup/backup list/restore` CLI 9 個，含 Desired-stale 偵測、backup→list 反映、restore 不自動套用的端到端整合；**Phase 6A**：`gateway serve --once` CLI 端到端呼叫 2 個，涵蓋無效設定路徑與有效設定的正常回傳） |
| **總計** | **372** | 皆為邏輯/單元/mocked 整合測試，**不等於**第三節的 Real Network Tests |

### B. Integration Tests

已完成的部分（見上表 `tests/IntegrationTests`）：Health check 聚合邏輯、CLI 端到端呼叫（含 `--dry-run` 確實不觸發真實指令、`--yes` 確認閘門、`--json` 輸出格式）；**Phase 3** Peer 生命週期與 WireGuard 設定產生器的整合；**Phase 4** Peer+Resource+Policy 與 nftables 規則產生器的整合；**Phase 5** 完整版本化生命週期：`config apply` 同時套用 WireGuard 與 nftables 並記錄版本、`config status` 正確反映 Active 版本、`config rollback` 成功建立新版本、`config diff` 正確比較兩版本的 Peer/Resource/Policy 差異。

已完成（Phase 6 新增）：
- ✅ **Systemd unit 語法驗證（真實工具驗證，非推測）**：`deploy/systemd/securetunnel-gateway.service` 已在 WSL2 Ubuntu 24.04（真實執行 systemd 的環境）用 `systemd-analyze verify` 實際驗證，過程中發現並修正兩個真實問題（`Documentation=` 曾誤填非 URI 字串、`StartLimitIntervalSec` 曾誤放在 `[Service]` 而非 `[Unit]`）；修正後在 `ExecStart` 路徑放置假的可執行檔重新驗證，回傳 exit code `0`，**零警告、零錯誤**。

已完成（Phase 6A 新增）：
- ✅ **`ExecStart` 改為真正的常駐 daemon 指令後重新驗證**：`ExecStart` 從 Phase 6 的 `config status` 佔位指令改為 `gateway serve` 後，同樣以 `systemd-analyze verify` 重新驗證，一樣 exit code `0`、零警告，證明語法/欄位放置本身依然正確。
- ✅ **`gateway serve --once` 在真實 Linux 上的啟動行為驗證**：已發佈的 self-contained `linux-x64` 執行檔在 WSL2 Ubuntu 24.04 上實際執行，對「`wireguard-tools`/`nftables` 未安裝」的情境正確記錄 `Gateway state: Blocked. Required tool(s) unavailable: wireguard-command, nftables-command.` 並在不進入常駐迴圈的情況下結束。**已知限制**：透過本專案 Bash 工具巢狀呼叫 `wsl.exe` 觀察到的數值 exit code 不可靠（見 troubleshooting.md 1.5 節，屬已知工具鏈問題非 daemon 缺陷）；因此 exit code 本身的正確性改由 `tests/DaemonTests`（in-process，非透過巢狀 `wsl.exe`）驗證。

已完成（Phase 7 新增）：
- ✅ **`scripts/uninstall.sh` 的範圍精確防火牆/介面清理，`--dry-run` 路徑真實驗證**：`bash -n` 語法檢查通過；在 WSL2 Ubuntu 24.04 上實際執行 `--dry-run`，並用一份真實構造的 `gateway.yaml` 驗證 `interfaceName` 解析邏輯正確、能印出對應的 `wg-quick down <name>`/`nft delete table inet securetunnel` 計畫指令。
- ✅ **`Backup/BackupService.cs` 還原中途失敗的誠實回報**：新增 2 個測試涵蓋「未知 entry 名稱不會被寫成字面路徑」與「中途失敗時已還原檔案清單被正確回報，而非未處理例外或誤報成功」。
- ✅ **`Services/DryRunSystemCommandExecutor.cs` 的 `wg` mutating 子指令防禦深度**：新增 6 個測試，見上表。
- ✅ **IPv6 拒絕由結構性推論補上迴歸測試**：見上表 `tests/FirewallTests` Phase 7 新增列。

尚未完成：
- `scripts/install.sh`/`scripts/uninstall.sh` 的真實 root 執行（需要 root 與真正的系統安裝目標，本開發環境不具備；`--dry-run` 路徑已如上真實驗證過）
- 真實 `systemctl start`/`stop`/`enable --now` 生命週期（同樣受限於本開發環境無 sudo、無系統安裝目標；unit 語法與 daemon 二進位本身皆已如上分別驗證過）
- Registry 變更自動觸發 `config apply`：**Phase 6A 已刻意選擇 Option A**（daemon 偵測到 Desired 落後 Active 時只記錄 log，見 operations-guide.md 第二十節），Option B（daemon 提供受控本地觸發器）仍未實作，留待未來視實際需求評估。

### C1. Real Linux Integration Test Lab（`test-lab/`，Phase 7 新增）

`test-lab/run-integration-tests.sh` 是一支已撰寫、可在真實 Ubuntu Server 上執行的整合驗證腳本，涵蓋下方 TC-001～TC-020 對應規格中的 15 項檢查（WireGuard 介面建立、Peer 設定、nftables table/chain 建立、default-deny、`config apply`/`rollback`、daemon 啟動與優雅關閉、systemd restart；`--with-packet-flow-test` 旗標另外用 network namespace 模擬一個受保護資源，涵蓋授權/NAT 相關檢查，預設關閉）。完整說明見 `test-lab/README.md`。

**誠實狀態**：這支腳本本身已完成 `bash -n` 語法檢查，且其「必須以 root 執行」的防護邏輯已在真實 WSL2 Ubuntu 24.04 上驗證過（確認在非 root 身份下正確拒絕並結束）；但**尚未在任何真實 Ubuntu Server 上端到端執行過**（本開發環境缺 `wireguard-tools`/`nftables`）——它是**已準備好、尚未執行**，不是「已驗證通過」，見 `test-lab/README.md` 的同一份聲明。

### C. Real Network Tests

需要真實 WireGuard handshake、真實 nftables 套用、真實 Client 連線。以下 TC-001～TC-020 是驗收標準，**目前 WSL2 環境大部分會標記為 BLOCKED**，需移轉到正式 Ubuntu Server 才能執行（見第三節）。

## 二、Real Network Test Cases 現況

> 狀態欄位只使用三種值：`PASSED`、`FAILED`、`BLOCKED`。**不允許把 BLOCKED 寫成 PASSED**，也不允許把 unit test 的結果當成這裡的驗收結果。**Phase 2 更新**：TC-001/002/003 對應的 CLI 功能已實作並在 WSL2 實測，但因 WSL2 未安裝 `wireguard-tools`、且缺乏免密 sudo，實測結果仍是 BLOCKED——差別在於現在是「工具缺失導致 BLOCKED」而非「功能不存在導致 BLOCKED」，原因欄位已更新反映這點。**Phase 3 更新**：TC-005（Client peer 設定成功）與 TC-015（Peer 停用後無法繼續存取）新增了 Registry 層級的單元/整合測試證據，但整體狀態仍是 BLOCKED，因為完整驗收語意需要真實網路層級的驗證（TC-006 handshake、Phase 4 nftables），原因欄位已詳細說明「哪一部分已驗證、哪一部分尚未驗證」，避免把子集驗證誤認為完整驗收。**Phase 4 更新**：TC-010/011/012/013/014/015/016 對應的 nftables 規則產生、default deny 結構、NAT 範圍限定、apply 生命週期皆已實作並有測試證據（見上方各列「原因」欄）；`firewall apply` 的語法驗證步驟已能在真實 Linux 上執行到「呼叫 `nft -c -f`」這一步，只是因 WSL2 未安裝 `nftables` 而回報 BLOCKED（工具缺失，非功能缺失，與 TC-001/002/003 相同性質）。**Phase 5 更新**：TC-017/018（設定驗證/rollback）現已有完整（mocked）程式邏輯證據，見下方各列說明。TC-004、TC-006～TC-009、TC-019、TC-020 仍全數 BLOCKED（多數依賴真實網路拓撲或 Phase 6 systemd 部署）。

| ID | 測項 | 狀態 | 原因 | 需要的環境 | 建議執行方式 |
|---|---|---|---|---|---|
| TC-001 | WireGuard 安裝檢查 | BLOCKED | **檢查邏輯已實作並在 WSL2 實測**（`validate-environment.sh` + `securetunnel-gateway doctor` 正確回報 `wireguard.wg`/`wireguard.wg-quick` = BLOCKED）；結果是 BLOCKED 因為 WSL2 尚未安裝 `wireguard-tools`，非程式問題 | 任一 Linux 環境 + sudo | 於 WSL2 或正式 Server 執行 `sudo apt install wireguard-tools` 後，`doctor` 應顯示 PASS，即可視為此 TC 通過 |
| TC-002 | Server key generation | BLOCKED | **功能已實作並在 WSL2 實測**（`securetunnel-gateway wireguard generate-keys` 於 `wg` 缺失時正確回報 `BLOCKED:` 而非假裝成功）；`tests/WireGuardTests/KeyManagementServiceTests.cs` 已用 mock 驗證產生/覆蓋保護/私鑰不外洩等邏輯 | 已安裝 `wireguard-tools` 的 Linux | 安裝 `wireguard-tools` 後於正式/WSL2 環境重跑 `wireguard generate-keys`，確認實際寫出 `0600` 私鑰檔案 |
| TC-003 | VPN interface 啟動 | BLOCKED | **CLI 指令已實作並在 WSL2 實測**（`securetunnel-gateway wireguard start --yes` 正確組出 `wg-quick up <iface>` 並在 `wg-quick` 缺失時回報 BLOCKED；`--dry-run` 確認不會誤觸發真實指令）；`wg-quick up` 本身需要 root，且 WSL2 未安裝 wireguard-tools | 具 root 權限的 Linux | 安裝 wireguard-tools 後，`sudo`（或具權限帳號）執行 `wireguard start --yes` |
| TC-004 | Server VPN IP 正確 | BLOCKED | 依賴 TC-003 | 同 TC-003 | 同 TC-003 |
| TC-005 | Client peer 設定成功 | BLOCKED | **`peer add` 功能已實作並在 WSL2/Windows 實測**（`peer add --yes` 成功配發 VPN IP 並持久化，`peer list` 正確顯示；`tests/PeerTests`、`tests/IntegrationTests/PeerCliInvocationTests` 涵蓋）。整體仍 BLOCKED，因為本 TC 語意包含「該設定能讓真實 Client 連線」，這需要 TC-006（真實 handshake），目前受 WSL2 網路限制 | 同 TC-003 + 至少一個 Client 公鑰 | 移轉到正式 Server 並完成 TC-006 後，用同一個已註冊的 Peer 驗證 |
| TC-006 | Client 成功 handshake | BLOCKED | WSL2 NAT 網路限制，外部 Client 無法連入；功能尚未實作 | 正式 Ubuntu Server 或已設定 portproxy 的環境 + 真實 Client | 移轉到正式 Server，或設定 `netsh portproxy`（見 troubleshooting.md） |
| TC-007 | Windows Client 可連線 | BLOCKED | 同 TC-006 | 同 TC-006 + Windows 主機 | 同 TC-006 |
| TC-008 | Linux Client 可連線 | BLOCKED | 同 TC-006 | 同 TC-006 + Linux 主機 | 同 TC-006 |
| TC-009 | VPN Client 可取得 VPN IP | BLOCKED | 依賴 TC-006 | 同 TC-006 | 同 TC-006 |
| TC-010 | VPN Client 可存取允許的 Website | BLOCKED | 依賴 TC-006（真實 handshake）+ Test Lab（Phase 7）。**規則產生層級已有測試證據**：`FirewallRuleGeneratorTests` 驗證 Active Peer + Enabled Resource + Enabled Policy 會正確產生 `ip saddr <peerIp> ip daddr <resourceIp> tcp dport 443 accept`，且已用真實 `nft -c -f` 在 WSL2 驗證語法正確（見 testing-guide.md 本節 Phase 4 更新說明）。但「真實封包確實通過」需要真實網路 | 正式 Server + test-lab 服務 | Phase 7 已提供 `test-lab/run-integration-tests.sh --with-packet-flow-test`（尚未在真實 Server 執行過），於正式 Server 執行後標記結果 |
| TC-011 | VPN Client 可存取允許的 API | BLOCKED | 同 TC-010 | 同 TC-010 | 同 TC-010 |
| TC-012 | VPN Client 可存取允許的 TCP Service | BLOCKED | 同 TC-010 | 同 TC-010 | 同 TC-010 |
| TC-013 | VPN Client 無法存取未授權資源 | BLOCKED | 同 TC-010（屬於負向測試）。**規則產生層級已有測試證據**：`FirewallRuleGeneratorTests.GenerateAsync_UnknownPeerOrResourceReference_ExcludedNotError`、`GenerateAsync_NeverProducesAnAllowAllRule` 驗證沒有對應 Policy 的組合不會產生 allow 規則 | 同 TC-010 | 同 TC-010，需特別驗證「拒絕」而非只驗證「允許」 |
| TC-014 | 未連 VPN 時無法存取受保護資源 | BLOCKED | 需要真實網路拓撲驗證 default deny。**規則產生層級已有測試證據**：`chain forward` 的 `policy drop` 保證任何未經 WireGuard 介面進來的流量天生不在轉送路徑上 | 正式 Server + test-lab | Phase 7 已提供 `test-lab/run-integration-tests.sh`（尚未在真實 Server 執行過），於正式 Server 執行後標記結果 |
| TC-015 | Peer 停用後無法繼續存取 | BLOCKED | 本 TC 語意是「真實網路層面」的存取阻斷，依賴 TC-006（真實 handshake）+ 真實 `nft apply`。**Registry + 規則產生層級的等價邏輯已有測試證據**：`peer disable`/`peer revoke` 後，`GetEffectivePeersAsync`、`config generate`、以及 **Phase 4 新增**的 `firewall generate` 皆確實排除該 Peer（`FirewallCliInvocationTests.FullFlow_DisableResource_ExcludedFromFirewallGenerate` 為對應的 Resource 版本，Peer 版本邏輯相同並由 `FirewallRuleGeneratorTests` 的 `GenerateAsync_NonActivePeer_ExcludedFromEffectiveRules` 涵蓋全部四種非 Active 狀態）；這證明「設定產生邏輯」正確，但**不等於**「真實封包被阻擋」，兩者是不同層級 | 正式 Server | Phase 7 完成後，在正式 Server 上：停用 Peer → 重新產生設定並套用 → 確認舊連線確實無法再存取受保護資源 |
| TC-016 | Firewall default deny 生效 | BLOCKED | 需要真實 nftables 套用與封包測試。**規則產生與語法驗證層級已有測試證據**：`firewall apply`（含 `nft -c -f` 語法檢查步驟）已用真實 `nft`（若已安裝）的程式路徑在 WSL2 上執行過，目前因 WSL2 未安裝 `nftables` 而在語法檢查/套用步驟回報 BLOCKED（見 troubleshooting.md），非程式邏輯問題 | 具 root 權限且已安裝 nftables 的 Linux | 安裝 `nftables` 後（`sudo apt install nftables`），先在 WSL2 驗證 `firewall apply` 本身是否成功（本機到本機），完整驗證待正式 Server |
| TC-017 | 錯誤設定不會套用 | BLOCKED | 完整 Configuration Apply 生命週期（candidate/active 版本化）已於 **Phase 5 實作完成**：`ConfigurationLifecycleServiceTests.ApplyAsync_InvalidGatewayConfiguration_ValidationFailed_ActiveUnchanged` 用真實（mocked）流程證明無效設定不會被套用、`history.ActiveVersion` 保持不變，且失敗的候選版本仍被記錄供稽核。整體仍標記 BLOCKED，因為這是 mocked 測試，尚未在真實 Ubuntu Server 上用真實 `wg`/`nft` 走過一次完整流程 | 正式 Ubuntu Server（已安裝 wireguard-tools + nftables） | 於正式 Server 執行 `config apply` 搭配一個刻意錯誤的設定，確認確實被拒絕，再標記 PASSED |
| TC-018 | 套用失敗可以 rollback | BLOCKED | Rollback 機制已於 **Phase 5 實作完成**：`RollbackAsync_ToValidVersion_CreatesNewActiveVersion`、`RollbackAsync_UsesSnapshotData_NotLiveRegistryChangedAfterward` 等測試證明可回滾到任一先前成功版本，且使用該版本自身快照而非即時 Registry。整體仍 BLOCKED，理由同 TC-017（mocked，非正式 Server 實測） | 正式 Ubuntu Server | 於正式 Server 完成一次 `config apply` 後刻意觸發下一版本失敗，執行 `config rollback` 確認系統回到前一版本的實際運作狀態 |
| TC-019 | Gateway 重啟後安全設定仍存在 | BLOCKED | **Phase 6A 更新**：Gateway Agent 現在有真正的常駐 daemon 模式（`gateway serve`），「重啟」語意的前置能力已齊備——`deploy/systemd/securetunnel-gateway.service` 的 `ExecStart` 已指向 `gateway serve` 並用 `systemd-analyze verify` 真實驗證（零警告零錯誤）、daemon 本身已在真實 WSL2 Ubuntu 24.04 上以已發佈的 `linux-x64` 執行檔驗證過啟動與 crash-recovery 偵測行為（`tests/DaemonTests`、operations-guide.md 第二十節）。整體仍 BLOCKED 的原因：本開發環境無 sudo、無系統安裝目標，尚未透過真實 `systemctl start`/`restart` 啟動過這個 process，因此「重啟後 WireGuard/nftables 狀態不受影響」這個語意本身仍待正式 Server 上實測 | 具 systemd 且已安裝 wireguard-tools/nftables 的正式 Linux | 於正式 Server 上 `sudo systemctl enable --now securetunnel-gateway`，之後 `systemctl restart securetunnel-gateway`，確認 WireGuard/nftables 狀態不受影響（daemon 本身重啟不會主動清除既有 nftables 規則，見 operations-guide.md 第五節） |
| TC-020 | Gateway Agent 重啟不會意外開放所有流量 | BLOCKED | 同 TC-019。**但底層保證已有測試證據**：nftables 規則的 default deny 是 chain policy 保證（見 firewall-model.md），Gateway Agent 本身重啟與否不影響已套用的 kernel 規則（Management Plane 與 Data Plane 分離，見 architecture.md 第三節） | 同 TC-019 | 同 TC-019 |

**Phase 5 更新**：TC-017、TC-018 的核心邏輯（設定驗證、candidate/active 分離、rollback 狀態機、fail-closed 保證）**已完整實作並通過 35 個 LifecycleTests + 9 個 CLI 整合測試**，這是目前累積證據最完整的兩個 TC；仍標記 BLOCKED 只是因為缺少正式 Ubuntu Server 上的真實 `wg`/`nft` 執行證據，而非邏輯未驗證。

## 三、未來移轉到正式 Ubuntu Server 的測試方式

1. 準備一台正式或雲端 Ubuntu Server 24.04 LTS，具備：
   - 可設定免密或互動 sudo 的部署帳號。
   - 已安裝 `wireguard-tools`、`nftables`。
   - 至少兩個可用網路路徑：對外可接受 WireGuard UDP 連線、對內可路由到受保護資源網段（或用 `test-lab/run-integration-tests.sh` 的 `--with-packet-flow-test` 選項，以 network namespace 在單一主機上模擬）。
2. 依 [installation-guide.md](installation-guide.md) 完成安裝。
3. 執行 `sudo GATEWAY_BIN=<path> test-lab/run-integration-tests.sh [--with-packet-flow-test]`（Phase 7 已提供、見上方 C1 節），涵蓋 TC-001～TC-020 中多數項目的自動化驗證。
4. 使用真實 Windows/Linux 主機安裝標準 WireGuard client，依 Gateway 提供的 Peer 設定連線，補上 `test-lab` 腳本未涵蓋的端到端連線測項（TC-006～TC-009）。
5. 依本文件 TC-001～TC-020 逐項執行，並把狀態從 BLOCKED 更新為實際的 PASSED/FAILED，記錄執行時間與執行者。
6. 若使用雲端 VM，注意安全群組/防火牆需開放 WireGuard UDP port，且需遵守十五章安全需求（不因測試方便而開放非必要 port）。

## 四、測試結果報告格式

每次執行 Real Network Tests 後，請記錄：

```
測試日期：<UTC 時間>
測試環境：<正式 Server / WSL2 / 其他，附版本資訊>
執行者：<角色，不記錄個資>
結果：
  PASSED: N
  FAILED: N
  BLOCKED: N
FAILED / BLOCKED 詳情：<逐項列出 ID、原因>
```

不得將本次報告中 BLOCKED 或 FAILED 的項目在後續文件中改寫為 PASSED，除非附上實際重新執行的證據（指令輸出、log 摘錄）。

## 五、Known Limitations

- Real Network Tests（TC-001～TC-020）全數 BLOCKED，符合預期，不代表功能失敗——本開發環境（WSL2）無 sudo、未安裝 `wireguard-tools`/`nftables`，真實封包層級驗證需要正式 Ubuntu Server。
- `scripts/install.sh`/`scripts/uninstall.sh` 未在真實環境（root、真正的系統安裝目標）執行過，僅完成程式碼審閱與腳本自身 `--dry-run` 模式驗證。
- systemd unit 檔的語法已用 `systemd-analyze verify` 真實驗證通過（見第一節），`ExecStart` 指向的 `gateway serve` 常駐 daemon 本身也已在真實 WSL2 Ubuntu 24.04 上直接執行驗證過啟動行為（見第一節 Phase 6A 更新），但**未**驗證 `systemctl enable --now`/`restart` 之後、透過 systemd 本身管理的真實生命週期行為（本開發環境無 sudo、無系統安裝目標）。
