# Security Model

本文件依十九章文件要求與十五章安全需求撰寫，說明 SecureTunnel Gateway 的安全設計、防禦假設與已知限制。**本專案未取得、也未聲稱取得任何正式安全認證**（例如 ISO 27001、SOC 2 等）；本文件是工程設計說明，不是合規證明。

> **Phase 2 實作狀態**：第一、四、六（部分）、十節描述的機制已有實際程式碼與測試佐證，而非僅是設計：私鑰以 `SensitiveString` 包裝防止意外經 `ToString()`/字串插值外洩（`KeyManagementServiceTests.SensitiveString_ToString_NeverExposesRealValue`）；`wg pubkey` 透過 stdin 而非命令列參數接收私鑰（避免 `ps` 可見，見 `KeyManagementServiceTests.GenerateServerKeyPairAsync_Success_...`）；所有外部指令一律經 `ISystemCommandExecutor` 以 `ProcessStartInfo.ArgumentList` 呼叫，不組字串餵給 shell；`security.failClosed=false`／`firewallDefaultPolicy≠deny`／`allowUnlistedResources=true` 皆由 `GatewayConfigurationValidator` 強制拒絕（42 個測試涵蓋）。
>
> **Phase 3 實作狀態**：第二 B、七、八節新增的 Peer 相關內容已有實際程式碼與測試佐證：`Peer` 類別結構上沒有私鑰欄位（`JsonFilePeerRepositoryTests.SaveAllAsync_NeverWritesAPrivateKeyField`）；重複公鑰（含 Revoked/Removed 狀態）一律拒絕新增（`PeerServiceTests.AddAsync_PublicKeyOfRevokedPeer_StillRejected`）；只有 `Active` 狀態的 Peer 會被納入產生的 WireGuard 設定（`WireGuardConfigGeneratorPeerTests.GenerateAsync_NonActivePeerInList_Rejected`）；`Revoked` 狀態的 Peer 無法被 `enable`（`PeerServiceTests.Revoke_ExcludesFromEffectiveConfig_AndCannotBeReEnabled`）；Peer Registry 讀取對缺漏欄位/重複 ID/重複公鑰/空檔案一律 fail-closed（`JsonFilePeerRepositoryTests`，7 個對應測試）。
>
> **Phase 4 實作狀態**：第六、七、八節新增/更新的內容已有實際程式碼與測試佐證：`FirewallRuleGenerator` 只納入 (Active Peer, Enabled Resource, Enabled Policy) 三者同時成立的組合（`FirewallRuleGeneratorTests`，多個排除情境測試）；不產生任何 allow-all 規則（`GenerateAsync_NeverProducesAnAllowAllRule`）；`FirewallApplyOrchestrator` 的每個失敗分支都不會讓系統落入全開放或狀態不明（`FirewallApplyOrchestratorTests`，8 個測試涵蓋語法失敗/套用失敗/驗證失敗個別情境並確認還原行為）；Resource 目的地拒絕 `/8` 或更寬的 CIDR（`ResourceValidatorTests.Validate_UnrestrictedDestination_Rejected`）。
>
> **Phase 5 實作狀態**：第五、八（部分）、十一、二十一、二十二節新增/更新的內容已有實際程式碼與測試佐證：Active/Candidate 版本在 Configuration History 中分離記錄且從不覆寫（`ConfigurationLifecycleServiceTests.ApplyAsync_TwiceSuccessfully_SecondBecomesActiveFirstBecomesLastKnownGood`）；驗證失敗的候選版本不會取代 Active（`ApplyAsync_InvalidGatewayConfiguration_ValidationFailed_ActiveUnchanged`）；Rollback 只接受曾經成功的目標版本、且使用該版本自身的快照資料而非即時 Registry（`RollbackAsync_ToNeverAppliedVersion_Rejected`、`RollbackAsync_UsesSnapshotData_NotLiveRegistryChangedAfterward`）；WireGuard 與 nftables 部分失敗會被明確標記為 `EffectiveStateUnknown` 而非假裝成功（`ApplyAsync_WireGuardSucceedsFirewallSyntaxFails_EffectiveStateUnknown_ActiveUnchanged`）；單一寫入者鎖正確拒絕並發套用（`ApplyAsync_LockAlreadyHeld_RejectsConcurrentApply`）並能回收過期鎖（`FileOperationLockTests`，6 個測試）；中斷操作能被偵測而非靜默視為成功（`DetectIncompleteOperationAsync_LastVersionStuckApplying_ReturnsWarning`）。
>
> **Phase 6 實作狀態**：第十七、十九、二十、二十三節新增/更新的內容已有實際程式碼佐證：備份封存包（`Backup/BackupService.cs`）建立時自動對私鑰檔案設定 `0600` 權限，還原前一律重新計算並比對 `manifest.json` 內的 `ContentSha256`（`tests/DeploymentTests/BackupServiceTests.cs`，9 個測試涵蓋毀損封存包拒絕寫入、還原前備份既有檔案等情境）；`scripts/uninstall.sh` 預設保留 `/etc/securetunnel-gateway`、`/var/lib/securetunnel-gateway` 資料，需同時加上 `--purge-data` 與 `--yes-i-am-sure` 才會刪除。設定完整性簽章（history 檔案雜湊鏈）與更細緻的本機權限分離仍是 Phase 7+ 的設計規格，尚未實作，見文末 Known Limitations。

## 一、WireGuard Key Management

- Server key pair 由 Gateway 在 Bootstrap 階段產生（`wg genkey` / `wg pubkey`），不自行實作金鑰產生邏輯（Phase 2，`KeyManagementService`）。
- Client private key **應由 Client 自行產生**，Gateway 只保存 Client public key（Phase 3，`Peers/PeerService` + `Models/Peer.cs`）。
- Gateway 提供的「產生 Client 設定」功能（`peer config`）只產生**範本**，從未產生或持有 Client 私鑰，任何情境（包含 Lab）皆不例外 — 詳見第三節。

## Peer 生命週期狀態（Phase 3，✅ 已實作）

`PeerStatus`（`src/SecureTunnel.GatewayAgent/Models/PeerStatus.cs`）定義五種狀態，狀態轉換由 `Peers/PeerService.cs` 強制執行，全部 fail-closed（不合法的轉換一律拒絕並回傳清楚錯誤，見 `tests/PeerTests/PeerServiceTests.cs`）：

| 狀態 | 語意 | 是否出現在 effective WireGuard 設定 | VPN IP |
|---|---|---|---|
| `Pending` | 已登記但尚未生效（保留給未來 Control Plane 預先註冊流程，Phase 3 的任何 CLI 指令都不會產生此狀態） | 否 | 佔用中 |
| `Active` | 生效中，可連線並存取 | **是** | 佔用中 |
| `Disabled` | **暫時**停用；身分、中繼資料、VPN IP 全部保留，方便之後 `enable` | 否 | 佔用中（保留） |
| `Revoked` | **永久**、安全驅動的撤銷；一旦撤銷不可逆 | 否 | **釋放**（可被其他 Peer 重新配發） |
| `Removed` | 軟刪除/封存；紀錄保留供稽核，非真正從儲存刪除 | 否 | 釋放 |

**關鍵不變量（invariant）**：不論狀態如何變化，**同一把公鑰一旦出現在 Registry 中，就永遠不能被新增為另一個 Peer**（`PeerService.AddAsync` 對「重複公鑰」的檢查涵蓋所有狀態，包含 `Revoked`/`Removed`）。這是刻意的設計，用來滿足「不得靜默重用已撤銷身分」的要求：即使一個 Peer 被 Remove，攻擊者或誤操作都無法用同一把公鑰重新註冊取得存取權；如果確實需要讓同一台裝置重新加入，操作者必須用**新的**金鑰對重新走一次「Client 端產生金鑰 → Gateway 註冊公鑰」的流程（見 [operations-guide.md](operations-guide.md) 第二節）。

VPN IP 釋放政策：`Disabled` 保留 IP（因為它預期會被 `enable` 復原，保留 IP 可以避免復原後又要重新分配、且不會有暫時性的位址衝突風險）；`Revoked`/`Removed` 釋放 IP（因為存取權已永久終止，繼續佔用位址只會浪費本就有限的 Client Pool 空間）。此政策由 `Peers/Ipv4VpnIpAllocator.cs` 的 `OccupyingStatuses` 常數實作，並有 `Ipv4VpnIpAllocatorTests` 涵蓋兩種情境。

## 二、Private Key Protection

- Server private key 儲存於檔案系統，檔案權限限制為僅 Gateway Agent 執行帳號可讀（規劃 `0600`，擁有者為服務帳號）。
- Private key 不得出現在：一般操作 log、error 訊息、CLI 一般輸出、設定檔的版本控制範例中。
- `.gitignore` 明確排除任何實際金鑰檔案與正式設定檔，只保留 `.example` 範例。

## 二 B、Client Private Key Security（強制要求，Phase 3 已實作）

這是本專案的強制安全要求，非選項：

**Gateway 絕不：**
- 把產生 Client 私鑰當成一般 Gateway 職責的一部分。
- 把 Client 私鑰存進 Peer Registry（`Models/Peer.cs` 這個類別在結構上**沒有**任何可存放私鑰的欄位 — 見下方「結構性保證」）。
- 把 Client 私鑰印在 CLI 輸出中。
- 把 Client 私鑰寫進 log。
- 從一般的 Peer 查詢/列表 API 回傳 Client 私鑰（因為根本不存在可回傳的東西）。
- 把 Client 私鑰放進儲存庫的任何檔案。

**實際流程**（`operations-guide.md` 第二節有完整指令範例）：

1. Client 私鑰在 **Client 裝置上**自行產生（`wg genkey`），或由操作者在**獨立、受控**的流程中產生（本專案不提供這個流程的自動化，刻意如此）。
2. Gateway 只接收 Client **公鑰**（`peer add --public-key`）。
3. Gateway 儲存公鑰與 Peer 中繼資料（Peer Registry，見 [configuration-guide.md](configuration-guide.md)）。
4. Gateway 產生 Client 設定**範本**（`peer config`），其中私鑰欄位是明確標示的佔位字串 `<INSERT_CLIENT_PRIVATE_KEY_HERE>`，絕不是真實私鑰，也不是憑空捏造的假值。

**結構性保證**（比「程式邏輯保證」更強）：`Models/Peer.cs` 這個 C# 類別完全沒有私鑰欄位，因此「不小心把私鑰序列化進 JSON Registry」在型別層級就不可能發生 — 不需要依賴「記得檢查」這種容易疏漏的人工紀律。`tests/PeerTests/JsonFilePeerRepositoryTests.SaveAllAsync_NeverWritesAPrivateKeyField` 額外驗證輸出的 JSON 內容不含 `PrivateKey` 字樣，作為迴歸測試。

**Lab-only 金鑰產生流程**：本專案**沒有**實作任何「Gateway 代為產生 Client 金鑰對」的功能，即使明確標示為 Lab-only 也沒有 — 原始需求允許在明確隔離、有文件記載限制的情況下提供這類功能，但團隊評估後判斷：CLI 引數方式接收私鑰會讓私鑰出現在 shell history／`ps` 輸出，風險大於「示範方便」帶來的價值，因此刻意不實作，改用「Client 端自行 `wg genkey`，只把公鑰交給 Gateway」作為唯一流程，Lab 與正式環境完全相同，沒有例外路徑需要額外留意。

## 三、Root Privilege（Root 權限模型）

- 需要 root 的操作僅限於：載入/設定 WireGuard 介面、套用 nftables 規則、修改 `ip_forward` sysctl。
- Gateway Agent 以 systemd service 執行，未來評估是否能透過 Linux capabilities（如 `CAP_NET_ADMIN`）取代完整 root，取代前先以 root 執行並在文件中清楚標示範圍（見 [installation-guide.md](installation-guide.md)）。
- 本階段（WSL2 開發環境）**不要求、也不會嘗試取得免密 sudo**；需要 root 的操作一律先產生可審查的腳本，交由使用者手動於具備權限的終端機執行。

## 四、Shell Command Injection

- 所有對外部指令（`wg`、`wg-quick`、`nft`、`ip`）的呼叫，一律使用參數化的 process 呼叫方式（例如 .NET 的 `ProcessStartInfo` + `ArgumentList`），**禁止**用字串組合後丟給 shell 執行。
- 所有輸入到指令參數的值（介面名稱、IP、port、公鑰等）在傳入前必須先通過設定驗證（格式、長度、允許字元），降低惡意或錯誤輸入造成的風險。

## 五、Configuration Tampering（設定檔被竄改）

- ✅ **Phase 5 已實作**：Active 版本與 Candidate 版本在 Configuration History 中分離記錄（`Models/ConfigurationSnapshot.cs` + `ConfigurationHistory.ActiveVersion`），Active 版本只能透過 `config apply`/`config rollback` 的流程更新（產生新版本，從不覆寫舊版本記錄）。
- ✅ 每份設定具備唯一遞增版本號與 SHA-256 內容雜湊（`ContentHash`），Apply/Rollback 流程會把每次變更的版本、結果、失敗原因記錄到 Configuration History（`ConfigurationLifecycleServiceTests` 涵蓋成功/各種失敗分支的記錄行為）。
- 設定檔完整性驗證（例如對 history 檔案本身簽章，偵測檔案被外部竄改而非透過 CLI 合法變更）尚未實作，本階段仍以檔案權限（`0600`）與版本紀錄作為基礎防護，完整性簽章列入 Known Limitations。

## 六、Firewall Fail-Closed

- ✅ **Phase 4 已實作**：Default policy 為 **deny**，由 `chain forward` 的 `policy drop` 結構性保證（不是靠規則清單的最後一條，見 [firewall-model.md](firewall-model.md#二流量方向與-chain-設計已實作)）。
- ✅ 設定驗證階段拒絕「無目的地的 allow 規則」（`resourceId`/`peerId` 指向不存在的實體）與「全開放規則」（destination 字首 `/8` 或更寬，含 `0.0.0.0/0`），避免因設定錯誤導致全部放行（`ResourceValidatorTests`、`FirewallRuleGeneratorTests.GenerateAsync_NeverProducesAnAllowAllRule`）。
- ✅ `firewall apply` 失敗時（語法錯誤、套用失敗、驗證失敗），系統會還原到上一個已知良好的規則集（`.lastknowngood` 備份），不會因套用失敗而落入「規則消失 = 全部放行」的狀態（`FirewallApplyOrchestratorTests`，8 個測試涵蓋各失敗分支）。
- ⏳ Gateway Agent 或系統重啟後，nftables 規則是否維持在重啟前的安全狀態，需要 systemd 相依關係保證，屬 Phase 6 systemd 部署範圍，尚未實作（見 installation-guide.md）。

## 七、Unauthorized Peer Access（未授權 Peer 存取）

- ✅ **Phase 3 已實作**：只有出現在 Peer Registry 中、且狀態為 `Active` 的公鑰，才會被 `WireGuardConfigGenerator` 納入產生的 WireGuard 設定（`[Peer]` 區塊），才可能完成 handshake 並取得 VPN IP。`Pending`/`Disabled`/`Revoked`/`Removed` 狀態的 Peer 一律被排除（`WireGuardConfigGeneratorPeerTests.GenerateAsync_NonActivePeerInList_Rejected` 驗證：即使呼叫端不小心把非 Active 的 Peer 傳進產生器，也會被拒絕，而非被靜默忽略或渲染）。
- ✅ **Phase 4 已實作**：即使某來源完成了 WireGuard 層的 handshake，仍必須通過 `securetunnel_vpn_access` chain 的 allow-list（by 來源 VPN IP + 目的地 + protocol + port）才能存取特定受保護資源 — 這兩層防護（WireGuard 層驗證身分 + nftables 層限制可達資源）現在**都已實作**：`FirewallRuleGeneratorTests` 驗證只有 (Active Peer, Enabled Resource, Enabled Policy) 三者同時成立才會產生 allow 規則；未知/非 Active Peer 的引用被排除而非報錯（見 [firewall-model.md](firewall-model.md#五access-policy-模型已實作allow-only--implicit-deny)）。
- **驗證範圍的誠實聲明**：以上是規則「產生」層級的驗證（規則內容正確反映 Peer/Resource/Policy 狀態），已在真實 Linux 用 `nft -c -f` 驗證過語法。真實封包是否確實被這些規則擋下/放行，需要正式 Ubuntu Server 進行 TC-013（未授權存取應被拒絕）等真實網路測試，目前 BLOCKED（見 testing-guide.md）。

## 八、Revoked Peer Behavior（Peer 被撤銷後的行為）

- ✅ **Phase 3 已實作**（Peer Registry 層）：`peer revoke` 會把狀態改為 `Revoked` 並**釋放**其 VPN IP；下一次 `config generate` 產生的 WireGuard 設定不會再包含該 Peer 的 `[Peer]` 區塊。`peer enable` 對 `Revoked` 狀態的 Peer 會被明確拒絕（見上方「Peer 生命週期狀態」的不變量），不存在任何指令能讓一個已撤銷的身分重新生效。
- ✅ **Phase 4 已實作**（Firewall 層）：撤銷的 Peer 同時會從 `firewall generate` 產生的 `securetunnel_vpn_access` chain 中消失 — 因為規則產生器每次都是從 Peer Registry 的**即時狀態**重新計算 effective rules，不是從快取或先前的規則集增量修改，所以「WireGuard 層撤銷了但 Firewall 層忘記同步」這種不一致狀態在架構上不可能發生（沒有「同步」這個步驟需要做對，兩者都是同一次 `Active` 狀態查詢的結果）。
- ⚠️ **仍需操作者主動執行 `config apply`**：`peer revoke` 本身只更新 Peer Registry，**不會自動**觸發套用。✅ **Phase 5 已縮短這個步驟**：操作者現在只需執行單一指令 `securetunnel-gateway config apply --yes`，就會同時重新產生並套用 WireGuard **與** nftables（見 [operations-guide.md](operations-guide.md) 第十三節），不再需要分別手動執行 `config generate`/`wireguard restart`/`firewall generate`/`firewall apply` 四個指令。在 `config apply` 完成之前，已撤銷的 Peer 若先前已完成 handshake 且 session 仍存活，理論上可能仍可持續使用既有連線直到套用完成——這是時間窗口而非架構缺陷，仍列入 Known Limitations，因為 Phase 5 沒有實作「Registry 變更時自動觸發 apply」（那需要背景程序/watch 機制，屬 Phase 6 systemd 常駐化之後才適合做）。
- Health check 尚未針對「Registry 與實際 WireGuard/nftables 設定不同步」這個狀態設計專門的檢查項目，列入 Known Limitations。

## 九、Replay / Handshake Security

WireGuard 協定本身處理 replay protection 與 handshake 安全（Noise Protocol Framework），**本專案不重新實作或修改這部分邏輯**，完全信任並依賴上游 WireGuard 的實作與安全紀錄。

## 十、Log 與敏感資料

Log 中**禁止**出現：

- Server / Client private key
- API token
- Password
- 完整敏感設定內容（例如完整設定檔傾印）
- 不必要的封包內容（Payload）

允許記錄：public key（可作為 Peer 識別的一部分，通常視為半敏感資訊，記錄時可考慮只記錄指紋/前綴，細節於 Phase 6 的 Logging 實作中定案）、VPN IP、事件結果、時間戳等。

## 十一、Configuration Rollback Abuse

- ✅ **Phase 5 已實作**：`config rollback` 屬安全性敏感操作，CLI 強制要求 `--yes` 或 `--dry-run`（本地 CLI 以系統帳號權限為信任邊界；未來若開放遠端管理需額外認證，見 architecture.md 第十六節未來 Control Plane 整合）；每次 rollback 都寫入 Configuration History（誰不記錄個人身分，但記錄時間、從哪個版本、回滾到哪個版本、結果——`RollbackTargetVersion` 欄位）。
- ✅ Rollback 目標**必須**是系統記錄在案、且**曾經成功**（`Active`/`Verified`/`RollbackSucceeded`）的版本——`RollbackAsync_ToNeverAppliedVersion_Rejected`、`RollbackAsync_ToUnknownVersion_Rejected` 測試驗證：不接受任意外部指定的設定內容、也不接受回滾到一個當初驗證失敗的版本，避免被用來繞過驗證流程注入未經檢查的設定。
- ✅ Rollback 使用目標版本**自身內嵌**的快照資料，不依賴當下可能已變更的 Registry（`RollbackAsync_UsesSnapshotData_NotLiveRegistryChangedAfterward` 測試驗證），避免「回滾」實際上套用了一份與當初標記版本不同的內容。

## 十二、Local Privilege Escalation Risks

- Gateway Agent 若以完整 root 執行，其本身的程式碼品質與輸入驗證就是重要的攻擊面；因此堅持第四節的參數化指令呼叫與輸入驗證。
- 設定檔與金鑰檔案權限最小化（僅服務帳號可讀寫），降低本機低權限使用者讀取敏感資料或竄改設定的風險。
- 本階段未實作細緻的權限分離（例如把「讀取 log」與「套用設定」分成不同帳號），列入 Known Limitations。

## 十三、Denial of Service

- WireGuard 本身對未知來源的封包有一定防護（不回應無效 handshake），可降低部分 DoS 風險。
- nftables 規則本身可以加入基本的連線速率限制（rate limiting），本階段的預設規則模板**不**預設加入複雜的 DoS 防護（避免影響正常使用又缺乏實測），此為 Known Limitations，未來可依需求擴充。
- 本專案不實作深度封包檢測（依禁止事項第 11 點），因此不提供應用層 DoS 防護。

## 十四、Network Segmentation

- VPN Network、Protected Resource Network、Gateway LAN Network 在設定驗證階段強制檢查不重疊（見 [network-topology.md](network-topology.md)），是網路區隔的第一道防線。
- 受保護資源之間彼此的網路區隔（例如 Website 是否能直接連到 TCP Service）不在本專案控制範圍內，屬於受保護網路自身的網路設計責任。

## 十五、IPv6 洩漏

- IPv6 forwarding **預設不啟用**。若受保護網路確實有 IPv6 需求，需要維運人員明確在設定中開啟，並理解目前的 nftables 規則模板主要針對 IPv4 設計，IPv6 規則需另外驗證，避免出現「IPv4 有管制、IPv6 沒有管制」而形成的洩漏路徑。
- Health check 與設定驗證階段建議檢查系統上是否有非預期開啟的 IPv6 forwarding，並回報。
- ✅ **（Phase 7 已審查並補上結構性證明）** `table inet securetunnel`（`Firewall/FirewallRuleGenerator.cs`）使用 nftables 的 **`inet` combined family**，這代表 `forward` chain 的 `policy drop` 對 IPv4 **與** IPv6 轉發流量同時生效；而目前所有 accept 規則（`securetunnel_vpn_access` chain）只使用 `ip saddr`/`ip daddr`（IPv4 專屬）比對，規則產生器從未輸出任何 `ip6` 比對式。結論：IPv6 轉發流量**沒有任何規則能命中 accept**，結構性地掉回 `policy drop`——這不是「忘記處理 IPv6」而是「同一個 default-deny 結構天生涵蓋 IPv6」。`tests/FirewallTests/FirewallRuleGeneratorTests.cs` 的 `GenerateAsync_NeverEmitsAnIpv6AcceptMatcher_Ipv6IsDeniedByConstruction` 將此性質鎖定為迴歸測試：未來若有人不小心新增了 `ip6` accept 路徑而未經安全審查，這個測試會失敗。
- ⚠️ 上述證明僅涵蓋「規則語意」層面（已通過真實 nft 語法檢查器驗證過語法，見 testing-guide.md），**尚未**用真實 IPv6 封包在真實 Linux 主機上端到端驗證「送一個 IPv6 封包，確認真的被擋下」，原因與第三節 NAT Packet Flow 相同：需要正式 Ubuntu Server，目前標記 BLOCKED。

## 十六、Management Plane 分離

- Gateway Agent（Management Plane）與 WireGuard / nftables（Data Plane）在程式碼結構與執行方式上分離（見 architecture.md 第三節）：Management Plane 掛掉不會讓 Data Plane 的既有規則消失。
- 未來與 Control Plane 的整合，一律採用 Gateway 主動 pull 設定 + 回報狀態的模式，Control Plane 不會直接對 Gateway 下達任意 shell command（見 architecture.md 第十六節），降低遠端管理介面被攻破後直接取得 Gateway shell 執行權的風險。

## 十七、Backup Security（✅ Phase 6 已實作）

- ✅ `gateway backup` 產生的封存包（tar+gzip）內含 WireGuard 私鑰（`keys/server.key`），視為敏感資料；建立時自動對其設定 `0600` 權限（Linux），存放位置需與正式金鑰檔案採取相同等級的權限限制，**不可**放在一般共享目錄或提交到版本控制。
- ✅ 封存包內含 `manifest.json`（`SchemaVersion`、`ContentSha256`），`gateway restore` 在寫入任何檔案**之前**一律重新計算並比對內容雜湊，雜湊不符（毀損或遭竄改）的封存包會被直接拒絕，不寫入任何檔案（`RestoreAsync_CorruptedArchive_RejectedWithoutWriting` 測試驗證）。
- ✅ `gateway restore` 從不自動套用（不會自動觸發 `config apply`），也從不靜默覆蓋——任何被取代的既有檔案都先備份為 `{原路徑}.pre-restore-{timestamp}`（`RestoreAsync_Real_WritesFilesAndPreservesPrevious` 測試驗證）。
- 本階段未實作**自動化排程**備份或加密備份機制（備份本身走 tar+gzip，非加密封存），列入 Known Limitations；備份與復原的手動流程見 [operations-guide.md](operations-guide.md) 第十/十一節。

## 十八、Time Synchronization

- WireGuard handshake 與 rekey 機制對系統時間有一定依賴；Health check 應檢查系統時間是否明顯偏移（例如與 NTP 來源差距過大），作為 Degraded 狀態的判斷依據之一。
- 本階段不強制安裝/設定 NTP client，僅在 health check 中檢查與提示。

## 十九、File Permission Requirements

| 檔案類型 | 建議權限 | 擁有者 |
|---|---|---|
| Server private key | `0600` | Gateway 服務帳號 |
| Active / Candidate 設定檔 | `0600` 或 `0640` | Gateway 服務帳號（群組視部署需求） |
| nftables ruleset 檔案 | `0600` | root / Gateway 服務帳號 |
| 一般操作 log | `0640` | Gateway 服務帳號 / log 群組 |

實際權限設定由安裝腳本（`scripts/install.sh`，見下方第二十節）與 systemd unit（`deploy/systemd/securetunnel-gateway.service`）定義套用，見 [installation-guide.md](installation-guide.md)。

## 二十、Secure Uninstall Behavior（✅ Phase 6 已實作，`scripts/uninstall.sh`）

- ✅ **預設保留資料**：`scripts/uninstall.sh` 只停用/移除 systemd unit 與 `/usr/lib/securetunnel-gateway` 執行檔，**預設保留** `/etc/securetunnel-gateway`（設定、金鑰）與 `/var/lib/securetunnel-gateway`（Registry、Configuration History、備份）——這些資料無法重新產生，刪除前必須是操作者的明確決定，而非解除安裝的預設副作用（fail-closed：寧可留下可能不再需要的資料，也不要意外刪除還有用的資料）。
- ✅ **雙重確認才會刪除資料**：需要同時加上 `--purge-data` **與** `--yes-i-am-sure` 兩個旗標，`uninstall.sh` 才會刪除 `/etc/securetunnel-gateway`、`/var/lib/securetunnel-gateway`（含其中的私鑰與備份）；只給 `--purge-data` 而不給 `--yes-i-am-sure` 會被拒絕並提示需要哪些旗標。
- ✅ 支援 `--dry-run`，可在不實際刪除任何東西的情況下預覽會執行的動作。
- ⏳ **未實作安全抹除**：刪除私鑰檔案時使用一般的檔案系統刪除（例如 Linux 上的 `rm`），未實作額外覆寫或安全抹除邏輯（視底層檔案系統能力而定，SSD/日誌型檔案系統本來就難以保證「覆寫等於實際清除」，列入 Known Limitations）。
- ✅ **（Phase 7 已實作）** ~~未實作移除 Gateway Agent 安裝的 nftables 規則~~ —— `uninstall.sh` 現在會執行**範圍精確**的清理：只呼叫 `nft delete table inet securetunnel`（絕不執行 `nft flush ruleset` 或任何會影響其他 table 的指令），並且會先從 `gateway.yaml` 讀出設定的 `interfaceName`、對**該精確名稱**執行 `wg-quick down`（絕不猜測或遍歷其他介面）。兩個動作都是 best-effort（找不到 `nft`/`wg-quick`、介面已經是 down、table 已經不存在都不視為錯誤），且**不受 `--purge-data` 旗標影響**（這是釋放 kernel/執行期狀態，不是刪除持久化資料，所以預設就會執行，不需要額外確認旗標）。已在 WSL2 上以真實 shell 執行驗證（`bash -n` 語法檢查 + 實際跑過 `--dry-run` 路徑並確認能正確從真實 `gateway.yaml` 解析出 `interfaceName`），但**尚未**在真實安裝、真實 `nft table` 存在的情況下端到端驗證（缺 `nftables`/`wireguard-tools`，見第三節）。

## 二十一、Concurrency and Locking（✅ Phase 5 已實作）

- `config apply`/`config rollback` 在真正開始套用前，會取得一個獨佔的單一寫入者鎖（`Lifecycle/FileOperationLock.cs`），實作方式是 `FileMode.CreateNew` + `FileShare.None` 建立鎖檔案——這在 Linux 與 Windows 開發機上行為一致，不依賴 Linux 專屬的 flock/fcntl API。
- 鎖檔案內容記錄持有者 PID、取得時間、主機名稱，讓另一個嘗試取得鎖的行程能在等待逾時前提供有意義的錯誤訊息（「另一個操作正在進行中，持有者：pid X，開始於 Y」）。
- **過期鎖偵測**：若鎖檔案存在但（a）記錄的 PID 對應的行程已不存在，或（b）鎖案齡超過 10 分鐘，視為「上一個持有者已崩潰」並安全回收——`FileOperationLockTests` 有 6 個測試分別驗證正常取得/釋放/逾時/兩種過期情境的判斷/未過期鎖不會被偷走。
- **明確的範圍限制**：這**只**保證單一 Gateway 主機內、單一行程層級的互斥，**不是**跨機器/分散式鎖。本專案本來就是單 Gateway 設計（見 architecture.md 未來 Control Plane 整合章節），多 Gateway 協調不在範圍內。
- Peer/Resource/Policy 三個 Registry 各自的 JSON 檔案寫入**仍然**沒有獨立的跨行程鎖定（這與 `config apply` 的鎖是不同層級——`peer add` 之類的指令不會取得 `config apply` 的鎖）；理論上兩個同時執行的 `peer`/`resource`/`policy` 指令仍可能互相覆蓋，列入 Known Limitations。

## 二十二、Crash Recovery（✅ Phase 5 已實作）

- `ConfigurationSnapshot.State` 在套用流程的每個關鍵步驟都會被持久化（`ApplyPending` → 觸碰系統前的最後檢查點；`Applying` → 即將開始寫入 WireGuard/nftables），因此即使行程在套用中途被中斷，Configuration History 中最後一筆紀錄的狀態能準確反映「進行到哪一步」。
- `DetectIncompleteOperationAsync`（`config status` 內部呼叫）會檢查最後一筆版本是否卡在非終態（`ApplyPending`/`Applying`/`RollbackPending`），若是則明確警告，**絕不**靜默把中斷的操作當成成功或失敗。
- 偵測到中斷操作時，系統**不會**自動嘗試修復——要求操作者先用 `config verify` 確認實際系統狀態（因為「history 記錄卡住」不代表「系統實際上沒套用成功」，唯一可靠的方法是直接查詢 `wg show`/`nft list table`），再決定重新 `config apply` 或 `config rollback`。這符合「Fail closed where possible / Require explicit operator action」的要求。
- ✅ **（Phase 6A 已解決）** ~~目前是 CLI 工具而非常駐 daemon，因此「啟動時檢查」實際上是「每次呼叫 `config status` 時檢查」~~ —— `gateway serve`（`Daemon/GatewayDaemonService.cs`）現在會在 daemon 啟動時、以及之後每個檢查週期（預設 60 秒）自動重跑這一整套判斷並寫入 journald，不再需要操作者手動觸發才會發現中斷的操作。**這個自動化本身仍嚴格遵守上面兩條規則**：daemon 偵測到中斷操作時同樣只記錄警告（分類為 `Blocked`），**絕不**自動嘗試 `config verify`/`config apply`/`config rollback` 以外的任何修復動作——見第二十四節。

## 二十三、systemd 部署下的 Root 權限（✅ Phase 6，延續第三節）

- `deploy/systemd/securetunnel-gateway.service` 預設以 `User=root` 執行，理由與第三節相同：`wg-quick`/`nft` 需要 root 或等同的 capabilities，且 `wg-quick` 內部可能依設定額外呼叫 `ip`/`resolvconf` 等各自有權限需求的指令，本專案**未**驗證 `CAP_NET_ADMIN`-only 是否足以涵蓋所有這些路徑。
- 一個文件化、但**未經驗證**的 `CAP_NET_ADMIN`-only 非 root 替代方案以註解形式保留在 unit 檔案中（`User=securetunnel-gateway` + `AmbientCapabilities=CAP_NET_ADMIN`），檔案內的註解明確列出啟用前必須驗證的三項條件（`wg-quick up`/`nft -f`/`ReadWritePaths` 讀寫皆需在該權限下成功），任何人要啟用前必須先在真實 Ubuntu Server 上完成驗證，而非直接切換。
- unit 檔案的其餘 hardening（`NoNewPrivileges`、`ProtectSystem=strict`、`ProtectHome`、`PrivateTmp`、`RestrictSUIDSGID`、`LockPersonality` 等）即使在 `User=root` 下仍然生效，縮小攻擊面。

## Phase 6 安全不變量重新確認（Confirmation，非重新推導）

以下不變量在 Phase 1-5 已個別文件化並有測試佐證；Phase 6（部署/備份/還原/systemd）新增的程式碼**沒有**改變任何一項，逐一重新確認如下：

- Fail-closed 行為（設定驗證失敗、套用失敗、Registry 毀損時一律拒絕而非降級放行）：不變，`gateway restore`/`gateway backup` 新增的例外路徑同樣遵循此原則（毀損封存包拒絕寫入、雜湊不符拒絕還原）。
- Default-deny / `firewallDefaultPolicy` 結構性保證：不變，Phase 6 未修改 `Firewall/` 模組。
- `allowUnlistedResources=false` 強制拒絕：不變。
- IPv6 不支援：不變，`gateway status`/`gateway backup` 均未新增 IPv6 相關路徑。
- Routed Mode 拒絕：不變。
- 不存在 allow-all fallback：不變。
- 無效設定無法被標記為 Active：不變，`config apply`/`config rollback` 邏輯本身未被 Phase 6 修改。
- 套用失敗不會回報成功：不變。

## 二十四、Phase 6A 安全不變量重新確認（`gateway serve` 常駐 daemon）

以下不變量在 Phase 1-6 已個別文件化並有測試佐證；Phase 6A 新增的常駐 daemon 執行模式（`Daemon/GatewayDaemonService.cs`）**沒有**改變任何一項，逐一重新確認如下（測試證據見 `tests/DaemonTests`）：

- **無 allow-all fallback**：不變。daemon 的四種狀態分類（Healthy/Degraded/Blocked/Failed）沒有任何一條路徑會在不確定或失敗的情況下退回「當作沒事」，見 operations-guide.md 第二十節的分類表。
- **不會自動啟用未驗證/無效的 Candidate**：不變且更嚴格。daemon 採用 Option A（見 operations-guide.md 第二十節）——偵測到 Desired 落後 Active 時只記錄 log，**從不**呼叫 `ApplyAsync`/`RollbackAsync`。`tests/DaemonTests` 的 `FakeConfigurationLifecycleService` 讓這兩個方法在被呼叫時直接拋出例外，daemon 的整套測試（含各種 Blocked/Degraded 情境）全部通過而未觸發該例外，即為「daemon 從未呼叫過」的反向證明（`NoUncontrolledAutoApply_DaemonNeverCallsApplyOrRollback` 測試）。
- **不明/無法判定的狀態維持 fail-closed（絕不悄悄回報 Healthy）**：不變。`config verify` 回報 `EffectiveStateKnown=false`、crash recovery 偵測到中斷操作、必要工具或金鑰不可用時，daemon 一律分類為 `Blocked`，不會因為「檢查跑不動」就退回一個樂觀的預設值。
- **daemon 日誌不洩漏私鑰或其他機密內容**：`tests/DaemonTests` 的 `PrivateKeyContent_NeverAppearsInDaemonLogMessages` 測試在私鑰檔案內容含有一個特徵字串的情況下執行完整啟動流程，斷言該字串從未出現在任何一則 log 訊息中——daemon 的 `DaemonStartupResult.Message` 設計上只包含檔案路徑、狀態名稱、規則產生器既有的結構化訊息，從不讀出/回傳檔案內容本身。
- **不開放任何網路管理介面**：`GatewayDaemonService` 沒有監聽任何 socket、沒有 HTTP/gRPC endpoint、不解析外部輸入指令——它唯一對外的動作是寫入 journald（透過 `ILogger`）。`gateway status` 是操作者另外執行的一次性 CLI 查詢，與正在執行的 daemon 之間沒有任何 IPC/RPC 通道；兩者各自獨立讀取磁碟上的設定/Registry/History/WireGuard 狀態。這是刻意的設計邊界，不是尚未完成的功能（見 Phase 6A 完成報告 Not Implemented：no Control Plane / Admin Portal / remote command execution）。

## 二十五、Phase 7 安全審查結果（Integration & Security Hardening）

Phase 7 對既有實作做了一次橫向安全審查（不重新設計架構，只針對具體發現的問題修正或明確記錄），逐項結果如下：

### 已發現並修正

- ✅ **Backup restore 中途失敗的誠實回報**（`Backup/BackupService.cs`）：先前若還原迴圈中某個檔案寫入中途拋出例外（例如目標路徑的父層目錄被其他程序佔用），例外會未經處理地往外傳播——呼叫端看到的是未分類的例外，而非清楚標示「哪些檔案已經被還原、哪些沒有」的結構化失敗訊息。修正後整個還原迴圈包在 `try/catch` 內，任一檔案失敗立即停止並回傳 `Success=false`，訊息明確列出**已經**還原的檔案清單與「此還原不完整，不要執行 `config apply`」的警告。見 `RestoreAsync_FailurePartwayThrough_ReportsWhichFilesWereAlreadyRestored_NotSilentlySuccess` 測試。
- ✅ **`wg` mutating 子指令的 dry-run 防禦深度**（`Services/DryRunSystemCommandExecutor.cs`）：先前 `wg` 指令整體被視為唯讀直通（因為既有呼叫端 `genkey`/`pubkey` 已經在自己的 dry-run 檢查點提前 return，從未真的呼叫到這裡），但這個保證只建立在「呼叫端沒有寫錯」之上。修正後 `wg genkey`/`wg pubkey`/`wg set` 明確被歸類為 mutating，即使未來有新的呼叫端忘記自己的 dry-run 檢查，也不會在 dry-run 模式下真的產生金鑰或修改介面。見 `DryRunSystemCommandExecutorTests.cs`。
- ✅ **`scripts/uninstall.sh` 的範圍精確防火牆清理**：見第二十節。
- ✅ **IPv6 拒絕的結構性證明補上迴歸測試**：見第十五節。

### 已審查、確認現有設計已經安全（無需修改）

- **Backup restore 的路徑穿越（path traversal）防護**：封存包內的 entry 名稱只被當作查詢**固定、受信任**的目標路徑對照表（`CollectTargetPaths`）的 key，從未被當成字面檔案系統路徑拼接使用；不在對照表中的 entry 名稱（例如刻意構造的 `../../evil.txt`）會被直接跳過並記錄警告，不會寫入任何位置。以真實封存包（含一個未知 entry 名稱）驗證：`RestoreAsync_ArchiveWithUnrecognizedEntryName_IsSkipped_NeverWrittenAsALiteralPath`。
- **Symlink 處理**：還原寫入一律走「寫到暫存檔 + `File.Move(tempPath, targetPath, overwrite: true)`」的原子寫入模式（與專案其他所有 JSON persistence 一致）。POSIX 的 `rename()`（`File.Move` 的底層實作）取代的是目的地路徑本身的目錄項，**不會**跟隨 symlink 寫入其指向的檔案——即使 `targetPath` 剛好是一個 symlink，結果也只是該 symlink 被替換成一個一般檔案，不會發生「透過 symlink 寫到非預期位置」的問題。
- **私鑰是否曾以命令列參數或一般 log 訊息外洩**：逐一檢視 `WireGuard/WireGuardService.cs`（`wg`/`wg-quick` 只帶介面名稱等非機密參數）與 `Security/KeyManagementService.cs`（私鑰一律透過 **stdin** 傳給 `wg pubkey`，從未出現在命令列引數；`wg genkey`/`wg pubkey` 呼叫皆標記 `SensitiveOutput = true`）；`Services/SystemCommandExecutor.cs`/`DryRunSystemCommandExecutor.cs` 對 `SensitiveOutput` 請求一律印出 `[arguments redacted]`，且兩者都從未記錄 stdout/stderr 的實際內容（只記錄 exit code）。結論：私鑰內容沒有任何已知路徑會進入應用程式日誌。
- **nftables table ownership 邊界**：`FirewallRuleGenerator` 產生的規則檔案從頭到尾只定義、只操作 `table inet securetunnel`，沒有任何程式路徑會列舉或刪除其他 table；`FirewallApplyOrchestrator`（Phase 4/5）的 apply 生命週期同樣只針對這一個 table。
- **Registry Consistency（Desired/Candidate/Active/Effective 一致性）**：本架構本來就不存在規格文字所設想的「一個獨立存放、可能過期的 Candidate 物件」——`config apply` 每次都是從**當下**的 Peer/Resource/Policy Registry 即時計算 Desired，不存在「舊的 Candidate 覆蓋新的 Desired」這種時序問題。`IsDesiredStaleAsync`（Phase 6）+ `ConfigurationSnapshot.ContentHash`（Phase 5）已經提供「Desired 是否已經偏離 Active」的完整偵測，且每個 apply 建立的版本都是不可變的（見第二十一/二十二節）。本階段判斷：不需要新增「revision identifier」或「source revision tracking」機制，因為 content hash 比對已經完整涵蓋規格所描述的需求；也刻意不引入分散式鎖（單機單寫入者鎖已足夠，見第二十一節）。

### 未修改、明確記錄為已知限制的項目

見下方 Known Limitations 清單中標記「（Phase 7）」的項目。

## Known Limitations（安全層面，累積清單）

- 未實作設定檔完整性簽章驗證。
- 未實作細緻的本機權限分離（單一服務帳號承擔所有操作）。
- 未實作 DoS 防護的速率限制規則模板。
- 未實作自動化加密備份。
- 私鑰安全刪除能力受限於底層檔案系統，無法一律保證。
- 目前開發環境（WSL2）無法驗證真實網路層級的安全行為（例如實際封包是否被正確 drop），僅完成邏輯與規則產生層級的驗證。
- ✅ **（Phase 3/4，已於 Phase 5 大幅改善）Registry 變更與實際系統套用之間的手動步驟**：不再需要分別執行四個指令，現在 `config apply` 一次完成；但**仍**需要操作者主動執行這一個指令（沒有自動觸發），時間窗口本身仍存在，見第八節。
- **（Phase 3/4）Peer/Resource/Policy Registry 各自無跨行程鎖定**：見第二十一節「Concurrency and Locking」對這與 `config apply` 鎖定範圍差異的說明。
- **（Phase 3）`peer status` 的即時 handshake 查詢是字串比對**：以公鑰是否出現在 `wg show` 輸出中做粗略判斷，不是結構化解析，未來如需更精確的每-Peer 連線狀態，應改為解析 `wg show <iface> dump` 的機器可讀格式。
- **（Phase 4）ICMP 不支援**、**不支援 hostname 型 Resource**、**不支援 Deny 規則**：皆為刻意設計，理由見 [firewall-model.md](firewall-model.md#九known-limitationsfirewall-層面)。
- **（Phase 4）`input` chain（Gateway 自身的存取控制）未實作**：本階段只管制「Peer 對受保護資源」的存取，不管制「誰能連到 Gateway 本身」。
- **（Phase 4/5）真實封包過濾/NAT 行為未經真實網路驗證**：WSL2 未安裝 `nftables`/`wireguard-tools`，規則「產生」與「語法驗證」的程式路徑已在真實 Linux 上執行過，但 `nft apply`/`wg-quick` 以下（含真實 TC-010~020 封包層級測試）維持 BLOCKED。
- **（Phase 6A）daemon 啟動分類刻意偏離規格文字的字面表述**：原始 Phase 6A 規格把「設定驗證失敗」歸類在 Blocked 這個大類下、卻又把 Failed 定義為任何「fatal initialization error」，兩者字面上有些微重疊。本專案選擇讓「設定驗證失敗」（configuration-validity 檢查項目為 Fail）歸類為 Blocked（daemon 持續運作並回報，不結束 process），只有「設定檔完全無法載入/解析」與「未預期例外」才是 Failed（process 結束）——理由是避免重新發明一套與既有 `IHealthCheckService` 不一致的分類邏輯，並避免設定一時錯誤就讓 systemd 進入 crash-loop。詳見 `Daemon/GatewayDaemonService.cs` 類別註解與 Phase 6A 完成報告。
- **（Phase 6A）`gateway serve` 未透過真實 `systemctl` 生命週期驗證**：daemon 本身已在真實 WSL2 Ubuntu 24.04 上以已發佈的 `linux-x64` 執行檔直接執行驗證過啟動與 crash-recovery 偵測行為，systemd unit 語法也已用 `systemd-analyze verify` 真實驗證，但兩者**未**串接測試過——也就是說，沒有透過真實 `systemctl start`/`stop`/`restart` 啟動過這個 daemon process。本開發環境無 sudo、無系統安裝目標是主因。
- **（Phase 5）Registry 變更不會自動觸發 `config apply`**：需要操作者主動執行；沒有 watch/背景程序機制，見第八節與 operations-guide.md 第十六節。
- **（Phase 5）單一寫入者鎖僅限單機**：不是跨機器/分散式鎖，見第二十一節。
- **（Phase 5）Crash Recovery 是被動偵測**：不會在偵測到中斷操作時自動修復，需操作者手動執行 `config verify` 後決定下一步，見第二十二節。
- **（Phase 5）Configuration History 無完整性簽章**：檔案本身可能被有檔案系統存取權的使用者直接編輯而不留痕跡（僅靠檔案權限 `0600` 防護），未來可評估對 history 檔案加上簽章或雜湊鏈驗證。
- **（Phase 6）備份無自動排程、非加密封存**：`gateway backup` 需操作者或 cron 主動觸發；封存格式為一般 tar+gzip（以檔案權限 `0600` 保護，非加密），需額外的傳輸/靜態加密機制自行補強。
- **（Phase 6）`CAP_NET_ADMIN`-only 非 root 運作未經驗證**：systemd unit 預設 `User=root`；文件化的低權限替代方案未在真實環境驗證，見第二十三節。
- ✅ **（Phase 6，已於 Phase 7 解決）** ~~`scripts/uninstall.sh` 不清除 nftables 規則~~ —— 見第二十節，現在會執行範圍精確（僅 `inet securetunnel` table）的清理。
- **（Phase 6）私鑰安全抹除未實作**：`uninstall.sh --purge-data` 使用一般檔案刪除，非安全抹除，見第二十節。
- ✅ **（Phase 6，已於 Phase 6A 解決）** ~~Gateway Agent 仍是一次性 CLI，非常駐 daemon~~ —— 見第二十四節，`gateway serve` 現在提供真正的常駐執行模式。
- **（Phase 7）Configuration History 無密碼學完整性驗證**：已審查（見第二十五節），判斷攻擊者若已具備能直接竄改 `config-history.json` 的本機檔案系統寫入權限，其威脅等級已等同於能直接讀取私鑰檔案（兩者權限需求相同），額外的簽章/雜湊鏈機制無法提供有意義的額外防護、卻會引入新的金鑰管理問題，因此本階段判斷為**已審查並接受的風險**，非疏漏。
- **（Phase 7）`input` chain（Gateway 自身可被連線的規則，例如限制誰能連到 WireGuard UDP port）仍未實作**：與 Phase 4 的判斷一致——這是操作者自己 OS 層防火牆（`ufw`/雲端安全群組等）的責任範圍，Gateway Agent 主動接管 `input` chain 有意外鎖死管理連線（例如 SSH）的風險，經 Phase 7 審查後判斷維持現狀比貿然接管更安全，見 [firewall-model.md](firewall-model.md#二流量方向與-chain-設計已實作)。
- **（Phase 7）真實封包層級的 Peer→Resource 授權/拒絕、NAT 行為仍未端到端驗證**：`test-lab/run-integration-tests.sh` 已撰寫並可執行（涵蓋 15 項規格檢查中的多數），但**尚未在真實 Ubuntu Server 上執行**（本開發環境缺 `wireguard-tools`/`nftables`），且其中最複雜的封包層級授權/NAT 測試（`--with-packet-flow-test`）預設關閉，需操作者在真實環境手動啟用並補上第二個 WireGuard peer network namespace，見 `test-lab/README.md`。
