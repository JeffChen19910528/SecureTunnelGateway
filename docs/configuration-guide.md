# Configuration Guide

本文件說明 SecureTunnel Gateway 的設定與資料檔：`gateway.yaml`、Peer Registry、Protected Resource Registry、Access Policy Registry（皆已實作並可實際運作）。範例位於 [`config/`](../config/)（`*.example.yaml` / `*.example.json`）。

> **Phase 2 更新**：`gateway.yaml` 的 schema 已從 Phase 1 草稿重新整理為對應 `src/SecureTunnel.GatewayAgent/Models/GatewayConfiguration.cs` 的分組方式（`wireGuard` / `network` / `routing` / `security`），並且**已經是可實際執行的程式碼**（`YamlConfigurationLoader` + `GatewayConfigurationValidator`，共 42 個 xUnit 測試涵蓋）。網路規劃數值（VPN 網段、Gateway IP、Client Pool、Listen Port）與 Phase 1 [network-topology.md](network-topology.md) 完全一致，只有欄位分組方式調整。
>
> **Phase 3 更新**：Peer 資料改為 **JSON 格式**的 Peer Registry（`peerStorePath`），**取代** Phase 1 草稿中 `config/peers.example.yaml` 描述的 YAML 格式。原因與設計見第二節「Peer Registry」。`config/peers.example.yaml` 保留作為歷史參考並已加註說明，實際格式請見 `config/peers.example.json`。
>
> **Phase 6 更新（FHS 路徑調整）**：`peerStorePath`/`resourceStorePath`/`policyStorePath`/`firewallRulesetPath`/`configurationHistoryPath`/`operationLockPath` 的**預設值**已從 `/etc/securetunnel-gateway/*` 改為 `/var/lib/securetunnel-gateway/*`——這些都是執行期間會變動的可變狀態，依 FHS（Filesystem Hierarchy Standard）不該放在存放靜態設定的 `/etc` 下。這只是**預設值**調整，非破壞性變更：既有 `gateway.yaml` 若已明確指定這些路徑則完全不受影響。新增欄位 `backupDirectory`（預設 `/var/lib/securetunnel-gateway/backups`）供 `gateway backup`/`gateway restore` 使用，見第三 C 節與 [operations-guide.md](operations-guide.md) 第十/十一節。完整部署目錄佈局見 [installation-guide.md](installation-guide.md#二-c linux-部署佈局-phase-6fhs-compliant)。
>
> **Phase 4 更新**：`protected-resources.yaml`（Phase 1 草稿）同樣被 **JSON 格式**取代，拆成兩份獨立的 Registry —— `resourceStorePath`（受保護資源，預設 `/var/lib/securetunnel-gateway/resources.json`，見上方 Phase 6 更新）與 `policyStorePath`（Peer 對 Resource 的授權，預設 `/var/lib/securetunnel-gateway/policies.json`）。拆成兩份而非一份的理由：Resource（「這個服務存在，在哪裡，開哪個 port」）與 Policy（「誰可以存取它」）是概念上不同的關注點，可以獨立變化（例如同一個 Resource 未來要授權給更多 Peer，不需要重複定義 Resource 本身）。詳見第三節。

## 一、gateway.yaml

完整範例見 [`config/gateway.example.yaml`](../config/gateway.example.yaml)。可用 `securetunnel-gateway validate --config <path>` 實際驗證（見 [operations-guide.md](operations-guide.md)）。

| 欄位 | 型別 | 必填 | 預設值 | 說明 |
|---|---|---|---|---|
| `gatewayId` | string | 否 | 空字串 | Gateway 唯一識別碼（未來 Control Plane 使用；驗證階段目前不強制非空） |
| `gatewayName` | string | 否 | 空字串 | 顯示名稱 |
| `operatingSystem` | string | 否 | `ubuntu-24.04` | 純資訊性欄位，描述目標 OS |
| `wireGuard.interfaceName` | string | 是 | `wg-securetunnel` | WireGuard 介面名稱；只允許英數字、`-`、`_`，1–15 字元（Linux IFNAMSIZ 限制），且不可與 `network.lanInterface` 相同 |
| `wireGuard.listenPort` | int (1–65535) | 是 | `51820` | WireGuard UDP listen port |
| `wireGuard.address` | string | 否 | 空字串 | Gateway 在 `wg-quick` 設定檔中的位址（CIDR），實際產生設定時取自 `network.gatewayVpnAddress` + `network.vpnCidr` 的字首長度 |
| `wireGuard.privateKeyPath` | path | 是 | — | Server private key 檔案路徑；驗證會拒絕空值、相對路徑、或位於 `/tmp`、`/var/tmp`、`/dev/shm` 等不安全位置 |
| `wireGuard.publicKeyPath` | path | 否 | 空字串 | Server public key 檔案路徑 |
| `wireGuard.saveConfig` | bool | 否 | `false` | 對應 wg-quick 的 `SaveConfig` |
| `network.vpnCidr` | CIDR | 是 | `10.250.0.0/24` | VPN 網段 |
| `network.gatewayVpnAddress` | IP | 是 | `10.250.0.1` | 需落在 `vpnCidr` 內，且不可落在 Client Pool 範圍內 |
| `network.clientAddressPoolStart` / `clientAddressPoolEnd` | IP | 是 | `10.250.0.10` / `10.250.0.200` | Client IP 配發範圍，需落在 `vpnCidr` 內，且 start 不可晚於 end |
| `network.lanInterface` | string | 是 | 空字串 | Gateway 面向受保護網路的網路介面名稱 |
| `network.protectedNetworks[]` | list | 否（建議至少 1 筆） | 空清單 | 受保護網路清單，每筆含 `name`、`cidr`；不可與 `vpnCidr` 重疊，彼此也不可重疊；空清單會產生 Warning（非 Error） |
| `routing.mode` | enum | 是 | `nat` | 僅接受 `nat`；`routed` 會被驗證明確拒絕並提示「尚未支援」；其他未知值同樣拒絕 |
| `routing.enableIpv4Forwarding` | bool | 否 | `true` | 是否需要啟用 IPv4 forwarding（實際套用由 `scripts/enable-ip-forwarding.sh` 完成，Configuration 只記錄意圖） |
| `routing.enableIpv6Forwarding` | bool | 否 | `false` | 若為 `true`，必須同時將 `routing.ipv6PolicyAcknowledged` 設為 `true`，否則驗證失敗（見 security-model.md 第十五節） |
| `routing.ipv6PolicyAcknowledged` | bool | 否 | `false` | IPv6 forwarding 的明確確認旗標 |
| `routing.natEnabled` | bool | 是（當 mode=nat 時） | `true` | `routing.mode = "nat"` 時必須為 `true`，否則視為設定矛盾 |
| `security.firewallDefaultPolicy` | enum | 是 | `deny` | 固定為 `deny`，驗證階段拒絕任何其他值（大小寫不敏感比對） |
| `security.allowUnlistedResources` | bool | 是 | `false` | 固定為 `false`，驗證階段拒絕 `true`（禁止 allow-all） |
| `security.requirePeerValidation` | bool | 否 | `true` | 是否要求 Peer 驗證（Phase 3 起實際生效） |
| `security.failClosed` | bool | 是 | `true` | 固定為 `true`，驗證階段拒絕 `false` |
| `logging.level` | enum | 否 | `Information` | 日誌等級 |
| `logging.auditLogPath` / `applicationLogPath` | path | 否 | `/var/log/securetunnel-gateway/audit.log` / `gateway.log` | 保留欄位，目前未使用——Phase 6 已定案日誌全面委由 journald（見 [operations-guide.md](operations-guide.md) 第十七節），不會再接上自訂檔案 log sink |
| `healthCheck.intervalSeconds` | int | 否 | `30` | Health check 週期（目前 CLI 為單次執行，週期性排程屬未來工作） |
| `healthCheck.diskSpaceWarningPercent` | int | 否 | `85` | 磁碟使用率超過此值視為 Degraded（尚未實作對應檢查項目） |
| `healthCheck.timeSyncWarningSeconds` | int | 否 | `10` | 系統時間偏移超過此秒數視為 Degraded（尚未實作對應檢查項目） |
| `controlPlane.enabled` | bool | 否 | `false` | 未來 Control Plane 整合開關，本階段不生效 |
| `controlPlane.endpoint` / `credentialReference` | string | 否 | 空 | 保留欄位 |
| `peerStorePath` | path | 否 | `/var/lib/securetunnel-gateway/peers.json` | Peer Registry 檔案路徑（Phase 3，見第二節；Phase 6 起預設路徑改為 `/var/lib`，見上方說明） |
| `resourceStorePath` | path | 否 | `/var/lib/securetunnel-gateway/resources.json` | Protected Resource Registry 檔案路徑（Phase 4，見第三節） |
| `policyStorePath` | path | 否 | `/var/lib/securetunnel-gateway/policies.json` | Access Policy Registry 檔案路徑（Phase 4，見第三節） |
| `firewallRulesetPath` | path | 否 | `/var/lib/securetunnel-gateway/ruleset.nft` | 產生的 nftables ruleset 檔案路徑（Phase 4） |
| `configurationHistoryPath` | path | 否 | `/var/lib/securetunnel-gateway/config-history.json` | Configuration History 檔案路徑（Phase 5，見第三 B 節） |
| `operationLockPath` | path | 否 | `/var/lib/securetunnel-gateway/gateway.lock` | 單一寫入者鎖檔案路徑（Phase 5） |
| `backupDirectory` | path | 否 | `/var/lib/securetunnel-gateway/backups` | `gateway backup` 預設輸出目錄（Phase 6，見第三 C 節） |
| `wireGuard.endpointHost` | string \| null | 否 | `null` | Gateway 對外公開的主機名稱/IP，供 Client 設定範本使用；未設定時範本會顯示 `<GATEWAY_PUBLIC_ENDPOINT>` 佔位字串 |

未在 YAML 中出現的欄位一律套用上表「預設值」欄（由 C# 模型的屬性初始值提供，非由 YAML 檔案指定），這點由 `tests/ConfigurationTests/YamlConfigurationLoaderTests.Load_MissingSections_FallsBackToModelDefaults` 驗證。

## 二、Peer Registry（`peerStorePath`，JSON 格式）

### 2.1 為何是 JSON，而不是 Phase 1 草稿中的 `peers.yaml`

Phase 1 的 `config/peers.example.yaml` 描述了一份 YAML 格式的 Peer 清單設計。Phase 3 實作時改採 **JSON**，原因：

- 目前是單一 Gateway、單一操作者的 MVP，不需要 YAML 的人工編輯友善性（Peer 由 CLI 管理，不預期被手動編輯）。
- `System.Text.Json` 搭配 C# 的 `required` 屬性，讀取時能免費獲得「欄位缺漏即視為損毀」的驗證（見 2.4 節），比自行為 YAML 寫等價驗證邏輯更可靠。
- 單一 JSON 陣列檔案最利於整份備份/還原（`cp`/`tar` 即可），也最容易做原子寫入（見 2.3 節）。

`config/peers.example.yaml` 保留在儲存庫中作為 Phase 1 歷史設計參考，檔案開頭已加註「已被 JSON 格式取代」的說明；實際格式範例見 [`config/peers.example.json`](../config/peers.example.json)。若未來需要多 Gateway 或高並發寫入，SQLite 是最自然的下一步（見 2.5 節 Known Limitations），但本階段判斷 JSON 已足夠。

### 2.2 Peer 欄位

對應 `src/SecureTunnel.GatewayAgent/Models/Peer.cs`：

| 欄位 | 型別 | 必填 | 說明 |
|---|---|---|---|
| `peerId` | string | 是 | 唯一識別碼，格式 `peer-<12 hex>`，由 Gateway 自動產生 |
| `name` | string | 是 | 顯示名稱，非空、≤100 字元、不含控制字元 |
| `description` | string \| null | 否 | 說明 |
| `publicKey` | string | 是 | WireGuard 公鑰（base64，解碼後需為 32 bytes）。**絕不是私鑰**，見第三節 |
| `assignedVpnIp` | IP | 是 | 落在 `network.clientAddressPoolStart`–`clientAddressPoolEnd` 內，且不與其他仍「佔用」中的 Peer 重複（見 2.6 節） |
| `status` | enum | 是 | `Pending` \| `Active` \| `Disabled` \| `Revoked` \| `Removed`，語意見 [security-model.md](security-model.md#peer-生命週期狀態) |
| `createdAtUtc` / `updatedAtUtc` | ISO 8601 datetime (UTC) | 是 | 建立/最後更新時間 |
| `lastHandshakeAtUtc` | ISO 8601 datetime \| null | 否 | 目前未由背景程序自動更新；`peer status` 指令會即時查詢 `wg show` 做最佳努力交叉比對，但不會回寫到此欄位（屬 Known Limitations） |
| `endpoint` | string \| null | 否 | 目前未使用（保留欄位，供未來記錄最近觀測到的 Client 來源） |
| `allowedIps` | list\<CIDR\> | 是 | 新增時預設為 `[assignedVpnIp/32]` |
| `persistentKeepaliveSeconds` | int \| null | 否 | 未設定則產生的 `[Peer]` 區塊不含 `PersistentKeepalive` 行 |

**沒有 `privateKey` 欄位** — `Peer` 這個 C# 類別在設計上完全沒有可以存放私鑰的屬性，因此「不小心序列化出私鑰」在結構上是不可能的，而不僅是靠程式邏輯避免（`tests/PeerTests/JsonFilePeerRepositoryTests.SaveAllAsync_NeverWritesAPrivateKeyField` 驗證輸出的 JSON 不含 `PrivateKey` 字樣）。

### 2.3 Persistence 設計：原子寫入與失敗處理

- **原子寫入**：`SaveAllAsync` 先寫入同目錄下的暫存檔（`<path>.tmp-<guid>`），成功後以 `File.Move(overwrite: true)` 原子覆蓋目標檔案；任何寫入中斷只會留下暫存檔，`peers.json` 本身要嘛是舊內容、要嘛是新內容，不會出現半寫入的損毀狀態。
- **讀取驗證（fail-closed）**：`LoadAllAsync` 會拒絕以下情況並丟出 `PeerRegistryCorruptException`（呼叫端會將其轉換成清楚的 CLI 錯誤訊息，**不會**靜默視為空清單）：
  - 檔案存在但內容為空白
  - JSON 格式錯誤
  - 任何記錄缺少必填欄位
  - 重複的 `peerId`
  - 重複的 `publicKey`
- **檔案不存在** 才會被視為「全新的空 Registry」，這是唯一被允許的「空清單」情況。
- **檔案權限**：寫入後在 Linux 上設為 `0600`（owner-only）；Windows 開發機無法設定 Unix 權限，僅記錄警告。
- **並發**：本階段**沒有跨行程鎖定機制**。兩個同時執行的 `securetunnel-gateway peer ...` 呼叫可能互相覆蓋（後寫入者勝出）。這對目前「單一操作者透過 CLI 操作」的 MVP 場景是可接受的取捨，已記錄於 Known Limitations；未來若要支援多操作者/自動化同時寫入，需要引入檔案鎖或改用 SQLite 等具備交易能力的儲存。

### 2.4 備份與復原

Peer Registry 是單一檔案，備份/復原方式與 [operations-guide.md](operations-guide.md#十備份設定) 描述的整體備份流程相同（`tar` 該檔案即可）。復原時：直接以備份檔案取代現有 `peers.json` 並重新啟動 Gateway Agent 的操作即可；由於載入時有完整驗證（見 2.3 節），還原一份損毀的備份會被 Gateway 立即偵測並拒絕載入，而不是悄悄接受壞資料。

### 2.5 Known Limitations（Persistence）

- 無跨行程鎖定（見 2.3 節「並發」）。
- 無自動備份排程。
- `lastHandshakeAtUtc` 不會被背景程序回填（`peer status` 只做即時查詢，不落地）。
- 單一 JSON 檔案，未分片；Peer 數量極大時（遠超一般小型企業規模）讀寫效能未經測試。

### 2.6 VPN IP 配發

見 `src/SecureTunnel.GatewayAgent/Peers/Ipv4VpnIpAllocator.cs`，規則摘要：

- 只從 `network.clientAddressPoolStart`–`clientAddressPoolEnd` 範圍內配發。
- 不會配發 Gateway 自己的 VPN IP，也不會配發 VPN CIDR 的網路位址或廣播位址。
- 「佔用中」的判定：狀態為 `Pending`、`Active`、`Disabled` 的 Peer 視為佔用其 IP（`Disabled` 仍保留 IP，方便之後 `enable` 回同一個 IP）。
- `Revoked`、`Removed` 的 Peer **釋放**其 IP，可被配發給其他新 Peer（該 Peer 的公鑰仍被永久封鎖重用，見第三節與 security-model.md）。
- 支援自動配發（取範圍內第一個可用位址）與明確指定（`--vpn-ip`，需驗證在範圍內、未被佔用）。
- 對應 CLI：`securetunnel-gateway peer allocate-ip`（唯讀預覽，不會建立任何 Peer 紀錄）。

### 2.7 三種「設定」的區別（重要）

Phase 3 會產生/處理三種不同的 WireGuard 相關設定，容易混淆，務必區分：

| 名稱 | 內容 | 含私鑰？ | 產生方式 |
|---|---|---|---|
| **Server peer configuration** | Gateway 自己的 `wg-quick` 設定檔中，每個已註冊 Active Peer 對應的 `[Peer]` 區塊（公鑰 + AllowedIPs） | 否（只有公鑰） | `securetunnel-gateway config generate`（見 docs/installation-guide.md），來源是 `WireGuardConfigGenerator` |
| **Client configuration TEMPLATE** | 給 Client 使用者參考的 `.conf` 檔案草稿，`PrivateKey` 欄位是明確標示的佔位字串 `<INSERT_CLIENT_PRIVATE_KEY_HERE>` | **否**，Gateway 從未產生或持有 Client 私鑰 | `securetunnel-gateway peer config`，來源是 `ClientConfigTemplateGenerator` |
| **Complete client configuration** | Client 自行（或由操作者在獨立、受控流程中）填入真實私鑰後，才成為「可直接使用」的設定 | 是，但**只存在於 Client 端**，Gateway 完全不參與、不接觸、不儲存這個版本 | 不在本專案的職責範圍內 |

`peer config` 的輸出**永遠**是 TEMPLATE（`IsCompleteUsableConfig` 恆為 `false`），這是刻意的設計，不是尚未完成的功能 — 見第三節與 [security-model.md](security-model.md)。

**安全提醒**：本檔案只存放 Client 公鑰，絕不存放私鑰。

## 三、Resource Registry 與 Policy Registry（JSON 格式，✅ Phase 4 已實作）

`config/protected-resources.example.yaml`（Phase 1 草稿）已被取代，保留作歷史參考；實際格式範例見 [`config/resources.example.json`](../config/resources.example.json) 與 [`config/policies.example.json`](../config/policies.example.json)。持久化設計（原子寫入、fail-closed 讀取、重複偵測）與 [第二節 Peer Registry](#二peer-registryperstorepathjson-格式) 完全相同的模式，此處不重複展開，只列欄位定義。

### 3.1 Resource 欄位

對應 `src/SecureTunnel.GatewayAgent/Models/ProtectedResource.cs`：

| 欄位 | 型別 | 必填 | 說明 |
|---|---|---|---|
| `resourceId` | string | 是 | 唯一識別碼，自動產生 |
| `name` | string | 是 | 顯示名稱，非空、≤100 字元 |
| `description` | string \| null | 否 | 說明 |
| `destination` | string | 是 | **明確 IPv4 位址或 CIDR**，不支援 hostname；字首長度 `/8` 以下（含 `0.0.0.0/0`）一律拒絕 |
| `protocol` | enum | 是 | `Tcp` \| `Udp`（不支援 `icmp`，見 [firewall-model.md](firewall-model.md#九known-limitationsfirewall-層面)） |
| `port` | int | 是 | 1–65535 |
| `portEnd` | int \| null | 否 | 若設定，需 ≥ `port`，代表 port range |
| `enabled` | bool | 是 | 停用時排除在 effective rule 之外 |
| `createdAtUtc` / `updatedAtUtc` | datetime | 是 | UTC |

### 3.2 Policy 欄位

對應 `src/SecureTunnel.GatewayAgent/Models/AccessPolicy.cs`：

| 欄位 | 型別 | 必填 | 說明 |
|---|---|---|---|
| `ruleId` | string | 是 | 唯一識別碼，自動產生 |
| `peerId` | string | 是 | 需引用已存在的 Peer（見 [firewall-model.md](firewall-model.md#五access-policy-模型已實作allow-only--implicit-deny) 的 Error/Warning 分層規則） |
| `resourceId` | string | 是 | 需引用已存在的 Resource |
| `enabled` | bool | 是 | — |
| `description` | string \| null | 否 | — |
| `createdAtUtc` / `updatedAtUtc` | datetime | 是 | UTC |

**沒有 `action`（Allow/Deny）欄位，也沒有 `priority`** — Allow-only + implicit deny 模型，理由見 [firewall-model.md](firewall-model.md#五access-policy-模型已實作allow-only--implicit-deny)。

## 三 B、Configuration History（`configurationHistoryPath`，JSON 格式，✅ Phase 5 已實作）

`config apply`／`config rollback` 每次執行都會在這個檔案中新增一筆版本紀錄（預設 `/var/lib/securetunnel-gateway/config-history.json`，Phase 6 起預設路徑改為 `/var/lib`，見文首說明）。完整生命週期設計見 [architecture.md](architecture.md#六configuration-生命週期已實作lifecycleconfigurationlifecycleservice)。

### 3B.1 欄位

對應 `src/SecureTunnel.GatewayAgent/Models/ConfigurationSnapshot.cs`（陣列包在 `ConfigurationHistory` 物件內，額外含 `activeVersion`／`lastKnownGoodVersion` 兩個指標欄位）：

| 欄位 | 型別 | 說明 |
|---|---|---|
| `version` | int | 唯一遞增版本號 |
| `createdAtUtc` | datetime | UTC |
| `sourceReason` | string | 人類可讀的產生原因，例如 `"manual apply via CLI"`、`"rollback to v4"` |
| `contentHash` | string | SHA-256（`peers`/`resources`/`policies` 的正規化序列化結果），不含任何私鑰 |
| `state` | enum | 見 `ConfigurationState`（`CandidateGenerated`/`Validated`/`ApplyPending`/`Applying`/`Applied`/`Verified`/`Active`/`ValidationFailed`/`ApplyFailed`/`VerificationFailed`/`RollbackPending`/`RollbackSucceeded`/`RollbackFailed`/`EffectiveStateUnknown`） |
| `peers`/`resources`/`policies` | array | **不可變快照**——該版本產生當下的完整資料副本，不是參照，rollback 時直接重用，不重讀當時的即時 Registry |
| `effectiveWireGuardPeerCount`/`effectiveFirewallRuleCount` | int | 這個版本會產生的 `[Peer]` 區塊數／nftables 有效規則數 |
| `failureReason` | string \| null | 失敗時的說明 |
| `wireGuardApplied`/`firewallApplied` | bool | 兩個 leg 各自是否成功（部分失敗時用來判斷是哪一邊失敗） |
| `rollbackTargetVersion` | int \| null | 若此版本是 rollback 的結果，記錄目標版本 |
| `previousActiveVersion` | int \| null | 產生此版本時，前一個 Active 版本是誰（成功後會變成 `lastKnownGoodVersion`） |

**沒有私鑰欄位** — 與 Peer Registry 相同的結構性保證（型別上就不存在可以放私鑰的欄位），`tests/LifecycleTests/JsonFileConfigurationHistoryRepositoryTests.SaveAllAsync_NeverWritesAPrivateKeyField` 驗證輸出不含 `PrivateKey` 字樣。

### 3B.2 保留政策（Retention）

History 檔案會在版本數超過 30 筆時自動裁剪，但**永遠保留** `activeVersion` 與 `lastKnownGoodVersion` 指到的版本，不論它們是否落在「最近 30 筆」範圍內（`Lifecycle/ConfigurationLifecycleService.Prune`）。這確保「最後一份已知良好設定」永遠不會被靜默刪除，符合原始需求「Do not silently delete the only recoverable configuration」。

### 3B.3 並發控制

`config apply`／`config rollback` 在真正開始套用前會取得單一寫入者鎖（`operationLockPath`，預設 `/var/lib/securetunnel-gateway/gateway.lock`），機制與限制見 [architecture.md](architecture.md#六configuration-生命週期已實作lifecycleconfigurationlifecycleservice)「單一寫入者鎖」段落。鎖定逾時預設 30 秒（`ConfigurationLifecycleService` 建構時可覆寫，CLI 目前使用預設值）。

## 三 C、Backup Directory（`backupDirectory`，✅ Phase 6 已實作）

`backupDirectory`（預設 `/var/lib/securetunnel-gateway/backups`）是 `gateway backup create` 未指定 `--output` 時的預設輸出目錄，也是 `gateway backup list` 掃描備份封存包的位置。此欄位只是一個目錄路徑，本身不是 Registry 檔案；備份封存包（tar+gzip，含 `manifest.json`）的內容格式與運作方式見 [operations-guide.md](operations-guide.md) 第十/十一節、[security-model.md](security-model.md) 第十七節。

## 四、設定驗證錯誤範例

以下為 `GatewayConfigurationValidator`（`src/SecureTunnel.GatewayAgent/Validation/GatewayConfigurationValidator.cs`）**實際會產生**的錯誤訊息，可用 `securetunnel-gateway validate --config <path>` 重現（`tests/ValidationTests` 共 42 個測試覆蓋這些規則）：

```
[ERROR] network.vpnCidr: network.vpnCidr (10.20.0.0/24) overlaps with protected network 'lab-protected-net' (10.20.0.0/24). Fix: Choose non-overlapping CIDR ranges for the VPN network and protected networks.

[ERROR] network.gatewayVpnAddress: Gateway VPN address 10.250.0.50 falls inside the client address pool (10.250.0.10-10.250.0.200). Fix: Choose a gateway address outside the pool range, or shrink the pool.

[ERROR] routing.mode: routing.mode = "routed" is not supported in this release. Fix: Use routing.mode = "nat" (see docs/network-topology.md, Routed Mode is a future enhancement).

[ERROR] security.firewallDefaultPolicy: security.firewallDefaultPolicy is 'allow', but only 'deny' is allowed. Fix: Set security.firewallDefaultPolicy to "deny". SecureTunnel Gateway does not support a default-allow policy.

[ERROR] security.failClosed: security.failClosed is false. SecureTunnel Gateway requires fail-closed behavior. Fix: Set security.failClosed to true.

[ERROR] wireGuard.privateKeyPath: '/tmp/server.key' is inside '/tmp/', which is a world-writable/temporary location and unsafe for a private key. Fix: Store the private key under a directory such as /etc/securetunnel-gateway/keys with 0700/0600 permissions.
```

以下為 `ResourceValidator` / `PolicyValidator`（`src/SecureTunnel.GatewayAgent/Firewall/`）**實際會產生**的錯誤訊息，可用 `securetunnel-gateway resource add` / `policy add` 重現（`tests/FirewallTests` 共 93 個測試覆蓋）：

```
[ERROR] destination: '0.0.0.0/0' is far too broad for a single resource (prefix /0). This looks like an attempt at unrestricted/LAN-wide access, which SecureTunnel Gateway refuses to generate. Fix: Define one resource per specific host or a narrow subnet (e.g. /28 or smaller), never a broad network.

[ERROR] destination: '2001:db8::1' looks like an IPv6 address. IPv6 resources are not supported in this release.

[ERROR] portEnd: portEnd (8000) must be >= port (8080).

[ERROR] peerId: Unknown peer 'peer-does-not-exist'. A policy must reference a peer that exists in the Peer Registry.

[ERROR] resourceId: A policy already grants peer 'peer-xxx' access to resource 'resource-yyy'. Duplicate peer-to-resource permissions are not allowed.
```

以及 `PolicyValidator` 產生的 **Warning**（不阻擋新增，但提示規則目前不會生效，見 [firewall-model.md](firewall-model.md#五access-policy-模型已實作allow-only--implicit-deny)）：

```
[WARN] peerId: Peer 'peer-xxx' is currently Disabled; this policy will produce no effective access until the peer is Active.
```

## 五、必填欄位一覽（快速檢查表）

`gateway.yaml`（Phase 2 已實作並有測試覆蓋）：
- `wireGuard.interfaceName` / `wireGuard.listenPort` / `wireGuard.privateKeyPath`
- `network.vpnCidr` / `gatewayVpnAddress` / `clientAddressPoolStart` / `clientAddressPoolEnd` / `lanInterface`
- `routing.mode`（且 `mode=nat` 時 `routing.natEnabled` 必須為 `true`）
- `security.firewallDefaultPolicy`（必須為 `deny`）/ `security.failClosed`（必須為 `true`）/ `security.allowUnlistedResources`（必須為 `false`）

Peer Registry（Phase 3 已實作）：
- 每個 Peer：`peerId` / `name` / `publicKey` / `assignedVpnIp` / `status` / `createdAtUtc` / `updatedAtUtc`

Resource / Policy Registry（Phase 4 已實作）：
- 每個 Resource：`resourceId` / `name` / `destination` / `protocol` / `port` / `enabled`
- 每個 Policy：`ruleId` / `peerId` / `resourceId` / `enabled`

## 六、安全限制摘要

- `wireGuard.privateKeyPath` 指向的檔案不得被提交到版本控制（見 [`.gitignore`](../.gitignore)），且不可位於 `/tmp`、`/var/tmp`、`/dev/shm`（驗證階段強制拒絕）。
- `security.firewallDefaultPolicy` 不可設為非 `deny` 的值（驗證階段強制拒絕）。
- `security.failClosed` 不可為 `false`（驗證階段強制拒絕）。
- `security.allowUnlistedResources` 不可為 `true`（驗證階段強制拒絕）。
- `routing.mode` 本階段只接受 `nat`；`routed` 會被明確拒絕並說明尚未支援，而非產生不明確的解析錯誤。
- `routing.enableIpv6Forwarding = true` 必須同時明確設定 `routing.ipv6PolicyAcknowledged = true`，避免 IPv6 路徑意外開通。
- Resource 的 `destination` 不可為字首長度 `/8` 或更寬的 CIDR（含 `0.0.0.0/0`），✅ Phase 4 已實作並強制拒絕。
- Policy 不可引用不存在的 Peer/Resource（Unknown Peer/Resource 一律拒絕，✅ Phase 4 已實作）。

## 七、與 Known Limitations 的關聯

`gateway.yaml` 的 parser/validator（Phase 2）、Peer Registry（Phase 3）、Resource/Policy Registry 與 nftables 規則產生（Phase 4）、Configuration History 與版本化 Apply/Rollback（Phase 5）、部署/systemd/Backup-Restore（Phase 6）、常駐 daemon 模式（Phase 6A，見下）皆已實作完成，全專案共 **363 個 xUnit 測試**（跨 ConfigurationTests / ValidationTests / WireGuardTests / PeerTests / FirewallTests / LifecycleTests / IntegrationTests / DeploymentTests / DaemonTests）驗證，可在 `dotnet test` 中重現。尚未完成的部分：

- `logging.*` 與 `healthCheck.*` 欄位目前只被解析與驗證存在性，尚未接上實際的檔案 log sink 或排程健康檢查（見 docs/troubleshooting.md）。日誌本身已於 Phase 6 定案全面委由 journald。
- 單一寫入者鎖僅保證單一 Gateway 主機內互斥，非跨機器/分散式鎖（見 [architecture.md](architecture.md#六configuration-生命週期已實作lifecycleconfigurationlifecycleservice)）。
- ~~Crash Recovery 是被動偵測，不是常駐 daemon 的自動修復~~ — **Phase 6A 更新**：`gateway serve`（`Daemon/GatewayDaemonService.cs`）現在是真正的常駐執行模式，開機（systemd `ExecStart`）與之後每個檢查週期（`--interval-seconds`，預設 60 秒）都會重新執行 Crash Recovery 偵測與 Desired/Active/Effective 狀態評估，並把結果寫入 journald；`gateway status` 仍然是操作者隨時可另外執行的一次性查詢指令，兩者各自獨立讀取同一份磁碟狀態，daemon 本身不對外開放任何查詢/管理介面。
- Peer/Resource/Policy 狀態變更後，仍需要操作者手動執行 `config apply` 才會反映到實際系統 —— 這是 Phase 6A 明確選擇的行為（Option A：daemon 只在偵測到 Desired 落後 Active 時記錄 log，從不自動呼叫 `ApplyAsync`/`RollbackAsync`），理由是避免任何形式的無人值守自動生效路徑。
