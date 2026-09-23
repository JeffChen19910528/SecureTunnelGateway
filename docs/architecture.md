# Architecture

## 一、範圍

本文件描述 **SecureTunnel Gateway**（本階段唯一開發標的）的架構。不涵蓋 Windows/Linux Client、完整 Admin Portal、完整 Control Plane 後端 — 這些是未來階段，本文件第十六節說明未來如何整合。

## 二、設計目標

1. 只有通過 WireGuard 驗證且被 Gateway 授權的 Peer，才能存取受保護資源。
2. 未連線 VPN、VPN 斷線、或 Peer 被停用，立即無法存取受保護資源。
3. 存取控制由 Linux Firewall（nftables）在封包層面強制執行，不依賴 Client 端行為。
4. 設定變更具備驗證、原子套用（atomic apply）與回滾（rollback）能力，失敗不得導致全部放行。
5. 不自行實作加密協定，VPN 加密完全交給 WireGuard。
6. 架構上區分 Data Plane 與 Management（Gateway Agent）Plane，兩者可獨立演進。

## 三、兩大平面：Data Plane 與 Management Plane

### 3.1 Data Plane（實際封包轉送）

負責真正的網路封包處理，全部執行在 **Linux Host**（非一般 Docker Container）：

- **WireGuard**：VPN 加密通道、Peer handshake、金鑰驗證。
- **Linux Routing / IP Forwarding**：決定封包如何在 VPN 介面與受保護網路介面之間轉送。
- **nftables**：Forward chain 上的 allow-list + default deny，實際決定哪個 VPN IP 可以連到哪個受保護資源的哪個 port。
- **受保護資源本身**（Website / API / TCP Service）：不屬於本專案開發範圍，只是 Gateway 保護的對象。

Data Plane 的正確性直接等於「這個 VPN Gateway 安不安全」，因此：

- 不放進一般（非 host network、非 NET_ADMIN）的 Docker Container。
- 所有規則變更都必須經過 Management Plane 的驗證與版本控制，不允許被繞過直接手動改動後失去追蹤。

### 3.2 Management Plane（SecureTunnel Gateway Agent）

負責「決定 Data Plane 應該長什麼樣子」，以 **systemd service** 執行的 .NET 10 應用程式：

- 設定讀取、解析、驗證（`Configuration` / `Validation`）
- WireGuard 設定產生與套用（`WireGuard`）
- nftables 規則產生與套用（`Firewall`）
- Routing / IP forwarding 檢查與設定（`Routing`）
- Peer 生命週期管理（新增／停用／移除）
- Configuration 版本控制、candidate/active 分離、rollback
- Health check、diagnostics（`Health`）
- 結構化 logging、audit（`Logging`）
- 未來與 Control Plane 溝通的介面（`Security` 中預留憑證/認證邏輯）

Gateway Agent **不是** VPN 本身，它是操控 WireGuard 與 nftables 的「駕駛座」。移除 Gateway Agent，既有的 WireGuard/nftables 設定仍會持續運作（fail-safe：管理層掛掉不等於資料層開洞）。

```
┌─────────────────────────────────────────────────────────────────┐
│                     Management Plane                            │
│   SecureTunnel Gateway Agent (.NET 10, systemd)                 │
│                                                                   │
│   Config Loader → Validator → Candidate Generator                │
│         │                          │                             │
│         │                          ▼                             │
│         │                 Atomic Apply Engine ── Rollback        │
│         │                          │                             │
│         ▼                          ▼                             │
│     Peer Store               Audit / Structured Log              │
└─────────────────────────────────┬─────────────────────────────────┘
                                    │ 產生設定、下達 apply 指令
                                    ▼
┌─────────────────────────────────────────────────────────────────┐
│                        Data Plane (Linux Host)                   │
│                                                                   │
│   wg-securetunnel (WireGuard) ──► nftables Forward Chain         │
│                                        │  allow-list + default deny│
│                                        ▼                          │
│                              Protected Resources                 │
└─────────────────────────────────────────────────────────────────┘
```

## 四、流量路徑

```
VPN Client
   │ WireGuard (UDP 51820, 加密)
   ▼
wg-securetunnel interface (Gateway VPN IP: 10.250.0.1)
   │ 明文（VPN 內部）
   ▼
nftables forward chain
   ├─ 來源是否為已知 VPN 子網（10.250.0.0/24）？否 → drop
   ├─ 目的地是否為已列出的受保護資源？否 → drop
   ├─ Peer 是否被允許存取此資源？否 → drop
   └─ 允許 → 轉送（NAT Mode 下先做 SNAT，見 network-topology.md）
   ▼
Protected Resource (例如 10.20.0.10:443)
```

未連 VPN 的來源封包不會出現在 `wg-securetunnel` 介面上，因此天生就無法進入這條路徑（fail-closed 的第一層）；即使有人能把封包送進 forward chain，也必须通过 allow-list 才能到達受保護資源（fail-closed 的第二層）。

## 五、Routing Mode：採用 NAT Mode

本專案 MVP 與正式環境**採用 NAT Mode**，理由與限制詳見 [network-topology.md](network-topology.md#nat-mode-採用理由與限制)。摘要：

- 選擇原因：降低受保護資源端的回程路由設定需求、適合小型企業初期部署、較容易整合既有內部網路。
- 代價：受保護資源端看到的來源 IP 是 Gateway 的位址而非 VPN Client 的真實 VPN IP，來源可觀測性較低 — 因此 **Peer 層級的存取決策必須在 Gateway 的 nftables 完成**，不可依賴受保護資源自己用來源 IP 做二次過濾（它看到的來源 IP 沒有意義）。
- 架構上保留 Routed Mode 的擴充空間：`RoutingMode` 是設定檔欄位而非寫死的程式邏輯，未來新增 Routed Mode 只需新增一種規則產生策略，不需重構核心流程。

## 六、Configuration 生命週期（✅ Phase 5 已實作：`Lifecycle/ConfigurationLifecycleService`）

```
Desired（即時讀取 Peer/Resource/Policy Registry）
   ↓
CandidateGenerated（不可變快照：Peer/Resource/Policy 資料 + 內容雜湊）
   ↓
Validated（GatewayConfigurationValidator + WireGuard/Firewall 產生器各自的驗證都通過）
   ↓ [--dry-run 在此停止，不寫入任何檔案]
ApplyPending（取得單一寫入者鎖，寫入 history，之後才開始碰系統 —— crash recovery 的關鍵檢查點）
   ↓
Applying（再次寫入 history，標記「即將開始變更系統」）
   ↓
   ├─ WireGuard 套用（寫入設定檔 + wg-quick restart，備份前一份設定，失敗時嘗試還原）
   │     └─ 失敗 → ApplyFailed，Active 不變，nftables 完全不會被觸碰
   ↓
   ├─ nftables 套用（重用 Firewall/FirewallApplyOrchestrator 的完整 generate→語法驗證→apply→verify）
   │     └─ 失敗 → EffectiveStateUnknown（WireGuard 已套用但 nftables 沒有，見下方「部分失敗」）
   ↓
Applied（兩個 leg 都回報成功）
   ↓
Verify（實際查詢 `wg show` 介面狀態 + `nft list table` 是否存在）
   │     └─ 驗證不到 → VerificationFailed 或 EffectiveStateUnknown，絕不假裝 Active
   ↓
Verified → Active（更新 history.ActiveVersion；前一個 Active 版本變成 LastKnownGoodVersion）
```

失敗狀態集合：`ValidationFailed`／`ApplyFailed`／`VerificationFailed`／`RollbackPending`／`RollbackSucceeded`／`RollbackFailed`／`EffectiveStateUnknown`（完整定義見 `Models/ConfigurationState.cs`）。**狀態永遠不會被壓縮成單一布林值**——每個版本在 Configuration History 中留下完整的狀態轉換紀錄，即使驗證失敗的候選版本也會被記錄（供稽核），只是不會變成 Active。

**部分失敗的處理原則**（WireGuard 與 nftables 是兩個獨立的 Data Plane 元件，套用不是原子的單一系統呼叫）：
- WireGuard 失敗 → nftables 完全不會被觸碰，`Applying` 狀態直接轉為 `ApplyFailed`。
- WireGuard 成功、nftables 失敗 → 標記 `EffectiveStateUnknown`。這聽起來令人擔心，但實際上是**安全的**：`FirewallApplyOrchestrator` 在失敗時已經把 nftables 規則還原成前一份已知良好版本（見 [firewall-model.md](firewall-model.md) 第六節），所以有效防火牆規則仍然是「舊的」default-deny 規則集——新的 WireGuard Peer 即使能完成 handshake，也不會出現在舊規則集裡，因此**不會**意外取得資源存取權，只是功能上「還沒生效」而已。`EffectiveStateUnknown` 這個標籤是刻意保守的：即使我們論證了它是安全的，仍然不敢自稱 `Active`，因為兩個元件的狀態不再互相對應。

**Candidate 快照設計**（`Models/ConfigurationSnapshot.cs`）：每個版本內嵌當時的 Peer/Resource/Policy 資料完整副本（不是參照），這樣 rollback 時可以精確重現「那個時間點」的設定，不受 Registry 之後被修改影響（見第八節）。快照**不含**任何私鑰內容——WireGuard 私鑰在套用當下才從磁碟即時讀取，從未進入快照或 history 檔案。

**版本化**：每個版本有唯一遞增的 `Version` 編號、`ContentHash`（SHA-256，見 `Lifecycle/SnapshotHasher.cs`）、`CreatedAtUtc`、`SourceReason`。History 檔案永遠保留 `ActiveVersion` 與 `LastKnownGoodVersion`（即使做版本數量的保留/裁剪也不會刪除這兩個）。

**單一寫入者鎖**（`Lifecycle/FileOperationLock.cs`）：以獨佔建立的鎖檔案實作（`FileMode.CreateNew` + `FileShare.None`），在 Linux 與 Windows 開發機上行為一致；偵測到鎖檔案存在但擁有者行程已不存在、或鎖案齡超過 10 分鐘時，視為過期鎖並安全回收（處理 crash 場景）。**這只保證單一 Gateway 主機內的互斥，不是跨機器/分散式鎖**。

**Rollback**（`ConfigurationLifecycleService.RollbackAsync`）：使用目標版本自身內嵌的快照資料重新走一次套用流程，**不會**讀取當前（可能已經變更過）的 Registry；只允許回滾到「曾經成功」（`Active`/`Verified`/`RollbackSucceeded`）的版本；回滾本身會建立一個**新**版本號（永不覆寫歷史紀錄），標記為 `RollbackSucceeded`。

**Crash Recovery**：目前是 CLI（非常駐 daemon），因此「啟動時檢查」實作為 `DetectIncompleteOperationAsync`，會在 `config status`／health check 中檢查 history 最後一筆紀錄是否卡在 `ApplyPending`/`Applying`/`RollbackPending`（代表行程曾被中斷），若是則明確提示、不假裝一切正常，要求操作者執行 `config verify` 確認實際系統狀態。

執行外部指令（`wg`、`wg-quick`、`nft`、`ip`）一律走參數化呼叫，不組字串餵給 shell，避免 command injection（沿用 Phase 2 的既有原則）。

## 七、Peer 管理模型

Peer 代表一個已授權的 VPN Client。欄位定義見 [configuration-guide.md](configuration-guide.md#peer-欄位)。管理原則：

- Client 私鑰**只由 Client 自行產生**，Gateway 只保存 Client **公鑰**。
- Gateway 產生 Client 設定檔的功能僅用於 **Lab / Bootstrap** 情境，並會在文件與輸出中明確標示，正式環境不應依賴 Gateway 幫使用者產生私鑰。
- Peer 狀態變更（停用/撤銷/移除）必須同步反映到 nftables 規則 — 「WireGuard 允許 handshake」與「nftables 允許轉送」是兩層獨立的控制，缺一不可。✅ Phase 4 已實作：`FirewallRuleGenerator` 每次產生規則時都會重新從 Peer Registry 讀取即時狀態，只有 `Active` Peer 才會出現在產生的規則中（`WireGuardConfigGeneratorPeerTests`、`FirewallRuleGeneratorTests` 皆有對應測試）；⚠️ 目前仍需操作者在 Peer 狀態變更後手動執行 `firewall generate`/`apply` 才會反映到實際 kernel 狀態，自動串接屬 Phase 5 範圍。

## 八、Firewall 規則模型（✅ Phase 4 已實作）

以 Resource-centric 的方式定義規則（誰可以存取哪個資源），而非直接寫死 nftables 語法：Access Policy 只是 (PeerId, ResourceId) 的授權配對，實際 nftables 語法由 `FirewallRuleGenerator` 統一產生。詳見 [firewall-model.md](firewall-model.md)。要點：

- Default policy：**deny**（由 `chain forward` 的 `policy drop` 結構性保證，不依賴規則清單的最後一條）。
- 規則必須明確指定：目的地（IPv4/CIDR）、port、protocol；來源永遠是 Peer 的 VPN IP，不需要在規則中額外指定。
- 不允許「無目的地」或「全開放」（`/8` 或更寬）的規則通過驗證（`ResourceValidator`）。
- 規則具備 `enabled` 旗標，方便維運調整而不需刪除規則定義；**不支援優先順序（priority）**，因為採用 Allow-only + implicit deny 模型，不存在規則互相覆蓋的情境，詳見 firewall-model.md 第五節的設計理由。

## 九、Health Check 架構

Health check 分層檢查（OS/Kernel → WireGuard → nftables → Interface/IP → Configuration 狀態），回傳 `Healthy / Degraded / Unhealthy / Unknown` 四種狀態，且**檢查本身不得改變系統狀態**（唯讀），除非明確呼叫 repair/apply 類指令。詳見 [operations-guide.md](operations-guide.md)。

## 十、CLI 架構

CLI（`securetunnel-gateway`）是 Gateway Agent 的操作介面，命令對應到 Management Plane 的功能模組（wireguard / peer / resource / firewall / config / health / diagnostics）。CLI 本身不直接操作 Data Plane，一律透過 Gateway Agent 的內部服務執行，確保所有操作都經過同一套驗證與 log 機制。詳見 [operations-guide.md](operations-guide.md)。

## 十一、Logging / Audit 架構

所有重要事件透過結構化 logging（規劃使用 Serilog）輸出，並區分一般操作 log 與 audit log。私鑰、token、密碼等敏感資訊在任何 log 層級都不得出現。詳見 [security-model.md](security-model.md#十log-與敏感資料)。

## 十二、Systemd 部署模型

Gateway Agent 以 systemd service 執行；WireGuard 與 nftables 是 Linux Host 原生功能，不透過 Gateway Agent 的 Docker 化。服務停止不得清除既有安全 Firewall 規則；服務啟動失敗不得造成資源全部開放。詳見 [installation-guide.md](installation-guide.md) 與 `deploy/systemd/securetunnel-gateway.service`。

## 十三、Container 使用邊界

本專案對 Docker 的使用範圍明確限制：

| 元件 | 是否用 Container | 說明 |
|---|---|---|
| WireGuard | 否 | Linux Host 原生執行，需要管理實體/虛擬網路介面 |
| nftables | 否 | Linux Host 原生執行，需要管理 kernel netfilter 狀態 |
| IP forwarding | 否 | Host kernel 設定 |
| Gateway Agent | 否（systemd） | 需要呼叫 host 上的 `wg` / `nft` / `ip` 指令 |
| Test Lab 受保護服務（網站/API/TCP） | 是 | 僅供開發測試，見 `test-lab/docker-compose.yml` |
| 未來 Control Plane API | 可以 | 獨立服務，未來評估 |
| 未來 Database | 可以（PostgreSQL Container） | 未來評估 |

若未來評估將 WireGuard/nftables 相關功能容器化，必須在文件中明確說明所需 capabilities（如 `NET_ADMIN`、`NET_RAW`）、是否需要 `--network host`、是否需要 `--privileged`，以及對安全性與可稽核性的影響 — 本階段不採用此做法。

## 十四、開發/測試環境與正式環境的差異（重要）

目前開發環境是 **WSL2 Ubuntu 24.04**，這不是正式部署目標。差異與限制：

| 面向 | WSL2 開發環境 | 正式 Ubuntu Server 24.04 LTS |
|---|---|---|
| Kernel | `*-microsoft-standard-WSL2`（微軟客製） | 標準 Ubuntu server kernel |
| 網路 | 單一 NAT 虛擬網卡，動態內部 IP，外部無法直接連入 | 具備真實/可路由 NIC，可設計 LAN + 受保護網段 |
| sudo | 需密碼，非互動 session 無法自動取得 | 依部署方式決定，通常仍建議需要密碼或改用最小權限帳號 |
| systemd | 可用但非 WSL2 主要設計場景 | 標準支援 |
| Docker | 需另外啟用 WSL integration | 標準支援 |

因此本階段所有「已測試」的宣稱，都會註明是 **邏輯 / 單元測試層級**，還是 **真實網路層級**。無法在 WSL2 執行的測試會標記為 `BLOCKED`（見 [testing-guide.md](testing-guide.md)），未來移轉到正式 Ubuntu Server 後才能補齊。

## 十五、開發階段（Phase 0–8）對應架構模組

| Phase | 對應架構區塊 |
|---|---|
| 0 | 環境檢查（已完成） |
| 1 | 本文件、docs/ 全部文件（本次） |
| 2 | Data Plane：WireGuard Bootstrap |
| 3 | Management Plane：Peer 管理 |
| 4 | Data Plane + Management Plane：nftables / 受保護資源 |
| 5 | Management Plane：Configuration 生命週期 |
| 6 | Management Plane：CLI + systemd |
| 7 | Test Lab + 測試 |
| 8 | 文件收尾、安全審查、Known Limitations |

## 十六、未來整合 Control Plane

本階段**不開發**完整遠端 Control Plane API，但保留以下整合空間：

1. Gateway 主動向 Control Plane 拉取設定（pull model，而非 Control Plane 直接 push/執行指令），降低「遠端任意執行 shell command」的攻擊面。
2. Gateway 使用短期憑證（例如短效 token / mTLS 憑證）向 Control Plane 驗證身分。
3. Gateway 定期回報：health 狀態、目前 Configuration Version、最近一次 apply 成功/失敗結果。
4. Gateway 永遠保留「最後一份有效設定」，即使與 Control Plane 失聯，也不會因此失去現有的存取控制（離線可用、fail-safe）。
5. Control Plane **不會**直接對 Gateway 下達任意 shell command；所有互動都透過定義良好的設定/狀態介面（例如版本化的設定文件 + 已知的 apply/rollback 流程），Gateway 自己決定如何驗證與套用。
6. 未來 Users / Groups / Devices / Gateways / Resources / Access Policies / Audit Logs 由 Control Plane 集中管理，Gateway 端只保留「執行所需的最小設定子集」（例如：這台 Gateway 需要哪些 Peer、哪些 Resource 規則），不需要知道完整的組織架構。

現階段的 `Security/` 模組與設定檔中會為「Control Plane 端點」「憑證參考」等欄位保留位置（選填、預設關閉），但不會實作對應的網路呼叫邏輯。

## 十七、已知限制（架構層級）

- 本階段沒有高可用（HA）/叢集設計，單一 Gateway 實例。
- 本階段沒有完整 RBAC，CLI 操作預設以本機系統權限（root/sudo）為信任邊界。
- IPv6 預設不開放未驗證路徑，只做最基本的檢查（見 security-model.md）。
- 尚未整合任何雲端供應商專屬功能（依禁止事項第 14 點）。
