# Firewall Model

> **Phase 4 狀態**：本文件描述的模型與規則已實際實作於 `src/SecureTunnel.GatewayAgent/Firewall/`，共 93 個 xUnit 測試（`tests/FirewallTests`）+ 41 個 CLI 整合測試（`tests/IntegrationTests`）涵蓋規則產生、apply 生命週期、驗證邏輯。**規則「產生」與「語法驗證」已在真實 Linux（WSL2）驗證過**（見 testing-guide.md）；**實際 `nft apply` 與真實封包過濾**因 WSL2 未安裝 `nftables` 而維持 BLOCKED，尚待正式 Ubuntu Server 驗證。

## 一、技術選擇：nftables

本專案使用 **nftables** 作為 Linux Firewall 實作技術，理由：

- Ubuntu 24.04 LTS 的現代預設 Firewall 框架（取代 iptables-legacy）。
- 規則語法支援結構化的 table/chain/set，方便由程式產生與版本化管理。
- 效能與可維護性優於逐條 `iptables` 指令疊加。
- 支援 `nft -c -f <file>`（syntax-only check，不套用），讓 Gateway Agent 能在套用前先驗證產生的規則語法是否正確，不需要冒著套用失敗的風險（見第六節 Apply 生命週期）。

## 二、流量方向與 Chain 設計（✅ 已實作）

```
VPN Client（WireGuard Peer）
    │  來源 IP = Peer 的 VPN IP（10.250.0.x），NAT 尚未發生
    ▼
WireGuard Interface (wg-securetunnel)
    ▼
nftables forward chain（hook forward, priority 0, policy drop）
    ├─ ct state established,related accept  ← 回程流量
    └─ jump securetunnel_vpn_access          ← 授權判斷（見下方）
              │
              ▼
    chain securetunnel_vpn_access（一般 chain，非 hook base chain）
    ├─ ip saddr <PeerVpnIp> ip daddr <ResourceDest> <proto> dport <port> accept   ← 每條 Effective Rule 一行
    └─ （沒有比對到任何規則 → 掉回 forward chain 的 policy drop，即 default deny）
              │
              ▼（若被允許）
    nftables postrouting chain（hook postrouting, priority 100 / srcnat）
    └─ ip saddr <VpnCidr> ip daddr <ProtectedCidr> masquerade   ← SNAT，僅限 VPN→受保護網路
              │
              ▼
    Protected Resource（看到來源 IP 已被 masquerade 成 Gateway 的 IP，見 network-topology.md NAT Mode）
```

實際的 table/chain 結構（`src/SecureTunnel.GatewayAgent/Firewall/FirewallRuleGenerator.cs`）：

- `table inet securetunnel` — **SecureTunnel Gateway 唯一擁有並管理的 table**，不觸碰系統上其他任何 nftables table。
  - `chain forward`（base chain，hook `forward`，priority `0`，**policy `drop`**）：處理「Forward traffic」與「Return traffic」需求 —— 先放行已建立連線的回程流量，其餘一律 `jump` 到授權 chain 判斷。
  - `chain securetunnel_vpn_access`（一般 chain，非 hook）：處理「VPN-to-protected-resource traffic」需求 —— 逐條列出目前有效的 (Peer, Resource) 授權，每條規則明確指定來源 IP、目的地、協定、port。沒有任何規則比對到，就自然「掉回」`forward` chain 繼續往下（沒有更多規則了），最終落到 `forward` chain 的 `policy drop`。**這就是本專案的 default deny 實作方式**：不是靠某一條「deny all」規則，而是靠 chain policy 本身，結構性地無法被繞過。
  - `chain postrouting`（base chain，hook `postrouting`，priority `100`／`srcnat`）：處理「NAT」需求 —— 只對「VPN CIDR → 受保護網路 CIDR」這個範圍做 masquerade，不是對所有流量做 masquerade。

未實作、本階段不在範圍內的 chain：`input` chain（管理 Gateway 自身可被連線的規則，例如限制誰能連到 WireGuard UDP port）— 屬於 Data Plane 的「Gateway 自我防護」課題，不同於本階段「Peer 對受保護資源的授權」課題，列入 Known Limitations。**（Phase 7 重新審查後維持此決定）**：主動接管 `input` chain 有意外鎖死管理連線（例如操作者自己的 SSH session）的風險，這屬於操作者自己 OS 層防火牆的責任範圍，不是 Gateway Agent 應該代為決定的事，見 security-model.md 第二十五節。

**IPv6 説明（Phase 7 補充審查）**：`table inet securetunnel` 使用的是 nftables `inet` combined family，其 `forward` chain 的 `policy drop` 對 IPv4 與 IPv6 轉發流量同時生效；而所有 accept 規則只使用 `ip saddr`/`ip daddr`（IPv4 專屬）比對，規則產生器從未輸出任何 `ip6` 比對式。因此 IPv6 轉發流量結構性地無法命中任何 accept 規則，天生就會落到 `policy drop`——細節與測試佐證見 security-model.md 第十五節「IPv6 洩漏」。

## 三、NAT Packet Flow：為何授權判斷一定發生在 NAT 之前

這是本階段最重要的安全性質，因此在此重複驗證推導過程（原始需求：「Firewall authorization must evaluate the original VPN source IP」「NAT must not be applied before the allow-list decision」）：

**Netfilter hook 執行順序**（Linux kernel 的固定行為，不是本專案自訂的）：
`prerouting → 路由決策 → forward → postrouting`

`forward` chain 掛在 `forward` hook（filter 類型），`postrouting` chain 掛在 `postrouting` hook（nat 類型，`srcnat`/masquerade 只能掛在這個 hook）。**根據 netfilter 的固定 hook 執行順序，`forward` hook 永遠比 `postrouting` hook先執行**。

因此：
1. 封包從 WireGuard 介面進來，此時來源 IP 是 Peer 的真實 VPN IP（例如 `10.250.0.10`），尚未被改寫。
2. `forward` chain（連帶 `securetunnel_vpn_access`）在**這個階段**做授權判斷 — 比對的 `ip saddr` 就是這個未經改寫的 VPN IP。
3. 只有通過授權判斷、被 `accept` 的封包，才會繼續往下流動到 `postrouting` hook。
4. `postrouting` chain 這時才執行 masquerade，把來源 IP 改寫成 Gateway 在受保護網路上的位址。

**結論**：授權判斷天生就是在 NAT 之前發生，這不是需要額外程式碼保證的邏輯，而是 nftables/netfilter 的 hook 架構本身保證的。本專案的 `FirewallRuleGenerator` 唯一要做對的事，是**不要把授權規則錯放到 `postrouting` chain**，以及**不要對授權判斷之前的任何流量做 masquerade**。`tests/FirewallTests/FirewallRuleGeneratorTests.GenerateAsync_MasqueradeRule_AppearsInPostroutingNotForward` 驗證了這件事：masquerade 規則的文字只出現在 `chain postrouting` 區塊，不會混進 `chain forward`/`chain securetunnel_vpn_access`。

**驗證方式的誠實聲明**：以上是**規則語義正確性**的驗證（規則文字符合 nftables 語法、且掛在正確的 hook/priority、且順序正確），並經過真實 `nft` 語法檢查器在 Linux 上跑過語法驗證邏輯的程式路徑（見 testing-guide.md）。但**尚未**用真實封包、真實兩端主機做端到端驗證（例如「用封包產生工具送一個偽造來源 IP 的封包，確認真的被擋下」），這需要正式 Ubuntu Server + 真實網路拓撲，目前標記 BLOCKED。

## 四、Protected Resource 模型（✅ 已實作）

對應 `src/SecureTunnel.GatewayAgent/Models/ProtectedResource.cs`：

| 欄位 | 型別 | 必填 | 說明 |
|---|---|---|---|
| `resourceId` | string | 是 | 唯一識別碼，格式 `resource-<12 hex>`，自動產生 |
| `name` | string | 是 | 顯示名稱 |
| `description` | string \| null | 否 | 說明 |
| `destination` | string | 是 | **明確的 IPv4 位址或 CIDR**，例如 `10.20.0.10` 或 `10.20.0.0/28`。**不支援 hostname** |
| `protocol` | enum | 是 | `Tcp` \| `Udp`。不支援 `icmp`（見第九節 Known Limitations，與 Phase 1 草稿的差異） |
| `port` | int | 是 | 目的地 port（單一 port，或 port range 的起點） |
| `portEnd` | int \| null | 否 | port range 的終點（含）；為 `null` 時代表單一 port |
| `enabled` | bool | 是 | 停用時不會出現在 effective rule 中 |
| `createdAtUtc` / `updatedAtUtc` | datetime | 是 | UTC 時間 |

### 為何不支援 hostname

原始需求明確要求「避免在此階段把 hostname-based resource 當成主要功能，除非有安全且經完整測試的 DNS 解析行為」，並且「不得在防火牆評估當下靜默解析任意 hostname」。本專案的判斷是：**完全不支援**，而非「支援但標示實驗性」。理由：

- 若在 `firewall apply` 當下解析 hostname，DNS 回應可能隨時間改變（TTL、負載平衡、DNS 快取污染攻擊），會讓「規則產生時看到的目的地」與「規則實際生效時的目的地」不一致 — 這正是原始需求想避免的「時間依變的靜默授權」。
- 若只在 `resource add` 當下解析一次並固定成 IP，那本質上跟直接要求操作者填 IP 沒有差異，只是多了一層可能出錯的間接性。
- 因此：**Phase 4 只接受明確 IPv4 位址/CIDR**，若受保護資源的 IP 會變動，由操作者自行維護（未來可評估的方向見 Known Limitations）。

### 拒絕過廣目的地

`ResourceValidator`（`Firewall/ResourceValidator.cs`）拒絕字首長度 `/8` 或更寬的 CIDR（包含 `0.0.0.0/0`），訊息明確指出「這看起來像是想繞過限制取得未受限存取」。這直接對應原始需求「Reject: ... unrestricted destination」「Do not implement unrestricted LAN access as a shortcut」。

## 五、Access Policy 模型（✅ 已實作，Allow-only + Implicit Deny）

對應 `src/SecureTunnel.GatewayAgent/Models/AccessPolicy.cs`：

| 欄位 | 型別 | 必填 | 說明 |
|---|---|---|---|
| `ruleId` | string | 是 | 唯一識別碼，格式 `rule-<8 hex>` |
| `peerId` | string | 是 | 被授權的 Peer |
| `resourceId` | string | 是 | 被授權存取的 Resource |
| `enabled` | bool | 是 | 停用時不影響其他規則 |
| `description` | string \| null | 否 | 說明 |
| `createdAtUtc` / `updatedAtUtc` | datetime | 是 | UTC 時間 |

**沒有 `action`（Allow/Deny）欄位，也沒有 `priority` 欄位** — 這是刻意的架構決策，理由（原始需求也明確允許此設計：「an allow-only model with implicit deny is acceptable and may be safer」）：

- Allow-only 模型下，「沒有規則」天生等於「拒絕」，不需要額外邏輯保證。
- 若同時支援 Allow 與 Deny，就必須定義優先順序語意（哪個規則贏？數字小的贏還是後定義的贏？Deny 是否能覆蓋 Allow？），這類優先順序 bug 是真實世界防火牆最常見的安全漏洞來源之一。
- MVP 階段的存取控制需求（「這個 Peer 能不能存取這個 Resource」）用純 Allow-only 完全足夠表達，不需要 Deny 規則帶來的額外表達力。

**驗證與「拒絕」的分層設計**（`Firewall/PolicyValidator.cs`，詳細理由見程式碼註解與本文件）：

| 情境 | 判定 | 理由 |
|---|---|---|
| `peerId`/`resourceId` 指向完全不存在的 Peer/Resource | **Error**（拒絕新增） | 對應「Unknown Peer/Resource must be denied」— 一個指向虛無的規則沒有意義 |
| `peerId` 指向存在但目前 `Disabled`/`Revoked`/`Removed` 的 Peer | **Warning**（允許新增，但提示不會生效） | 讓操作者可以預先定義規則，或在暫時停用 Peer 期間保留規則定義，不需要每次都刪除重建 |
| `resourceId` 指向存在但目前 `disabled` 的 Resource | **Warning**（同上） | 同上 |
| 同一組 (peerId, resourceId) 已存在其他規則 | **Error**（拒絕新增，見 `JsonFilePolicyRepository` 的重複權限檢查） | 避免同一授權被重複定義造成混淆 |

## 六、Apply 生命週期（✅ 已實作：`FirewallApplyOrchestrator`）

對應原始需求第十節「Apply and Verification Behavior」，實作於 `Firewall/FirewallApplyOrchestrator.cs`，狀態機定義於 `Models/FirewallApplyState`：

```
NotStarted
   │  載入 Peer/Resource/Policy，呼叫 FirewallRuleGenerator（dry-run 模式，純記憶體驗證）
   │  失敗 → 直接回報 Failed，狀態停在 NotStarted，完全不碰任何檔案或 nft
   ▼
Generated
   │  --dry-run 到此為止（回報成功，不繼續）
   │  否則：把候選規則寫到 <FirewallRulesetPath>.candidate（暫存檔，非現行檔案）
   │  用 `nft -c -f <candidate>` 做語法檢查
   │  失敗（含 nft 不存在 → BLOCKED）→ Failed，現行檔案完全不受影響
   ▼
SyntaxValidated
   │  備份現行檔案（若存在）到 <FirewallRulesetPath>.lastknowngood
   │  把候選檔案複製成現行檔案
   │  用 `nft -f <現行檔案>` 實際套用
   │  失敗 → 還原備份（若先前沒有現行檔案，改為刪除，避免留下語意不明的殘檔）→ Failed
   ▼
Applied
   │  用 `nft list table inet securetunnel` 驗證 table 真的存在
   │  驗證失敗/不確定 → Failed，訊息明確標示「UNKNOWN」，絕不假裝套用成功
   ▼
Verified   ← 只有走到這一步，`firewall apply` 才回報 Success = true
```

**关键保证**（皆有 `tests/FirewallTests/FirewallApplyOrchestratorTests.cs` 的 8 個測試逐一驗證）：
- 任何步驟失敗，錯誤訊息都會標明「最後成功走到哪一步」（`[last successful step: <State>]`），CLI 可以清楚分辨「產生失敗」vs「語法錯誤」vs「套用失敗」vs「驗證失敗」。
- Apply 失敗時，現行檔案（代表 kernel 應該有的狀態）會被還原成上一個已知良好版本，不會留下「檔案內容 ≠ kernel 實際狀態」的混淆狀態。
- 沒有任何路徑會讓系統落入「全部放行」— 因為候選規則本身（來自 `FirewallRuleGenerator`）從產生的那一刻起就已經是 default-deny 結構，沒有「先全開再收斂」這種中間狀態。
- 完整的 candidate/active **版本化**（保留任意歷史版本、`config rollback` 指令）屬於 Phase 5 範圍；本階段只保證「最近一次已知良好狀態」可還原（`.lastknowngood`），這點已在 Known Limitations 中明確標註，不誇大完成度。

## 七、Rule Generation 的確定性與去重

`FirewallRuleGenerator.ComputeEffectiveRules`：
- 只納入 `Active` Peer + `enabled` Resource + `enabled` Policy 三者同時成立的組合（見第五節表格）。
- 輸出前依 `(PeerVpnIp, Destination, Port)` 排序 — **與輸入的檔案順序或字典疊代順序無關**，保證同一份資料無論如何排列輸入，永遠產生 byte-identical 的輸出（`FirewallRuleGeneratorTests.GenerateAsync_TwoPeers_DeterministicOutputRegardlessOfInputOrder` 驗證）。
- 防禦性地再次檢查是否有「相同 (VPN IP, 目的地, 協定, port)」的重複有效規則（正常情況下 `JsonFilePolicyRepository` 的重複權限檢查已經防止這發生，這裡是縱深防禦，比照 `WireGuard/WireGuardConfigGenerator.ValidatePeerSet` 的同一種模式）。

## 八、CLI 對應（✅ 已實作）

見 [operations-guide.md](operations-guide.md) 完整指令範例。摘要：`resource`/`policy` 各有 `list/show/add/enable/disable/remove`；`firewall` 有 `validate`（純驗證，計算 effective rule 數量但不寫檔）、`generate`（渲染 + 寫檔，支援 `--dry-run`/`--force`）、`status`/`show`（查詢現有 kernel 狀態）、`apply`（完整生命週期，需要 `--yes` 或 `--dry-run`）。

## 九、Known Limitations（Firewall 層面）

- **ICMP 不支援**：與 Phase 1 草稿的設計不同 — 原始 Phase 1 文件曾規劃 ICMP 支援，但 Phase 4 實作時判斷 ICMP 的授權語意（ping 不像 TCP/UDP 有明確的 port 概念）與本階段的 Resource 模型（destination + protocol + port）不完全對齊，且需求急迫性較低，因此本階段只支援 TCP/UDP，ICMP 留給未來評估。這是一個**具體發現的不相容並已記錄**的架構調整，範圍限定在「Resource 的 protocol 選項」，不影響其他既有決策。
- **不支援 hostname 型 Resource**（見第四節）。
- **不支援 Deny 規則**，只有 Allow-only + implicit deny（見第五節，此為刻意設計而非未完成）。
- **`input` chain（Gateway 自我防護）未實作** — 本階段只管制「Peer 對受保護資源」的存取，不管制「誰能連到 Gateway 本身」。
- **無完整版本化與任意版本 rollback** — 只有單一層級的 `.lastknowngood` 備份（見第六節），完整 candidate/active 版本歷史是 Phase 5 範圍。
- **無速率限制 / DoS 防護規則模板**。
- **無「規則被外部手動修改」的偵測** — `firewall status` 只回報 table 是否存在，不會比對內容雜湊來偵測外部竄改。
- **真實封包過濾與 NAT 行為未經真實網路驗證**（見第三節「驗證方式的誠實聲明」與 testing-guide.md）— WSL2 未安裝 `nftables`，且缺乏免密 sudo，`nft -f`（apply）以下的所有步驟在目前開發環境皆為 BLOCKED，規則「產生」與「語法」層面已驗證。
