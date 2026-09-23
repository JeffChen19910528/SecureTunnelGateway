# Network Topology

## 一、預設網路規劃

以下為**範例值**，全部可透過 `config/gateway.yaml` 調整，不可寫死在程式碼中。

| 項目 | 預設值 |
|---|---|
| VPN Interface 名稱 | `wg-securetunnel` |
| VPN Network | `10.250.0.0/24` |
| Gateway VPN IP | `10.250.0.1` |
| Client IP Pool | `10.250.0.10` ～ `10.250.0.200` |
| WireGuard Listen Port | `51820/udp` |
| 範例受保護網路 | `10.20.0.0/24` |

範例受保護服務：

| 名稱 | 位址 | Protocol |
|---|---|---|
| Website | `10.20.0.10:443` | TCP |
| API | `10.20.0.20:8443` | TCP |
| TCP Service（如 PostgreSQL） | `10.20.0.30:5432` | TCP |

## 二、網段重疊檢查（Configuration Validation 必查項目）

設定驗證必須確保以下網段彼此不重疊，重疊時驗證**必須失敗**並回報清楚錯誤（哪兩個網段重疊、重疊範圍）：

- VPN Network（`10.250.0.0/24`）
- Gateway LAN Network（Gateway 對外/對內部網路的介面網段）
- Protected Resource Network（`10.20.0.0/24` 等）
- Client Local Network（VPN Client 端本地網路，例如使用者家中 `192.168.1.0/24`）— 這項通常無法由 Gateway 直接得知，因此驗證邏輯至少涵蓋前三者，Client Local Network 的衝突風險會在文件中提示使用者於 Client 端注意（Split Tunnel 情境下尤其重要，見第五節）。

## 三、NAT Mode 採用理由與限制

本專案 **MVP 與正式環境採用 NAT Mode**（架構決策，見 [architecture.md](architecture.md#五routing-mode採用-nat-mode)）。

### 3.1 NAT Mode 是什麼

VPN Client 的封包進入 Gateway 後，Gateway 在轉送到受保護資源前，會把來源位址 SNAT 成 Gateway 自己在該受保護網路上的位址。受保護資源看到的來源 IP 是 **Gateway**，不是 VPN Client 的 VPN IP（`10.250.0.x`）。

```
VPN Client (10.250.0.15)
   │ WireGuard
   ▼
Gateway wg-securetunnel (10.250.0.1)
   │ nftables: allow-list 判斷（此時仍知道真實來源 10.250.0.15）
   │ SNAT → Gateway 在受保護網路的 IP（例如 10.20.0.1）
   ▼
Protected Resource 看到來源 = 10.20.0.1（Gateway），而非 10.250.0.15
```

### 3.2 採用原因

1. **降低受保護資源端的回程路由設定需求**：受保護資源不需要知道 `10.250.0.0/24` 這個 VPN 網段要怎麼回應，因為它看到的來源就是 Gateway 本身、在同一個受保護網段裡。
2. **適合小型企業初期部署**：不需要去改動既有內部網路設備（交換器/路由器）的路由表。
3. **較容易整合既有內部網路**：Gateway 可以直接以「一台新主機加入現有網段」的方式部署，而不需要對既有網路團隊提出路由變更需求。

### 3.3 代價與限制（必須被記錄且不得被忽略）

1. **來源 VPN IP 可見性降低**：受保護資源的 access log 只會看到 Gateway 的 IP，看不到是哪個 VPN Client 存取的。若需要「誰在什麼時間存取了哪個資源」的稽核能力，**必須依賴 Gateway 自己的 audit log**（記錄 Peer → Resource 的存取事件），不能指望受保護資源的 log 做到這件事。
2. **不得因此放寬 Firewall**：NAT 只影響「受保護資源看到的來源 IP」，**不影響 Gateway 內部的存取決策**。nftables 在做 SNAT 之前，就已經用真實的 VPN 來源 IP（`10.250.0.x`）與 Peer 身分決定是否放行；allow-list + default deny 原則完全不變。
3. **仍然必須採取 allow-list 與 default deny**：NAT 只是「轉送階段」的位址轉換，不是存取控制機制本身。
4. **除錯難度略增**：在受保護資源端做網路除錯時，需要對照 Gateway 的 audit log 才能還原「這個來源 IP（Gateway）的封包實際上是哪個 VPN Client 送出的」。

### 3.4 與 Routed Mode 的差異

| | NAT Mode（採用） | Routed Mode |
|---|---|---|
| 受保護資源是否需要知道 VPN 網段路由 | 不需要 | 需要（新增回程路由指向 Gateway） |
| 受保護資源看到的來源 IP | Gateway 的 IP | VPN Client 真實 VPN IP（`10.250.0.x`） |
| 部署阻力 | 較低 | 較高（需協調網路團隊改路由） |
| 網路可觀測性 | 較低（來源 IP 不可見） | 較高 |
| 是否需要 NAT | 需要（SNAT） | 通常不需要 |

### 3.5 未來擴充 Routed Mode

`RoutingMode` 是設定檔中的欄位（`nat` / `routed`），架構上規則產生器（Firewall Rule Generator）會依模式套用不同的 nftables 規則模板（NAT Mode 額外加上 SNAT/MASQUERADE 規則，Routed Mode 則不加）。本階段只實作 `nat`，`routed` 保留為未來擴充項目，不在本階段開發，但欄位與驗證邏輯會預留（避免的錯誤是：使用者設成 `routed` 卻套用了 NAT 的規則產生器而沒有明確報錯 — 若未實作，驗證階段應直接拒絕並提示「此模式尚未支援」，而不是默默套用錯誤行為）。

## 四、IP Forwarding 與 NAT 規則

- 需啟用 IPv4 forwarding（`net.ipv4.ip_forward=1`）。
- IPv6 forwarding **不預設開放**；若受保護網路確實需要 IPv6，須額外評估並明確設定，不得因為「順手開了 IPv4」就一併開放未驗證的 IPv6 路徑（見 [security-model.md](security-model.md#十五ipv6-洩漏)）。
- NAT（MASQUERADE/SNAT）只套用在「VPN 子網 → 受保護網路」這條路徑，**不對所有流量啟用 MASQUERADE**。

## 五、Split Tunnel 架構

本專案設計為 **Split Tunnel**（而非 Full Tunnel，依禁止事項第 8 點，Full Tunnel 不作為主要功能）：

- VPN Client 的 `AllowedIPs` 只包含 VPN 網段與受保護資源網段（例如 `10.250.0.0/24, 10.20.0.0/24`），**不包含 `0.0.0.0/0`**。
- Client 的一般網際網路流量（例如瀏覽公開網站）不會經過 Gateway，只有目的地在受保護網路內的流量才會走 VPN 通道。
- 好處：降低 Gateway 頻寬與延遲負擔、減少「VPN 斷線影響使用者一般上網」的風險、更貼近「私有資源存取控管」而非「匿名上網」的定位。
- 提醒：Split Tunnel 情境下，Client Local Network（見第二節）若剛好與 VPN Network 或受保護網路重疊，會造成路由衝突，因此 Client 端設定文件會提醒使用者留意。

## 六、目前開發環境（WSL2）與此拓撲的落差

目前開發/驗證環境（WSL2 Ubuntu 24.04）只有一張 NAT 虛擬網卡（`eth0`，動態 IP 如 `172.23.x.x/20`），沒有第二張介面可以模擬「受保護網路」，也無法讓外部真實 Windows/Linux WireGuard Client 直接連入。因此：

- 本階段在 WSL2 上只能驗證：設定檔中的網段重疊檢查邏輯、nftables 規則文字產生是否正確、WireGuard 設定檔內容是否正確 — 這些都是**邏輯層級**驗證。
- 無法在 WSL2 驗證：真實封包是否確實被 SNAT、外部 Client 是否真的能 handshake 並存取受保護資源 — 這些屬於 [testing-guide.md](testing-guide.md) 中標記 `BLOCKED` 的項目，需要正式 Ubuntu Server（或至少有可路由第二網段的 VM/實體機）才能執行。
