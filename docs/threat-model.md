# Threat Model

本文件使用簡化的 STRIDE 分類，列出 SecureTunnel Gateway 面對的主要威脅、對應防護措施，以及尚未處理的風險。搭配 [security-model.md](security-model.md) 閱讀。

## 一、資產（Assets）

1. WireGuard Server private key
2. Peer（Client）public key 清單與其授權狀態
3. 受保護資源的可用性與機密性
4. Gateway 設定（含 Firewall 規則）的完整性
5. Audit log 的完整性與可信度
6. Gateway 主機本身（作業系統層級）

## 二、威脅行為者（Threat Actors）

| 行為者 | 描述 |
|---|---|
| 外部未授權使用者 | 沒有有效 Peer 身分，嘗試直接存取受保護資源或 Gateway |
| 已撤銷 / 過期的舊 Peer | 曾經授權、目前應已失效的使用者或裝置 |
| 已授權但意圖不良的 Peer | 合法使用者嘗試存取未授權的資源 |
| 本機低權限使用者 | 對 Gateway 主機有部分存取權（非 root），嘗試讀取敏感檔案或提權 |
| 供應鏈 / 相依套件風險 | WireGuard、nftables、.NET 相依套件本身的漏洞（本專案不自行處理上游漏洞，只負責及時更新） |

## 三、STRIDE 分析

### Spoofing（偽冒）
- **威脅**：偽冒成合法 Peer 嘗試連線。
- **防護**：WireGuard 使用公私鑰配對驗證身分，未知公鑰無法完成 handshake。
- **殘留風險**：若 Client private key 外洩（Client 端保管責任），偽冒可能成功；本專案無法防護 Client 端金鑰保管不當。

### Tampering（竄改）
- **威脅**：竄改 Gateway 設定檔或 nftables 規則以取得未授權存取。
- **防護**：檔案權限限制、Candidate/Active 分離、版本化與 audit log。
- **殘留風險**：本階段未實作設定完整性簽章驗證（見 security-model.md Known Limitations）。

### Repudiation（否認）
- **威脅**：管理者或系統否認曾執行某項變更（新增 Peer、修改規則）。
- **防護**：結構化 audit log 記錄操作、時間、結果、（未來）actor 欄位。
- **殘留風險**：本階段 CLI 操作以本機系統帳號為 actor，若多人共用同一帳號，無法區分具體個人（需搭配作業系統層級的帳號管理）。

### Information Disclosure（資訊洩漏）
- **威脅**：私鑰、設定內容、內部網路結構透過 log 或錯誤訊息洩漏。
- **防護**：Log 敏感資料過濾（見 security-model.md 第十節）、私鑰不進入一般輸出。
- **殘留風險**：NAT Mode 下受保護資源端 log 看不到真實來源 VPN IP（設計取捨，非漏洞，但需維運人員理解其稽核影響）。

### Denial of Service（阻斷服務）
- **威脅**：大量無效連線嘗試消耗 Gateway 資源，或針對 WireGuard UDP port 的流量灌爆。
- **防護**：WireGuard 對無效 handshake 的基本防護。
- **殘留風險**：本階段未提供速率限制規則模板，屬於 Known Limitations，未來視需求於 nftables 規則中補強。

### Elevation of Privilege（權限提升）
- **威脅**：透過 Gateway Agent 的漏洞（例如指令注入）取得 root 權限。
- **防護**：參數化指令呼叫、輸入驗證、最小化 root 操作範圍（見 security-model.md 第四節）。
- **殘留風險**：Gateway Agent 目前規劃以較高權限（root 或具 `CAP_NET_ADMIN` 等）執行，程式碼品質與輸入驗證的嚴謹度直接影響此風險，需持續的程式碼審查（見 [../CONTRIBUTING.md](../CONTRIBUTING.md)）。

## 四、情境式威脅（Scenario-based）

### 情境 1：Peer 被撤銷後仍嘗試存取
- **預期行為**：WireGuard 拒絕新的 handshake；即使既有 session 尚未斷（WireGuard 沒有主動踢除機制），nftables 層也應同步移除該 Peer 的 allow 規則，使其無法轉送至受保護資源。
- **對應測試**：TC-015（見 testing-guide.md）。

### 情境 2：未連 VPN 的來源直接嘗試存取受保護資源
- **預期行為**：封包根本不會出現在 `wg-securetunnel` 介面上，也不在 VPN 子網範圍內，nftables default deny 直接阻擋。
- **對應測試**：TC-014。

### 情境 3：設定套用過程中失敗（例如 nftables 規則語法錯誤）
- **預期行為**：Apply 流程偵測失敗，觸發 rollback 至上一個 active 設定，系統不落入全部放行或規則真空狀態。
- **對應測試**：TC-017、TC-018。

### 情境 4：Gateway 主機或 Gateway Agent 重啟
- **預期行為**：重啟後 WireGuard 介面與 nftables 規則維持重啟前的安全狀態（透過 systemd 相依關係與開機自動套用最後一份 active 設定達成）。
- **對應測試**：TC-019、TC-020。

### 情境 5：設定檔要求「允許全部流量」
- **預期行為**：Configuration Validation 直接拒絕，不允許此類設定被儲存為 candidate，更不會被 apply。

## 五、超出範圍（Out of Scope，本階段）

依原始需求禁止事項與本階段範圍，以下不在本專案威脅模型防護範圍內：

- 流量匿名化 / 對抗流量分析。
- 深度封包檢測（DPI）層級的應用層攻擊偵測。
- 受保護資源本身應用層漏洞（例如網站本身的 SQL Injection）。
- Client 裝置本身的安全狀態（是否中毒、私鑰是否洩漏）。
- 多租戶隔離（本階段單一 Gateway 服務單一組織）。

## 六、Known Limitations（威脅模型層級）

- 未實作異常行為偵測（例如短時間內大量失敗連線的告警）。
- 未實作設定完整性簽章，Tampering 防護仍主要依賴檔案權限與人工審查。
- 目前開發環境（WSL2）無法對上述情境進行真實網路層級的攻防驗證，僅能驗證邏輯正確性（見 testing-guide.md 的 BLOCKED 項目）。
