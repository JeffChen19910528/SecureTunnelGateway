# Operations Guide

> **Phase 6A 狀態**：以下標示「✅ 已實作」的指令是真實可執行的程式碼（`src/SecureTunnel.GatewayAgent/Cli/RootCommandFactory.cs`），已用 `dotnet run`／self-contained 發佈檔在 Windows 與 WSL2 Ubuntu 24.04 實測（含 `--json`、`--dry-run`、`--yes` 行為），並有 `tests/IntegrationTests/CliInvocationTests.cs`、`PeerCliInvocationTests.cs`、`FirewallCliInvocationTests.cs`、`ConfigLifecycleCliInvocationTests.cs`、`GatewayCliInvocationTests.cs`、`tests/DaemonTests/GatewayDaemonServiceTests.cs` 涵蓋（共 363 個 xUnit 測試橫跨全專案）。

## 一、CLI 總覽

```
securetunnel-gateway version                    ✅ 已實作
securetunnel-gateway doctor                      ✅ 已實作
securetunnel-gateway health                      ✅ 已實作
securetunnel-gateway validate                    ✅ 已實作
securetunnel-gateway config generate             ✅ 已實作（Phase 3 起自動納入 Active Peer 的 [Peer] 區塊）
securetunnel-gateway wireguard status            ✅ 已實作
securetunnel-gateway wireguard show              ✅ 已實作
securetunnel-gateway wireguard generate          ✅ 已實作（config generate 的別名）
securetunnel-gateway wireguard generate-keys     ✅ 已實作（Phase 2.5 新增，原始需求未列出但為必要功能）
securetunnel-gateway wireguard start             ✅ 已實作
securetunnel-gateway wireguard stop              ✅ 已實作
securetunnel-gateway wireguard restart           ✅ 已實作
securetunnel-gateway peer list                   ✅ 已實作（Phase 3）
securetunnel-gateway peer show                   ✅ 已實作（Phase 3）
securetunnel-gateway peer add                    ✅ 已實作（Phase 3）
securetunnel-gateway peer enable                 ✅ 已實作（Phase 3）
securetunnel-gateway peer disable                ✅ 已實作（Phase 3）
securetunnel-gateway peer revoke                 ✅ 已實作（Phase 3）
securetunnel-gateway peer remove                 ✅ 已實作（Phase 3；軟刪除/封存，見第八節）
securetunnel-gateway peer status                 ✅ 已實作（Phase 3；儲存狀態 + best-effort `wg show` 交叉比對）
securetunnel-gateway peer config                 ✅ 已實作（Phase 3；產生 Client 設定範本，見第八節）
securetunnel-gateway peer allocate-ip            ✅ 已實作（Phase 3；唯讀預覽，不建立 Peer）
securetunnel-gateway resource list/show/add/enable/disable/remove   ✅ 已實作（Phase 4）
securetunnel-gateway policy list/show/add/enable/disable/remove     ✅ 已實作（Phase 4）
securetunnel-gateway firewall validate            ✅ 已實作（Phase 4；純驗證 + effective rule 數量，不寫檔不套用）
securetunnel-gateway firewall generate            ✅ 已實作（Phase 4；渲染 nftables ruleset，支援 --dry-run/--force）
securetunnel-gateway firewall status              ✅ 已實作（Phase 4；查詢 `inet securetunnel` table 是否存在）
securetunnel-gateway firewall show                ✅ 已實作（Phase 4；`nft list table` 原始輸出）
securetunnel-gateway firewall apply               ✅ 已實作（Phase 4；完整生命週期：產生→語法驗證→套用→驗證，見第七節）
securetunnel-gateway config status                ✅ 已實作（Phase 5；Active/Last-Known-Good/最新版本狀態，含中斷操作偵測）
securetunnel-gateway config list                  ✅ 已實作（Phase 5；列出所有已記錄的版本）
securetunnel-gateway config show --version <n>    ✅ 已實作（Phase 5；單一版本完整細節）
securetunnel-gateway config diff --from <a> --to <b>   ✅ 已實作（Phase 5；兩版本間 Peer/Resource/Policy 增減）
securetunnel-gateway config validate              ✅ 已實作（Phase 5；等同 `config apply --dry-run`）
securetunnel-gateway config apply                 ✅ 已實作（Phase 5；**完整**版本化生命週期：驗證→產生→套用 WireGuard+nftables→驗證→Active，見第十三節）
securetunnel-gateway config verify                ✅ 已實作（Phase 5；查詢「實際」目前有效狀態，不依賴 history 記錄）
securetunnel-gateway config rollback --version <n>   ✅ 已實作（Phase 5；使用該版本自身的不可變快照資料，見第十四節）
securetunnel-gateway gateway status               ✅ 已實作（Phase 6；Configured/Desired/Active/Effective 綜合狀態，見第十七節）
securetunnel-gateway gateway backup [create]       ✅ 已實作（Phase 6；建立備份，見第十八節）
securetunnel-gateway gateway backup list           ✅ 已實作（Phase 6；列出既有備份）
securetunnel-gateway gateway restore --file <path> ✅ 已實作（Phase 6；從備份還原 Registry/History/金鑰，見第十八節）
securetunnel-gateway gateway serve                ✅ 已實作（Phase 6A；常駐 daemon 執行模式，systemd ExecStart 實際呼叫的指令，見第二十節）
```

> `gateway health`/`diagnostics`/`version` 刻意**沒有**再獨立提供——Phase 2 起的頂層 `health`/`doctor`/`version` 已涵蓋同樣的用途，重複提供只會製造「同一件事兩種問法」的混淆。`gateway status` 是 Phase 6 真正新增的內容：它把 `health`（環境/工具可用性）、`config verify`（實際生效狀態）、`config status` 的中斷操作偵測、以及全新的 Desired-vs-Active 落差偵測整合成一次查詢。

**`config generate` 與 `config apply` 的差異（容易混淆，務必區分）**：`config generate`（Phase 2 遺留，`wireguard generate` 的別名）**只**產生 WireGuard 介面設定檔，不觸碰 nftables，也不記錄版本歷史。`config apply`（Phase 5 新增）才是完整的版本化生命週期——同時套用 WireGuard **與** nftables、記錄可回溯的版本、驗證後才標記 Active。日常操作（新增 Peer 後要真正生效）應使用 `config apply`，不要只用 `config generate`。

共同行為（已實作項目皆符合）：

- 危險操作（`wireguard start`/`stop`/`restart`）不加 `--yes` 或 `--dry-run` 時會直接拒絕執行並提示原因，不會默默略過或執行。
- 輸出支援人類可讀（預設）與 `--json`（所有已實作指令皆支援，非 `--output human/json` 這種獨立選項，而是布林旗標 `--json`；文件先前版本描述的 `--output` 形式已調整）。
- 私鑰絕不顯示在任何輸出中（`wireguard generate-keys` 只輸出公鑰）。
- Exit code：`0` 成功（含 Health=Degraded 仍視為可接受的 0）、`1` 一般失敗、`2` 驗證失敗（`validate`/`config generate`/loading 錯誤）；`3`（權限不足專用碼）尚未在各指令中細分使用，目前權限不足會回傳 `1` 並在訊息中說明，細分列入 Known Limitations。
- `wg`/`wg-quick`/`nft` 等指令不存在時，回傳 `BLOCKED`（非 0 exit code 並在訊息中明確標示 `BLOCKED:` 前綴），不會偽裝成功。

## 二、新增使用者或裝置（新增 Peer，✅ 已實作）

**步驟 1：在 Client 裝置上自行產生金鑰對**（Gateway 從不代為產生正式 Peer 的私鑰，見 [security-model.md](security-model.md#三client-private-key-security)）：

```bash
# 在 Client 裝置（不是 Gateway！）上執行：
wg genkey | tee client-private.key | wg pubkey > client-public.key
cat client-public.key   # 把這一行的內容交給 Gateway 操作者
```

**步驟 2：在 Gateway 上註冊該公鑰**：

```bash
securetunnel-gateway peer add \
  --config /etc/securetunnel-gateway/gateway.yaml \
  --name "Alice Laptop" \
  --public-key "<步驟1輸出的公鑰>" \
  --description "Alice 的筆電，業務部門" \
  --yes
```

`peer add` 屬安全性敏感操作（會授予 VPN 存取權），未加 `--yes` 會直接拒絕執行；加 `--dry-run` 可預覽會配發到的 VPN IP與結果而不寫入任何資料。Gateway 會自動從 `network.clientAddressPoolStart`–`clientAddressPoolEnd` 範圍配發未使用的 VPN IP（也可用 `--vpn-ip <ip>` 明確指定），公鑰格式（base64、解碼 32 bytes、非全同位元組的佔位樣式）與重複公鑰（含已 Revoked/Removed 的舊紀錄）都會被拒絕。輸出**不會**顯示或要求輸入私鑰。

**步驟 3：把新 Peer 套用到實際系統**（✅ Phase 5：一個指令同時處理 WireGuard 與 nftables）：

```bash
securetunnel-gateway config apply --config /etc/securetunnel-gateway/gateway.yaml --yes
```

（`peer add` 只更新 Peer Registry；`config apply` 才會讓新增/停用/撤銷真正對正在執行的系統生效，並記錄一個可回溯的版本。完整生命週期見第十三節。）

**查詢與管理**：

```bash
securetunnel-gateway peer list --config /etc/securetunnel-gateway/gateway.yaml
securetunnel-gateway peer list --config /etc/securetunnel-gateway/gateway.yaml --json
securetunnel-gateway peer show --config /etc/securetunnel-gateway/gateway.yaml --id peer-xxxxxxxxxxxx
securetunnel-gateway peer status --config /etc/securetunnel-gateway/gateway.yaml --id peer-xxxxxxxxxxxx
securetunnel-gateway peer allocate-ip --config /etc/securetunnel-gateway/gateway.yaml   # 預覽下一個可配發 IP，不建立 Peer
```

Lab 測試情境下如需快速產生一份「Client 設定範本」給測試裝置參考，見第八節「撤銷 Peer」下方的 `peer config` 說明；Gateway **永遠不會**代為產生或儲存 Client 私鑰，即使在 Lab 情境下也一樣（無論任何情境都不提供此功能 — 這是刻意的安全設計，不是尚未完成）。

## 三、建立受保護資源（✅ Phase 4 已實作）

```bash
securetunnel-gateway resource add \
  --config /etc/securetunnel-gateway/gateway.yaml \
  --name "Internal Website" \
  --destination 10.20.0.10 \
  --protocol tcp \
  --port 443 \
  --description "業務部門內部網站" \
  --yes

securetunnel-gateway resource list --config /etc/securetunnel-gateway/gateway.yaml
securetunnel-gateway resource show --config /etc/securetunnel-gateway/gateway.yaml --id resource-xxxxxxxxxxxx
securetunnel-gateway resource disable --config /etc/securetunnel-gateway/gateway.yaml --id resource-xxxxxxxxxxxx --yes
securetunnel-gateway resource remove  --config /etc/securetunnel-gateway/gateway.yaml --id resource-xxxxxxxxxxxx --yes
```

`--destination` 必須是明確的 IPv4 位址或 CIDR（例如 `10.20.0.10` 或 `10.20.0.0/28`），**不支援 hostname**；`--protocol` 只接受 `tcp`/`udp`；過廣的 CIDR（`/8` 或更寬，含 `0.0.0.0/0`）會被拒絕（詳見 [firewall-model.md](firewall-model.md)）。`add`/`enable`/`disable`/`remove` 皆屬安全性敏感操作，需要 `--yes` 或 `--dry-run`。`resource remove` 是**真正刪除**（非軟刪除），與 `peer remove` 的封存語意不同 — 因為 Resource 本身不像 Peer 公鑰帶有「不可重用身分」的風險（見 [firewall-model.md](firewall-model.md) 對此差異的說明）。

## 四、設定存取規則（Peer-to-Resource 授權，✅ Phase 4 已實作）

```bash
securetunnel-gateway policy add \
  --config /etc/securetunnel-gateway/gateway.yaml \
  --peer-id peer-xxxxxxxxxxxx \
  --resource-id resource-xxxxxxxxxxxx \
  --description "Alice 可存取內部網站" \
  --yes

securetunnel-gateway policy list --config /etc/securetunnel-gateway/gateway.yaml
securetunnel-gateway policy disable --config /etc/securetunnel-gateway/gateway.yaml --id rule-xxxxxxxx --yes
securetunnel-gateway policy remove  --config /etc/securetunnel-gateway/gateway.yaml --id rule-xxxxxxxx --yes
```

`--peer-id`/`--resource-id` 必須引用已存在的 Peer/Resource，否則拒絕新增（`ValidationFailure` exit code）；引用一個目前 `Disabled`/`Revoked`/`Removed` 的 Peer，或目前停用的 Resource，會成功新增但附帶警告訊息（提示此規則暫時不會生效），詳見 [firewall-model.md](firewall-model.md#五access-policy-模型已實作allow-only--implicit-deny)。重複的 (Peer, Resource) 授權會被拒絕。設定完 Policy 後，需接著執行 `firewall generate`/`apply`（見第七節）才會真正生效。

## 五、啟動與停止 Gateway

```bash
# Gateway Agent 本身（systemd 管理）
sudo systemctl start securetunnel-gateway
sudo systemctl stop securetunnel-gateway
sudo systemctl status securetunnel-gateway

# WireGuard 介面（✅ 已實作；start/stop/restart 屬危險操作，需 --yes 或 --dry-run）
securetunnel-gateway wireguard start --config /etc/securetunnel-gateway/gateway.yaml --yes
securetunnel-gateway wireguard stop  --config /etc/securetunnel-gateway/gateway.yaml --yes
securetunnel-gateway wireguard restart --config /etc/securetunnel-gateway/gateway.yaml --yes
```

**重要**：`wireguard stop` 只停用 VPN 通道本身；停止 Gateway Agent（`systemctl stop securetunnel-gateway`）**不會**自動清除既有的 nftables 安全規則（見 security-model.md 第六節），避免服務停止時意外造成全部放行。`wg`/`wg-quick` 未安裝時，`start`/`stop`/`restart` 會回傳 `BLOCKED:` 前綴的訊息與非 0 exit code。

`systemctl start/stop securetunnel-gateway` 實際上是啟動/停止 `securetunnel-gateway gateway serve`（Phase 6A 常駐 daemon，見第二十節）——`ExecStart` 已不再是 Phase 6 的佔位指令。`systemctl stop` 送出 SIGTERM，daemon 會優雅結束當前迴圈後 exit 0，同樣**不會**自動清除 nftables 規則。

## 六、查看連線狀態（✅ 已實作）

```bash
securetunnel-gateway wireguard status --config /etc/securetunnel-gateway/gateway.yaml
securetunnel-gateway wireguard show   --config /etc/securetunnel-gateway/gateway.yaml   # 對應原生 `wg show` 完整輸出
```

目前 `status`/`show` 直接反映 `wg show` 的結果（介面 Up/Down/NotConfigured/Unknown 四種狀態）。**Peer 層級的 handshake 時間、傳輸統計、displayName 整理**要等 Phase 3 Peer 管理實作後才會附加中繼資料；本階段 `wg show` 若沒有任何 Peer，只會顯示介面本身的資訊。

## 七、Firewall 驗證、產生與套用（✅ Phase 4 已實作）

```bash
# 純驗證：檢查 Peer/Resource/Policy 引用是否有效，計算 effective rule 數量，不寫檔不套用
securetunnel-gateway firewall validate --config /etc/securetunnel-gateway/gateway.yaml

# 產生 nftables ruleset 檔案（預覽用 --dry-run，實際寫檔需 --force 覆蓋既有檔案）
securetunnel-gateway firewall generate --config /etc/securetunnel-gateway/gateway.yaml --dry-run
securetunnel-gateway firewall generate --config /etc/securetunnel-gateway/gateway.yaml --force

# 完整套用生命週期：產生 → nft 語法驗證 → 套用 → 驗證 table 是否存在（見 firewall-model.md 第六節）
securetunnel-gateway firewall apply --config /etc/securetunnel-gateway/gateway.yaml --yes
securetunnel-gateway firewall apply --config /etc/securetunnel-gateway/gateway.yaml --dry-run   # 只跑到「產生+驗證」，不碰 nft

# 查詢現況
securetunnel-gateway firewall status   # 只回報 table 是否存在
securetunnel-gateway firewall show     # 完整 `nft list table` 原始輸出
```

`firewall apply` 屬安全性敏感操作，需要 `--yes` 或 `--dry-run`。套用失敗時（語法錯誤、`nft -f` 失敗、或套用後驗證不到 table），CLI 輸出會標明「最後成功走到哪一步」（`Generated`/`SyntaxValidated`/`Applied`/`Verified`），且**絕不會**在驗證失敗時仍回報成功 — 即使 `nft -f` 本身的 exit code 是 0。`nft` 未安裝時，`generate`/`validate` 仍可正常運作（純文字產生，不需要 `nft`），只有 `apply`（含其中的語法驗證步驟）與 `status`/`show` 會回報 `BLOCKED:`。
`firewall validate`：對目前 candidate（或指定檔案）做純驗證，不套用，回傳驗證結果與 exit code。

## 八、撤銷 Peer（✅ 已實作）— Disable vs Revoke vs Remove

三個指令語意不同，選錯會有安全或維運上的差異，務必分清楚（完整定義見 [security-model.md](security-model.md#peer-生命週期狀態)）：

| 指令 | 用途 | Peer 紀錄 | VPN IP | 公鑰可否重新使用 | 可否復原 |
|---|---|---|---|---|---|
| `peer disable` | **暫時**停用（例如員工休假、裝置送修） | 保留 | 保留（方便之後 `enable` 拿回同一個 IP） | — | `peer enable` 可復原 |
| `peer revoke` | **永久**、安全驅動的撤銷（例如裝置遺失、員工離職、金鑰外洩） | 保留（供稽核） | **釋放**（可配發給其他 Peer） | **否**，永久封鎖，即使 Remove 後也一樣 | 不可復原（`peer enable` 會被拒絕） |
| `peer remove` | 封存/軟刪除（清理 Peer 清單） | 保留（`Removed` 狀態，非真正刪除，見第 2.1 節設計理由） | 釋放 | 否（同 Revoke 的封鎖規則） | 冪等（對已 Removed 的 Peer 再次執行視為無操作並回報成功） |

```bash
# 暫時停用，之後還會用到
securetunnel-gateway peer disable --config /etc/securetunnel-gateway/gateway.yaml --id peer-xxxxxxxxxxxx --yes

# 之後要恢復
securetunnel-gateway peer enable --config /etc/securetunnel-gateway/gateway.yaml --id peer-xxxxxxxxxxxx --yes

# 永久撤銷（裝置遺失/離職/金鑰外洩）
securetunnel-gateway peer revoke --config /etc/securetunnel-gateway/gateway.yaml --id peer-xxxxxxxxxxxx --yes

# 清理（軟刪除，不影響稽核紀錄）
securetunnel-gateway peer remove --config /etc/securetunnel-gateway/gateway.yaml --id peer-xxxxxxxxxxxx --yes
```

三者都：
- 需要 `--yes`（或 `--dry-run` 預覽）才會執行，屬安全性敏感操作。
- 只更新 Peer Registry；要讓變更對正在執行的系統生效，接著執行 `securetunnel-gateway config apply --yes`（✅ Phase 5：同時處理 WireGuard 與 nftables，見第十三節）。
- `config apply` 會同時重新產生並套用 nftables 規則——撤銷的 Peer 在下一次 `config apply` 後會同時從 WireGuard 與 nftables 兩層消失（見 [security-model.md](security-model.md) 第八節）。

**狀態轉換限制**（拒絕不合法的轉換，全部 fail-closed）：`enable` 只能從 `Pending`/`Disabled` 執行；`disable` 只能從 `Pending`/`Active` 執行；`revoke` 可從 `Pending`/`Active`/`Disabled` 執行；`remove` 可從任何非 `Removed` 狀態執行。嘗試不合法的轉換（例如對已 `Revoked` 的 Peer 執行 `enable`）會回傳清楚的錯誤訊息與非 0 exit code，不會靜默成功。

## 八 B、產生 Client 設定範本（✅ 已實作）

```bash
securetunnel-gateway peer config --config /etc/securetunnel-gateway/gateway.yaml --id peer-xxxxxxxxxxxx
# 存成檔案：
securetunnel-gateway peer config --config /etc/securetunnel-gateway/gateway.yaml --id peer-xxxxxxxxxxxx --output alice.conf
```

輸出是一份**範本**（`.conf` 內容），`PrivateKey` 欄位固定是 `<INSERT_CLIENT_PRIVATE_KEY_HERE>` 佔位字串 — Gateway 從未產生、持有或詢問 Client 私鑰。操作者需要把這份範本交給使用者，由使用者（或操作者在裝置本機上）用 `wg genkey` 產生私鑰後手動填入才能使用。若 `wireGuard.endpointHost` 未設定，`Endpoint` 也會是 `<GATEWAY_PUBLIC_ENDPOINT>` 佔位字串。若 Server 尚未產生金鑰（見 [installation-guide.md](installation-guide.md) Step 4），此指令會回報 `BLOCKED`，不會用假資料頂替。三種「設定」的區別（Server peer configuration / Client 設定範本 / 完整可用設定）見 [configuration-guide.md](configuration-guide.md#27-三種設定的區別重要)。

## 九、處理錯誤

1. 先執行 `securetunnel-gateway health --config <path>` 確認整體狀態（Healthy/Degraded/Unhealthy/Unknown）。✅ 已實作。
2. 若為 Degraded/Unhealthy，執行 `securetunnel-gateway doctor --config <path>` 取得完整的環境檢查與 health 分項結果（涵蓋原本規劃的 `diagnostics` 指令內容；獨立的 `diagnostics` 指令是否還需要另外提供，留待 Phase 6 評估）。✅ 已實作。
3. 查看 `logging.applicationLogPath`（一般錯誤）與 `logging.auditLogPath`（設定變更/安全事件）— ⏳ 尚未接上檔案 sink，目前 log 只會輸出到 Console（stdout/stderr）。
4. 常見問題與對應排解步驟見 [troubleshooting.md](troubleshooting.md)。

## 十、備份設定（✅ Phase 6：`gateway backup` 已取代手動 tar 流程）

```bash
securetunnel-gateway gateway backup create --config /etc/securetunnel-gateway/gateway.yaml
securetunnel-gateway gateway backup        --config /etc/securetunnel-gateway/gateway.yaml   # 未帶子指令時等同 create
securetunnel-gateway gateway backup create --config /etc/securetunnel-gateway/gateway.yaml --output /path/to/my-backup.tar.gz
securetunnel-gateway gateway backup create --config /etc/securetunnel-gateway/gateway.yaml --dry-run   # 只預覽會包含哪些檔案，不寫入
securetunnel-gateway gateway backup list   --config /etc/securetunnel-gateway/gateway.yaml
```

備份內容涵蓋 `gateway.yaml`、`peers.json`、`resources.json`、`policies.json`、`config-history.json`、`keys/server.key`、`keys/server.pub`（存在的才會被納入；不存在的檔案不會導致失敗，只是不出現在 manifest 中）。封裝格式為 tar+gzip，內含一份 `manifest.json`（`SchemaVersion`、`CreatedAtUtc`、`GatewayId`、`ContentSha256`、`IncludedFiles`），`ContentSha256` 是對「檔名+內容雜湊」排序後計算的複合雜湊，供 `gateway restore` 驗證封存包是否完整、未被竄改。預設輸出到 `backupDirectory`（預設 `/var/lib/securetunnel-gateway/backups`，見 [configuration-guide.md](configuration-guide.md)），檔名帶時間戳記；也可用 `--output` 指定明確路徑。

**備份檔案內容包含 WireGuard 私鑰**——建立時會自動設定 `0600` 權限（Linux），但備份檔案的**存放與傳輸安全**仍是操作者責任，不可放在一般共享目錄或提交到 Git，比照 [security-model.md](security-model.md) 的私鑰保護要求。

## 十一、復原設定

```bash
# 情境 A：Gateway 設定邏輯本身沒問題，只是想回到較早的版本（✅ Phase 5，Registry 未毀損時的首選）
securetunnel-gateway config list                              # 先找出要回滾到哪個版本
securetunnel-gateway config rollback --version 4 --yes

# 情境 B：Registry 檔案本身毀損或遺失，需要從備份還原（✅ Phase 6）
securetunnel-gateway gateway restore --config /etc/securetunnel-gateway/gateway.yaml --file /path/to/backup.tar.gz --dry-run   # 先預覽
securetunnel-gateway gateway restore --config /etc/securetunnel-gateway/gateway.yaml --file /path/to/backup.tar.gz --yes       # 實際還原
securetunnel-gateway config apply    --config /etc/securetunnel-gateway/gateway.yaml --yes                                     # 還原後必須手動套用，見下方說明
```

`gateway restore` **絕不會自動套用**還原的資料——它只把 Registry/History/金鑰檔案寫回磁碟（這些是「Desired」輸入），從不觸碰 Active/WireGuard/nftables 的實際生效狀態，也不會自己呼叫 `config apply`；操作者必須自行決定並手動執行 `config apply` 讓還原的資料生效（見第十九節）。還原前一律先重新計算封存包的 `ContentSha256` 並與 manifest 比對，雜湊不符（毀損或遭竄改）會直接拒絕、不寫入任何檔案。還原也**不會**默默覆蓋既有資料——每個被取代的既有檔案都會先備份為 `{原路徑}.pre-restore-{timestamp}`，不會遺失還原前的狀態。未加 `--yes`（且未加 `--dry-run`）會直接拒絕執行。

`config rollback` 的完整行為見第十四節。

## 十三、`config apply` 完整流程（✅ Phase 5 已實作）

這是日常操作中**最常用**的指令——新增/停用 Peer、新增/停用 Resource 或 Policy 之後，用這一個指令就能同時把 WireGuard 與 nftables 都套用到最新狀態，並記錄可回溯的版本：

```bash
# 先預覽（不套用、不寫入版本歷史）
securetunnel-gateway config apply --config /etc/securetunnel-gateway/gateway.yaml --dry-run
# 等同於：
securetunnel-gateway config validate --config /etc/securetunnel-gateway/gateway.yaml

# 實際套用
securetunnel-gateway config apply --config /etc/securetunnel-gateway/gateway.yaml --yes

# 查看結果
securetunnel-gateway config status --config /etc/securetunnel-gateway/gateway.yaml
securetunnel-gateway config verify --config /etc/securetunnel-gateway/gateway.yaml   # 查「實際」系統狀態，不是 history 記錄
```

`config apply` 內部依序執行（詳見 [architecture.md](architecture.md#六configuration-生命週期已實作lifecycleconfigurationlifecycleservice)）：讀取目前 Peer/Resource/Policy → 驗證 → 建立不可變快照（新版本號）→ 取得單一寫入者鎖 → 套用 WireGuard（寫設定檔 + `wg-quick restart`）→ 套用 nftables（完整重用 `firewall apply` 的邏輯）→ 驗證兩者實際狀態 → 只有兩者都確認生效才標記為 `Active`。

**任何一步失敗都不會讓舊的 Active 版本消失**：
- WireGuard 套用失敗 → nftables 完全不會被觸碰，新版本標記 `ApplyFailed`，舊 Active 版本仍在生效。
- WireGuard 成功但 nftables 失敗 → 標記 `EffectiveStateUnknown`（詳見 [architecture.md](architecture.md) 對「部分失敗」的說明，這個狀態雖然名稱嚇人，但實際上不會造成意外放行）。
- 兩者都套用成功但驗證查不到（`wg show`/`nft list table` 沒反映預期狀態）→ 標記 `VerificationFailed`/`EffectiveStateUnknown`，同樣不標記 Active。

失敗時，用 `config show --version <n>` 查看該版本的 `failureReason` 欄位了解詳情，用 `config verify` 確認系統實際狀態後再決定下一步（重新 `config apply`，或 `config rollback` 到已知良好版本）。

## 十四、`config rollback` 完整流程（✅ Phase 5 已實作）

```bash
securetunnel-gateway config list                       # 找出想回滾的版本號
securetunnel-gateway config show --version 4            # 先看看那個版本長什麼樣子
securetunnel-gateway config rollback --version 4 --dry-run   # 預覽
securetunnel-gateway config rollback --version 4 --yes       # 實際回滾
```

**重要行為**：
- 只能回滾到**曾經成功**（`Active`/`Verified`/`RollbackSucceeded`）的版本；回滾到一個當初驗證失敗或套用失敗的版本會被拒絕，避免把系統帶回一個從未真正生效過的狀態。
- 回滾使用**目標版本自己內嵌的快照資料**（該版本產生當下的 Peer/Resource/Policy 完整副本），**不會**讀取目前的即時 Registry——即使你在 v4 之後又新增了 Peer，回滾到 v4 也只會恢復 v4 當時的內容，不會意外保留之後新增的 Peer。
- 回滾成功會建立一個**新**版本號（例如從 v6 回滾到 v4，會產生 v7，內容等同 v4），而不是把 history 改回 v4——版本歷史永遠只增不改。
- 回滾同樣需要 `--yes` 或 `--dry-run`，且套用/驗證邏輯與 `config apply` 完全相同（同樣可能遇到部分失敗，處理方式相同）。

## 十五、Crash Recovery 與中斷操作偵測（✅ Phase 5 已實作）

如果 `config apply`／`config rollback` 執行到一半（例如系統斷電、行程被強制終止），下次執行 `config status` 會明確標示：

```bash
securetunnel-gateway config status --config /etc/securetunnel-gateway/gateway.yaml
# [WARNING] Version 5 was left in state 'Applying' - the Gateway Agent process was likely
# interrupted mid-operation (started 2026-09-23T10:00:00Z). Effective system state cannot
# be assumed from this alone; run `config verify` to check actual WireGuard/nftables state,
# then `config apply` or `config rollback <last known good version>` as appropriate.
```

**不會**自動假設中斷的操作是成功或失敗——這需要操作者用 `config verify` 主動確認實際系統狀態，再決定要重新 `config apply` 還是 `config rollback` 到已知良好版本。

**Phase 6A 更新**：這段偵測邏輯現在也會在 `gateway serve`（常駐 daemon，見第二十節）開機時與之後每個檢查週期自動重新執行，訊息會直接寫入 journald，不需要操作者手動呼叫 `config status` 才會發現。但即使 daemon 偵測到中斷操作，也**只會**記錄警告、把整體狀態標記為 `Blocked`（daemon 自己的分類，見第二十節）——絕不自動 `config apply`/`config rollback`，最終決定永遠留給操作者。

## 十七、日誌（Logging，✅ Phase 6 已定案）

Gateway Agent **不**提供自訂檔案 log sink（先前文件曾提到的 `logging.applicationLogPath`/`auditLogPath` 檔案落地已確定不會實作）。日誌全面委由 journald：systemd unit（`deploy/systemd/securetunnel-gateway.service`）設定 `StandardOutput=journal`、`StandardError=journal`、`SyslogIdentifier=securetunnel-gateway`，所有 Serilog Console 輸出都會被 journald 擷取並附上時間戳記、優先權等中繼資料。

```bash
journalctl -u securetunnel-gateway                # 查看全部日誌
journalctl -u securetunnel-gateway -f              # 即時追蹤
journalctl -u securetunnel-gateway --since today
journalctl -u securetunnel-gateway -p err          # 只看 error 等級以上
```

選擇委由 journald 而非自建 log sink的理由：日誌輪替（rotation）、持久化、跨開機保存等問題 journald 都已解決，自建 sink 只會重複造輪子且更容易在權限/磁碟空間問題上出錯。

## 十八、Diagnostics and Status — `gateway status`（✅ Phase 6 已實作）

```bash
securetunnel-gateway gateway status --config /etc/securetunnel-gateway/gateway.yaml
securetunnel-gateway gateway status --config /etc/securetunnel-gateway/gateway.yaml --json
```

`gateway status` 把四個原本要分別查詢的問題合併成一次呼叫：Configured（設定檔是否能載入）、Desired（Registry 目前內容是否已 apply）、Active（版本歷史記錄的狀態）、Effective（WireGuard/nftables 實際生效狀態）。輸出的 `overallStatus` 依下列**明確優先順序**計算（越前面優先權越高，第一個符合的條件就決定結果，不會被後面的條件覆蓋）：

1. 偵測到中斷的操作（`DetectIncompleteOperationAsync` 非 null，例如上次 `config apply`/`rollback` 執行到一半就中斷）→ `Unknown`（我們真的不知道目前實際狀態，見第十五節）
2. `health` 回報 `Unhealthy` → `Failed`
3. `wg`/`nft` 指令本身不存在（health item 為 `wireguard-command`/`nftables-command` 且狀態 `Blocked`）→ `Blocked`
4. Desired 與 Active 不一致（`desiredStale = true`，即 Registry 目前內容的雜湊與 Active 版本快照的 `ContentHash` 不同）**或** `health` 為 `Degraded` → `Degraded`
5. 以上皆非 → `Healthy`

JSON 輸出欄位：`desiredStale`（Registry 是否已有尚未 `config apply` 的變更，由 `IsDesiredStaleAsync` 計算，比較即時 Registry 雜湊與 Active 快照的 `ContentHash`，不需要跑 `config diff` 就能知道有沒有漂移）、`activeVersion`/`lastKnownGoodVersion`（版本歷史指標）、`effective.{WireGuardUp,FirewallTablePresent,EffectiveStateKnown}`（`config verify` 的即時查詢結果）、`incompleteOperation`（中斷操作偵測訊息，正常時為 null）、`health`/`healthItems`（完整 health check 分項）。

## 十九、Upgrade and Operational Rollback（✅ Phase 6）

三種各自獨立、互不影響的「回復」機制，操作前先確認自己遇到的是哪一種問題：

| 情境 | 使用機制 | 影響範圍 |
|---|---|---|
| 想升級/降級 Gateway Agent 執行檔本身版本 | 重新發佈 + `sudo ./scripts/install.sh --publish-dir <新版輸出目錄>`（見 [installation-guide.md](installation-guide.md)） | 只取代 `/usr/lib/securetunnel-gateway` 執行檔與 systemd unit；`/etc`、`/var/lib` 下所有設定與狀態完全不受影響（`install.sh` 冪等、從不刪除既有 Registry/History/金鑰） |
| Gateway 邏輯設定（Peer/Resource/Policy）想回到較早版本 | `config rollback --version <n>`（Phase 5，見第十四節，行為未變） | 只影響 Registry 內容與 Active 指標，使用該版本自身內嵌的不可變快照，不需要備份檔案 |
| WireGuard/nftables「實際生效狀態」與預期不符，或 Registry 檔案本身毀損 | 先用 `config verify` 診斷（查即時系統狀態），Registry 毀損時用 `gateway restore` 從備份復原（見第十一節），復原後手動 `config apply` 重新套用 | 依診斷結果而定；`gateway restore` 從不自動套用，`config verify` 完全唯讀 |

這三者刻意保持獨立：二進位升級不該牽動設定歷史，設定回滾不該需要備份檔案，而備份還原也不該被誤認為「已經生效」——見第十一節對 `gateway restore` 「絕不自動套用」的說明。

## 二十、Gateway Daemon — `gateway serve`（✅ Phase 6A 已實作）

Phase 6 的 systemd unit 原本只是把 `config status` 當佔位指令執行一次就結束；Phase 6A 補上真正的常駐執行模式：

```bash
# 前景執行（除錯/直接觀察用）：
securetunnel-gateway gateway serve --config /etc/securetunnel-gateway/gateway.yaml

# 自訂檢查週期（預設 60 秒）：
securetunnel-gateway gateway serve --config /etc/securetunnel-gateway/gateway.yaml --interval-seconds 30

# 只跑一次啟動診斷就結束，不進入常駐迴圈（腳本化驗證/測試用，systemd 不會用這個模式）：
securetunnel-gateway gateway serve --config /etc/securetunnel-gateway/gateway.yaml --once

# 實際部署：透過 systemd（ExecStart 已指向 gateway serve，見 installation-guide.md）
sudo systemctl start securetunnel-gateway
sudo systemctl stop securetunnel-gateway   # 送出 SIGTERM，daemon 優雅結束
```

**daemon 在做什麼**：啟動時（之後每個週期重複一次）依序執行——載入並驗證設定 → Phase 5 crash-recovery 偵測（`DetectIncompleteOperationAsync`）→ 檢查 `wg`/`nft` 是否可用 → 檢查金鑰可用性/權限 → 檢查設定驗證結果 → `config verify`（Effective 狀態是否可判定）→ `IsDesiredStaleAsync`（Desired 是否已落後 Active）。全部沿用 Phase 5/6 既有的 `IConfigurationLifecycleService`/`IHealthCheckService`，沒有另外實作一套平行邏輯。

**daemon 自己的四種狀態**（與 `gateway status` 的 Healthy/Degraded/Blocked/Failed/Unknown 五種狀態刻意不同，見下方說明）：

| 狀態 | 觸發條件 | daemon 的行為 |
|---|---|---|
| `Failed` | 設定檔完全無法載入（YAML 語法錯誤/檔案不存在），或啟動診斷本身丟出未預期例外 | **process 結束，exit code 非 0**，不進入迴圈 |
| `Blocked` | 偵測到中斷操作、`wg`/`nft` 指令不存在、金鑰不可用或權限不安全、設定驗證失敗、必要 OS 權限不足、Effective 狀態無法判定 | process **繼續執行**，每個週期重複記錄同一個 Blocked 原因到 journald，直到操作者處理好問題（不會自我了斷去讓 systemd `Restart=on-failure` 重開機） |
| `Degraded` | Desired 已落後 Active（`desiredStale = true`），或 health check 有 Warn 等級項目 | process 繼續執行，記錄提醒（例如「有變更尚未 apply」） |
| `Healthy` | 以上皆非 | process 繼續執行，正常記錄 |

> **為什麼 `Blocked` 不會讓 process 結束**：這是刻意的設計選擇，與 Phase 6A 原始規格文字的字面表述（把「設定驗證失敗」歸在 Blocked、但又把「fatal initialization error」定義為 Failed）有些微落差——本專案選擇重用既有的 `IHealthCheckService`/`IConfigurationLifecycleService` 抽象、不另外發明第二套分類邏輯，並且優先避免「設定一時錯誤就讓 systemd 進入 crash-loop」。只有「連設定檔都讀不到」或「完全未預期的例外」才會被視為真正無法運作而結束 process。

**`--once` 的 exit code**：`Healthy`/`Degraded` → 0；`Blocked`/`Failed` → 非 0。這讓 `--once` 可以直接用在腳本或 CI 驗證裡（`gateway serve --config ... --once && echo OK`），不需要另外解析輸出。

**與 `gateway status` 的關係**：兩者完全獨立，彼此不通訊——daemon 不開放任何網路連接埠或 IPC 通道（刻意不做 Control Plane / Admin API），操作者隨時可以另外執行 `gateway status` 查詢，讀的是同一份磁碟上的設定/Registry/History/WireGuard 狀態，daemon 正在跑或沒在跑都不影響 `gateway status` 的查詢結果。

**Registry 變更後仍需要手動 `config apply`（Option A）**：即使 daemon 正在跑，Peer/Resource/Policy 變更之後 Desired 落後 Active 時，daemon 只會在日誌裡記錄警告（`Degraded`），**絕不**自動呼叫 `config apply`/`config rollback`。這是本階段刻意的取捨：避免任何形式的無人值守自動生效路徑（原規格文件列出的 Option B——由 daemon 提供一個受控的本地觸發器——留待未來視實際需求再評估）。

**優雅關閉**：SIGINT（Ctrl+C，前景執行時）與 SIGTERM（`systemctl stop` 送出的訊號）都會觸發同一套關閉流程——結束目前迴圈、記錄「daemon stopped gracefully」、exit code 0。不會有任何安全設定因為關閉流程而被意外放寬或清除（daemon 關閉不會觸碰 nftables 規則，見第五節）。

**已驗證方式**：`tests/DaemonTests`（15 個 xUnit 測試）針對啟動分類的四種狀態、crash recovery 各種情境（中斷 apply/rollback、Effective 狀態不明、history 讀取失敗、Active 快照遺失）、迴圈的取消/優雅關閉/週期間隔/暫時性例外容錯、以及「日誌絕不外洩金鑰內容」都有覆蓋，並在真實 WSL2 Ubuntu 24.04 上以自我包含（self-contained）`linux-x64` 發佈檔實際執行過 `gateway serve --once`，正確判定並記錄 `Blocked`（`wireguard-tools`/`nftables` 未安裝）。真實 exit code 語意由 xUnit 測試套件驗證（見上方 exit code 說明），而非透過巢狀 `wsl.exe` 呼叫觀察——後者的 `$?` 傳遞在本專案已知不可靠（見 [troubleshooting.md](troubleshooting.md)），並非 daemon 本身的問題。

## 十六、Known Limitations

- ✅ **（Phase 6 已解決）** 先前規劃的獨立 `diagnostics` 指令確定不會提供；其用途已由 `gateway status`（第十八節）整合覆蓋。
- ✅ **（Phase 5 已解決）** Peer/Resource/Policy 變更不再需要手動分別執行 `config generate`/`wireguard restart`/`firewall generate`/`firewall apply` 四個指令——現在 `config apply` 一個指令就會依序完成全部步驟並記錄可回溯版本。`config generate`（Phase 2 遺留的窄範圍工具）與 `firewall apply`（Phase 4，只管 nftables 那一半）仍然存在，供需要單獨操作某一層的情境使用，但日常操作建議一律用 `config apply`。
- **Registry 並發（Peer/Resource/Policy 三個 JSON 檔案本身）**：仍然各自無跨行程鎖定，兩個同時執行的 `peer`/`resource`/`policy` 指令仍可能互相覆蓋（這與 `config apply`/`config rollback` 的單一寫入者鎖是不同層級的保護——後者只保護「套用」這個動作不被並發執行，不保護 Registry 檔案本身的並發寫入）。見 [configuration-guide.md](configuration-guide.md#23-persistence-設計原子寫入與失敗處理)。
- **`config apply`/`config rollback` 的單一寫入者鎖只保護單一 Gateway 主機**，不是跨機器/分散式鎖（本專案本來就是單 Gateway 設計，見 architecture.md）。
- **`peer status` 的 handshake 資訊不落地**：只在指令執行當下即時查詢 `wg show` 做字串比對，不會回寫到 Peer Registry 的 `lastHandshakeAtUtc` 欄位。
- **`config apply`/`firewall apply` 的真實套用與驗證維持 BLOCKED**：WSL2 未安裝 `wireguard-tools`/`nftables`；規則產生與語法驗證的程式路徑已在真實 Linux 驗證過，見 [testing-guide.md](testing-guide.md)。
- **不支援 ICMP、hostname 型 Resource、Deny 規則**：刻意設計，理由見 [firewall-model.md](firewall-model.md#九known-limitationsfirewall-層面)。
- ✅ **（Phase 6A 已解決）** ~~Crash Recovery 是被動偵測，不是常駐 daemon 的自動修復~~ —— `gateway serve`（第二十節）現在是真正的常駐 daemon，開機與之後每個週期都會自動重跑 crash-recovery 偵測並寫入 journald；不過即使偵測到問題，daemon 仍然只記錄、從不自動 `apply`/`rollback`（見第二十節）。
- **備份不會自動排程**：`gateway backup` 需要操作者或 cron 主動觸發，`gateway serve`（第二十節）目前不內建備份排程器（刻意的設計取捨，避免 daemon 擁有寫入/覆蓋備份目錄的自動化路徑；見 Phase 6A 完成報告 Not Implemented）。
- **`scripts/install.sh`/`scripts/uninstall.sh` 未以真正的 root 身份完整執行過**：WSL2 開發環境無 sudo、無真正的系統安裝目標；已完成程式碼審閱、`bash -n` 語法檢查，以及兩支腳本自身 `--dry-run` 模式在真實 WSL2 Ubuntu 24.04 上的實際執行驗證。**（Phase 7）** `uninstall.sh` 新增的範圍精確 nftables/WireGuard 介面清理（見 [installation-guide.md](installation-guide.md#安裝解除安裝腳本)、security-model.md 第二十節）同樣只驗證到 `--dry-run` 路徑與 `interfaceName` 解析邏輯，尚未在真實安裝、真實 `nft table` 存在的情況下端到端驗證。
- **（Phase 7）真實 Ubuntu Server 端到端整合驗證**：`test-lab/run-integration-tests.sh` 是一支已撰寫、涵蓋 WireGuard 介面建立、Peer 設定、nftables table/chain 建立、default-deny、`config apply`/`rollback`、daemon 啟動與優雅關閉、systemd restart（15 項規格檢查中的多數）的可執行腳本，但**尚未在真實 Ubuntu Server 上執行過**（本開發環境缺 `wireguard-tools`/`nftables`）——見 `test-lab/README.md` 與 [testing-guide.md](testing-guide.md)。其中最複雜的封包層級授權/NAT 驗證（`--with-packet-flow-test`）預設關閉。
- **`gateway serve` 未透過真實 `systemctl start`/`stop` 生命週期驗證過**：同樣受限於 WSL2 開發環境無 sudo、無系統安裝目標；已驗證的是（a）unit 檔案語法/邏輯的 `systemd-analyze verify`（真實通過）與（b）daemon 本身在真實 Linux（WSL2 Ubuntu 24.04）上以已發佈的 `linux-x64` 執行檔直接執行 `gateway serve --once` 的啟動與記錄行為（真實通過），但沒有透過 systemd 本身啟動/停止過這個 process。
