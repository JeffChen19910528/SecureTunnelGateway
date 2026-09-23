# Contributing

感謝你對 SecureTunnel Gateway 有興趣。本專案目前處於早期開發階段（Phase 1: Documentation and Architecture），開發依 [docs/architecture.md](docs/architecture.md#十五開發階段phase-08對應架構模組) 定義的 Phase 0–8 順序進行。

## 開發原則

1. **Data Plane 與 Management Plane 分離**：WireGuard / nftables / routing（Data Plane）不放進一般 Docker Container，一律在 Linux Host 執行；Gateway Agent（Management Plane）以 systemd service 執行。詳見 [docs/architecture.md](docs/architecture.md)。
2. **Fail-closed 優先**：任何設定錯誤、套用失敗、服務重啟，都不得導致受保護資源被全部放行。新增功能時，先想清楚失敗路徑（failure path）會落在什麼狀態。
3. **不自行實作加密協定**：VPN 加密完全交由 WireGuard 處理，不修改或重新實作其協定邏輯。
4. **不得將測試結果誇大**：Unit test 通過不等於真實網路驗證通過。未執行或無法執行的測試，必須標記為 `BLOCKED` 並附上原因，不得寫成 `PASSED`。詳見 [docs/testing-guide.md](docs/testing-guide.md)。
5. **敏感資料處理**：私鑰、token、密碼絕不進入一般 log、error 訊息或版本控制。提交前請對照 [docs/security-model.md](docs/security-model.md#十log-與敏感資料) 與 [.gitignore](.gitignore) 自我檢查。
6. **Shell 指令安全**：呼叫 `wg`/`wg-quick`/`nft`/`ip` 等外部指令一律使用參數化呼叫，不得用字串組合後交給 shell 執行，避免 command injection。

## 提交前檢查

- 是否有任何私鑰、真實設定檔（非 `.example`）、憑證被加入變更？
- 是否新增了會執行危險操作（開放全部流量、跳過驗證）的程式碼路徑？
- 是否更新了對應的文件（架構變更需同步 `docs/architecture.md`，設定欄位變更需同步 `docs/configuration-guide.md`）？
- 涉及重大架構決策（Routed vs NAT Mode、Container vs Host Service、root 權限模型變更等）是否已先與專案負責人確認？依原始開發流程要求，這類決策不應單方面決定。

## 目錄慣例

見 [README.md](README.md#專案結構) 的專案結構說明；新增檔案請放入對應既有目錄，避免建立未在架構文件中說明的新頂層目錄。
