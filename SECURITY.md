# Security Policy

## 回報安全性問題

如果你在 SecureTunnel Gateway 中發現安全性問題（例如：Firewall 規則可被繞過、私鑰可能外洩、設定驗證可被繞過造成危險設定被套用等），**請不要開 public issue**。

請透過專案維護者指定的私下管道回報（例如私訊或內部安全信箱，實際聯絡方式由專案維護者於正式發佈時補充），並盡可能提供：

- 問題描述與重現步驟
- 受影響的版本/commit
- 可能的影響範圍
- 你的建議修復方向（若有）

## 範圍

本專案目前僅涵蓋 **VPN Gateway / VPN Server** 本身（WireGuard、nftables、Gateway Agent、相關腳本與設定）。不涵蓋：

- 尚未開發的 Client 應用程式
- 尚未開發的 Control Plane / Admin Portal
- 使用者自行部署的「受保護資源」本身的應用層安全性

## 已知安全設計與限制

詳見 [docs/security-model.md](docs/security-model.md) 與 [docs/threat-model.md](docs/threat-model.md)，其中列出目前已處理的威脅類別與尚未處理的 Known Limitations。**本專案未取得任何正式安全認證**，文件內容是工程設計說明，不是合規保證。

## supported versions

本專案目前處於早期開發階段（Phase 1），尚無穩定發行版本，暫不提供正式的版本支援矩陣。
