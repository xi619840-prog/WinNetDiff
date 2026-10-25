# WinNetDiff

已完成最後 GUI 修正，一般匯出直接去識別化；**完整資料…** 需要重新勾選風險確認並主動匯出，Enter／Esc／關閉視窗均取消。缺少儲存資料夾時須自行選擇，取消／失敗／未完成診斷有明確提示。[本輪驗收與限制](docs/gui-final-2.2.0a3.md)。

**原始碼 Alpha 預覽候選（尚未公開）。** Windows EXE／正式 Release 仍被門禁阻止：受控代理修改／復原及乾淨 Windows 11 VM 尚未驗收，修復功能不得視為適用於正式環境。[2.2.0a3 證據](docs/gui-final-2.2.0a3.md) · [原始碼公開清單](docs/source-alpha-publication.md) · [驗證狀態](docs/validation.md)。


![啟動畫面](docs/images/startup-en-2.2.0a3-gui-final.jpg)

本輪實際 2.2.0a3 Windows 啟動畫面，英文介面，使用隔離設定。尚未掃描，不含真實裝置報告或私人路徑。

WinNetDiff 由 **Alden** 署名，透過代理、路由、雙棧、TCP/TLS/HTTP 與網路過濾元件的差分證據，協助定位 Windows 網路問題。它是診斷輔助工具，不保證自動定位或修復所有故障。

[English 完整說明](README.md) · [简体中文完整说明](README.zh-CN.md) · [隱私](PRIVACY.md) · [操作風險與回復](docs/safety-model.md)

## 啟動與語言

需要 Windows 10/11、Python 3.10+，GUI 另需 Tcl/Tk；沒有第三方 Python 執行期相依套件。

```powershell
py -3 windows_net_diffdiag.py --lang zh-TW
py -3 -m winnetdiff --lang zh-TW
py -3 windows_net_diffdiag.py --cli --lang zh-TW --no-network
py -3 windows_net_diffdiag.py --cli --lang zh-TW --profile global
```

English、简体中文、繁體中文可在介面選擇。語言會建議對應的測試目標設定，使用者仍能獨立切換設定或輸入自己的網域；已自訂的目標不會被語言切換覆寫。唯讀本機稽核可離線執行，本機代理檢查仍會使用回送位址。

普通模式顯示主要發現與下一步，專家模式提供階段耗時與原始證據。快照可比較新增、移除、啟用、停用與設定變化。修復後以相同目標和參數重新驗證，沒有改善時會標示未驗證有效。

## 安全與驗收

預設不提權、不修改系統、不上傳資料。符合條件的使用者代理修復與回復須逐次確認並備份；無法可靠回復的 DNS 快取清除預設只提供人工指引。驅動、安全中心與網卡綁定沒有通用的一鍵清理功能。

報告與快照預設去識別化，完整報告和 WFP XML 需明確確認。分享前仍須人工檢查，勿公開私密備份。EXE 若未標示簽章即屬未簽署，請核對來源與 SHA-256，不要無條件忽略安全警告。

目前為 **2.2.0a3** 預覽版。模擬測試、Windows Runner、Windows 11 GUI 與實際系統修復的驗證狀態分開記錄，見[驗收狀態](docs/validation.md)。尚未自動公開 GitHub 倉庫或 Release。

Copyright (c) 2026 **Alden**。採用 [MIT License](LICENSE)，不公開本名或私人電子郵件。


## 選用診斷（自 2.2.0a2 引入）

Fake-IP／DNS 稽核結合目標位址的最長前綴路由、活動介面、DNS 設定、已知代理核心程序與實際探針結果。正常 TUN 映射屬於預期模式，不能僅因命中 `198.18.0.0/15` 就稱 DNS 污染；私有與本機 DNS 也可能正常。缺少可用目標路由、TCP 失敗且未觀察到已知核心時才回報「疑似殘留」。離線模式保留設定線索與未驗證項。

PMTU 按鈕僅在同一 IPv4 位址重複 TLS 逾時後可用，仍需單獨同意。記錄 ICMP 負載與估計 IPv4 封包大小。「需要分片」表示回饋已返回；靜默或大小差異不能確診黑洞，也不會修改 MTU、MSS 或登錄設定。

「複製精簡診斷卡」先顯示預覽，再由使用者按下複製。卡片僅使用固定類別、列舉、版本與數值耗時，排除原始名稱、位址、網域、URL、錯誤與動態診斷文字。最終字串實際檢查 **≤500 字元**，不保證絕對匿名，請先審閱；不會自動上傳。

```powershell
py -3 windows_net_diffdiag.py --cli --no-network --share-card
py -3 windows_net_diffdiag.py --cli --no-network --no-fake-ip-audit
py -3 windows_net_diffdiag.py --cli --pmtu --confirm-pmtu
```

語言、目標設定與稽核開關互不重設。`--fake-ip-audit` 明確啟用稽核；一般掃描不自動追加 PMTU。CLI 儲存預設拒絕覆蓋；GUI 明確確認後才原子替換。README 使用本輪 2.2.0a3 的真實啟動截圖。


本輪聯合審查證據與限制： [2.2.0a2 integration](docs/combined-review-2.2.0a2.md).

## 2.2.0a3 F5 / F6 / F7

通用宿主關聯、企業 HTTP 代理路徑診斷與固定同一 IP 重試已實作。預設固定地址；可用 --retry-mode rotate 輪替 DNS 位址。代理實測需要 --proxy-paths --confirm-proxy-paths 與連線 CLI 診斷。WFP 匯入只作為歷史關聯資料。[命令、證據與限制](docs/f567-2.2.0a3.md)。
