# WinNetDiff 2.2.0a1 增量開發與驗證報告

日期：2026-10-25。公開作者：Alden。此為原 WinNetDiff 倉庫的增量開發與本機候選交付，**正式發行門檻仍未解除**。

## 1. P0／P1 修復狀態

本輪先完整解壓附件，依序讀取 00、01、02、03 與原始設計參考。新增任務書是執行依據；Gemini 原始補丁未直接合併。其先前審查不是對本輪工作樹的實測結果。

開始前已重新執行既有完整套件，**270 項通過**，生成來源檢查也通過。工作內容保留於 `rollback/pre-extensions-2.1.0b2-20261025`，提交 `7a814d45c8b8917937790dee2f789305a68b90d0`。使用獨立暫存索引保存完整工作內容，原 Git 暫存區未改動，沒有 reset、clean 或覆蓋舊交付。

代理恢復、Windows API、共用脫敏與代理蒐集四個核心檔案，已用實際檔案內容對比回滾提交，均相同。原 P0 語義 CAS、受支援 WinINET API、策略／端點衝突保護、日誌階段、整體與階段逾時分離、精確翻譯及隱私回歸全部保留。傳輸模組僅增加完整解析位址證據；未退回 Gemini 舊旗標比較或舊 blob 寫入方式。

本輪另修正匯出一致性。GUI 報告、歷史與差分匯出新增明確覆蓋確認及原子儲存；CLI 報告與比較輸出也預設拒絕覆蓋。語言切換保留 Fake-IP 開關；設定與 UAC 參數明確帶入該選擇。舊精確參數斷言補上新欄位，原斷言未刪除或放寬。

**獨立 14 項紅隊腳本與本次附件 reference 完全同位元組**。它真正呼叫 restore_proxy，並驗證計數器變動可恢復、真實端點變動拒絕覆蓋。沒有把舊歷史日誌當成本輪驗收。

## 2. 新功能與測試矩陣

| 範圍 | 已落地行為 | 回歸與邊界 |
|---|---|---|
| Fake-IP／DNS | `collectors/dns_audit.py`、`analysis/dns_rules.py` 與獨立開關；檢查 `198.18.0.0/15`，關聯系統解析、完整解析位址、DNS 設定、介面狀態、已知核心程序及目標路由 | FIP-01–06；健康 TUN 為預期模式，私有 DNS 正常不警報；失敗查詢／未測／整體預算不足保持不確定 |
| 目標選路 | 最長前綴優先，再比路由加介面 metric；多介面同成本、缺少必要欄位為未知；不以 TUN 預設路由是否存在替代目標選路 | 專用路由勝過物理預設、其他 TUN 不遮蔽 /32、斷線介面、不同下一跳與缺 metric 反例；未知預設 metric 不得遮蔽更明確的有效路由 |
| DNS 來源邊界 | 顯示已設定伺服器與介面活動／虛擬狀態；本機 DNS 用端點清單區分有／無／未能驗證監聽 | 不將 UDP connect 當成服務存在；不聲稱已捕獲每次實際回應的 DNS 伺服器；已知程序名稱搜尋可漏掉改名或嵌入式核心 |
| 高優先嫌疑 | 需有同目標 TCP 失敗、完整查詢下無可用路由及未見已知核心；仍稱疑似殘留，沒有自動修復命令 | overall_timeout、取消、權限不足、可用特定路由及離線未測均不得升級；證據級別與優先順序分離 |
| PMTU 輔助 | GUI 單獨同意、CLI `--pmtu --confirm-pmtu`；僅同一 IP／上下文重複 IPv4 TLS 逾時；一般掃描不自動追加；IPv6 與基準測試網段安全略過 | MTU-01–06；負載與估計封包大小分開，1200+28=1228、1472+28=1500；有限尺寸／重試／總預算與命令間取消；最後一個封包耗盡總預算也不冒充 ICMP 靜默 |
| Ping 語義 | 英文／中文內文區分 Echo、需分片、不可達、拒絕存取、逾時及未知；不以 ok 或退出碼單獨判斷 | 明確分片回饋為尺寸受限，表示回饋已到達；大包靜默小包回覆仍不確定；全靜默不歸因 MTU；不修改 MTU/MSS/登錄 |
| 精簡卡 | `reports/share_card.py` 使用欄位允許清單，只輸出固定類別、列舉、驗證版本與數值耗時；預覽後另按複製；CLI 只輸出預覽 | CARD-01–05／PRIV-01；排除原始名稱、網域、IP/MAC/SSID、路徑、URL、Token、動態 Finding／錯誤；控制字元與 Markdown 注入被拒絕使用；最終字串實算 ≤500 |
| GUI／CLI | 三語言按鈕、保留目標／開關、背景工作、取消、原子檔案保存與目前語言輸出 | 實際隔離 Tk 回呼測試，剪貼簿 API 以 Mock 驗證先預覽、再複製；實機預覽不按複製，保留原剪貼簿 |

新增 48 項專項與整合回歸，包括選路邊界、CLI、Tk、構建器與校驗；連同既有 270 項，**最終完整套件 318 項通過**。完整套件已包含獨立 14 項；另外獨立執行 14 項通過，不能重複加總成不同案例數。

## 3. CI／Release 與構建

單文件產生器保留明確模組清單及標準函式庫 import 順序。現在驗證相對模組、符號、別名與範圍；不支援的函式／條件範圍 app import、星號、別名或清單外依賴會明確失敗，不會靜默刪除。測試包含重複 import 之間有名稱重新賦值的反例，未採用 Gemini 字串去重器。來源包也會先拒絕過期或缺少的生成檔。

模組、生成檔及候選 CLI EXE 的三語言唯讀入口分別實跑；純 Fake-IP、Ping 分類、分享卡與三語言 help 具有模組／單文件一致性測試。生成兩次 SHA-256 相同，交付前會再驗證解壓副本及來源 ZIP 可重現性。

SHA256SUMS 改用 `scripts/checksums.py` 逐項建立並驗證檔名與內容，涵蓋巢狀目錄、空格及中文檔名，拒絕重複、遺漏、路徑穿越、錯誤檔名與雜湊不符。不是僅檢查一份清單存在。Release 暫存目錄採根目錄 ignore，避免打包來源時混入 Windows ZIP／EXE；若錯誤強制追蹤仍會被隱私預檢擋下。

PR CI 僅 contents:read。Release 構建 job 不持有 OIDC／attestation 寫權，獨立 attestation job 才有這些權限；只有明確選取建立草稿的 workflow_dispatch，加上 release environment 與成功的前置檢查，才可建立 draft。Tag 自動觸發不建立草稿，也不自動正式發布。版本／生成來源／已審閱雜湊與受控真機證據 gate 位於構建及上傳之前，現在仍回傳預期的阻擋狀態。

官方 `actions/attest@v4` 已固定提交 `1e69f48acb82d1966a394da916b4c1698aa569d6`；其他四個官方 Action 也於本輪重新查驗。建置證明不等於程式碼簽章，也不能保證安全或消除 SmartScreen／防毒警告。本輪沒有執行 GitHub Runner、push、建立倉庫／Release 或上傳資料。

本機使用既有隔離建置環境與鎖定 PyInstaller 6.22.3，產生未簽署 GUI／CLI 候選。候選 BUILD_INFO 綁定本輪生成源碼 SHA-256，包含 Python／建置依賴版本，標示 candidate_only=true、clean_vm_validated=false、formal_release_ready=false。完整來源、零第三方 Python 執行相依的單文件、雙 EXE、授權／第三方聲明與校驗清單一起交付。

## 4. 真機驗證與仍待完成項

本機為 Windows 11 x64 build 26200、Python 3.12.14、Windows PowerShell 5.1。模組／單文件／CLI EXE 三語言唯讀執行皆留存獨立日誌與來源雜湊。觀察到 18 個網卡、45 條路由、175 個綁定，核心代理／路由／安全查詢錯誤數為 0；輔助 NDI 元資料仍有受限項，已獨立記錄，不冒充全部完整。

實際 GUI EXE 啟動、本機稽核、控制項可用性與精簡卡預覽已檢查。完整本機 GUI 預覽為 238/500 字元，未按複製；剪貼簿複製分支在隔離 Tk 測試中使用 Mock。GUI 使用隔離的 LOCALAPPDATA／APPDATA，不改使用者原有偏好設定，也不操作其他 WinNetDiff 視窗。

本機原生中文 ping 的兩個尺寸均收到 Echo，包括迴路測試。文件範例網段位址也有回覆，因此**不將這些結果當成對公網可達性或路徑 MTU 下限的證明**。這驗證了原生命令、CP936 解碼與語義解析；需分片與封鎖分支仍為 Mock 驗證，沒有修改實際 MTU 或製造黑洞。

另以單一公開測試目標執行候選 CLI 的正常 DNS/TCP/TLS/HTTP 診斷。觀察到 IPv4 HTTP 回應與 IPv6 解析不可用；本機命中基準測試網段，但已知核心與目標路由佐證不足，因此保留 fake_ip_indeterminate，沒有把 HTTP 成功包裝成完整健康代理情境驗證；細節見網路驗證摘要。沒有為了得到期望結果而停止代理、改 DNS 或改路由。

仍未完成或無法確認的項目如下。

- 真實代理寫入／恢復與自然 Connections 計數器波動恢復；本輪只有唯讀與 Mock。
- 在受控 Windows 環境重現健康 Fake-IP／代理異常退出兩種完整情境；分支單元測試通過，但沒有停止目前代理製造故障。
- 實體／虛擬受控路徑上的 ICMP 需分片與封鎖情境，及與真實 TLS 故障的因果關係。
- 真實 UAC 對話框取消、高權 WFP 匯出、乾淨 Windows 11 VM 的候選 EXE；既有同機啟動不能替代乾淨 VM。
- Windows 10、其他 Python 版本、GitHub CI Runner、建置證明和程式碼簽章。

因此正式發行仍被 `release-gate.json` 擋下。未刪除或禁用網路驅動、防護元件、虛擬網卡，未重設 Winsock、MTU、DNS、IPv6 或防火牆。

## 重現命令與證據位置

```powershell
py -3 scripts/build_standalone.py --check
py -3 -m unittest discover -s tests -v
$env:WINNETDIFF_SOURCE = (Resolve-Path windows_net_diffdiag.py).Path
py -3 tests/regression/test_winnetdiff_redteam_v2.py
py -3 windows_net_diffdiag.py --self-test
py -3 -m winnetdiff --self-test
py -3 scripts/publication_audit.py
py -3 scripts/checksums.py <candidate-folder> --verify
```

原始附件與中途／歷史紀錄在忽略目錄 `.local_validation/extensions_20261025/`。最終驗收使用 final_*.log、release_acceptance_entrypoints/summary.json、最後候選 BUILD_INFO 與獨立原始測試日誌；中途結果不替代最終結果。交付的 Evidence 目錄僅放測試輸出及經整理的摘要，真實完整報告與原始系統清單留在本機忽略目錄。

技術依據：[Windows ping 參數](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/ping)、[RFC 1191](https://www.rfc-editor.org/rfc/rfc1191)、[RFC 2923](https://www.rfc-editor.org/rfc/rfc2923)、[RFC 2544](https://www.rfc-editor.org/rfc/rfc2544)、[GitHub artifact attestations](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations)。
