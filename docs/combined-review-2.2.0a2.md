# WinNetDiff 2.2.0a2 聯合審查整合與驗證

2026-10-25，作者 Alden。這是本機候選版，正式發布門禁維持關閉。既有模組化倉庫保留，未公開 GitHub 倉庫或 Release，未修改目前電腦的代理、路由、DNS、MTU、安全元件或驅動。

## 原始工作樹與整合紀錄

工作樹位於既有 WinNetDiff 目錄。開始時 main 尚無 HEAD，原始暫存區含舊版首次提交內容，後續開發在工作樹中；沒有重設、清除或覆寫暫存區。整合前以獨立索引建立回滾分支 `rollback/pre-combined-review-2.2.0a1-20261025`，提交 `c6b5e7f3f355c744b1a2388d683c859f1d3b080e`。原暫存樹為 `42ac009b8b9530c9ec0c20db60687dcad89187ed`。最終來源快照分支與提交另列於交付 Evidence/git_snapshot.json，沒有變更使用者目前分支。

附件解壓至忽略的本機驗證目錄，核對 134 個附件雜湊項目。先閱讀入口、正式任務與獨立審查，再比較候選的每個檔案；32 個檔案有新增或內容差異，逐檔整合。候選單檔未採用，單檔最後由模組重新產生。原有代理語義回復、權限邊界、整體與階段期限、Fake-IP、PMTU、診斷卡、匯出原子性與發布流程均保留。

兩條審查線共同變動的 privacy、engine、cli、evidence 以聯合候選為起點逐項審閱。CLI 保留 scan 的 Windows 平台守衛，GUI 仍提早拒絕非 Windows 系統；測試僅替換模擬邊界。既有 NDIS 必要條件的測試隨明訂的新證據契約改為「完整盤點、真實執行狀態、缺少歸屬與共享宿主反例」，仍驗證標籤或不完整盤點不得升級。原始獨立 14 項測試檔未修改。

## P0／P1 與聯合修正

| 項目 | 實作與證據 |
|---|---|
| 執行中 WFP／服務候選 | 不強制要求 NDIS 綁定；必須有完整應用程式與登錄盤點、獨立執行狀態及無已知擁有者。合法共享宿主與缺少執行來源均不提供 E3 佐證。E3 仍不代表致因或死鎖。 |
| 路徑與識別碼 | 目錄不再保留私人葉節點，支援含空白路徑；HMAC 與目錄遮蔽共同作用，三語 JSON、Markdown、快照聯合回歸保留合法版本號及 Unicode 原始服務名稱。 |
| 排序、DNS 與命令 | Findings 先依嚴重性排序；DNS 位址支援單值／陣列，無路由時只關聯活動介面設定的 DNS；PowerShell 檔案查詢同時限制批次數與編碼長度，缺列維持未知。 |
| F1 系統工具 | 透過 GetSystemDirectoryW 及明確 allowlist 解析絕對路徑，拒絕相對路徑與未知工具；失敗不回退 PATH。靜態測試涵蓋應用程式 subprocess 呼叫點，64 位 Windows 實際執行全部 9 類唯讀工具。 |
| F2 金鑰 | Windows 從建立時便使用僅目前使用者與 SYSTEM 的受保護 DACL；寫入並 flush 後同磁碟獨佔 rename。以相同 handle 檢查擁有者、ACL 與內容。壞檔、權限過寬及寫入失敗保留原檔並使用工作階段金鑰。六個實際子程序競爭與中文目錄測試通過。 |
| 快照相容性 | 記錄 HMAC scheme 與 key fingerprint；不同金鑰或新舊 scheme 明確拒絕比較，舊檔不刪除。舊版快照仍可互相比較；提示有三種語言。 |
| F3 Markdown | 動態欄位跳脫、程式碼圍欄長於內容反引號；補上 GFM 裸網址及電子郵件自動連結防護。使用真正 cmark-gfm、啟用 unsafe HTML 並以未跳脫惡意對照驗證，三語完整／遮蔽共 6 組均無注入標籤或連結，表格正常。電子郵件中的 @ 後加入零寬空白，JSON 保留可讀取的原資料格式。 |
| F4 並行與取消 | 最多 6 個 host×family 工作，結果維持 host、IPv4、IPv6 順序；DNS 槽位等待納入預算但不當作解析延遲。補上剛取得槽位時取消／期限的競爭處理，啟動失敗釋放原槽位；socket 有界等待結束後若已取消，不誤報 TLS 逾時。 |
| 訊息模板 | 無參數 GUID 大括號在 msg 與後續三語翻譯階段均保持原文。 |

## 本輪實際測試

Windows 11 x64、Python 3.12.14。本輪基線 318/318，附件候選整合後 387/387；最終加上 11 項獨立聯合回歸為 **398/398，無失敗、無跳過**。獨立原始測試另外執行 **14/14**；模組與生成單檔內建自測各 **19/19**。編譯、單檔一致性及發布檔案預檢另附原始日誌。

歷史 Linux 日誌的 387 項包含 26 項平台跳過，只是附件來源證據；不計入本輪 Windows 通過數。中途測試與執行設定錯誤保留於忽略目錄，交付以明確標記的最終日誌為準。測試沒有使用或建立使用者真實 pseudonym.key；自測使用記憶體金鑰，一般測試與入口驗證使用隔離路徑。

`scripts/validate_review_native.py` 以真實 IPv4／IPv6 loopback TCP 接受連線但不回覆 TLS，分別量測順序／並行與取消；沒有替換 socket、TLS 或時鐘。只用呼叫邊界將探針導向動態本機連接埠。各目標的 TLS 階段歸因與結果順序相同，取消結果均為 cancelled。這是本機受控慢連線證據，不宣稱廣域網路提速。DNSBusy 後釋放槽位，真實 localhost 解析恢復。原始時間與來源 SHA-256 在 Evidence/native_summary.json。

GUI 透過新建後立即隱藏的 Tk 視窗與程式內 callback 驗證，三語唯讀盤點均完成五層結果；沒有桌面自動操作、剪貼簿變更或實際 UAC。這能證明程式介面啟動與工作流程，不代表人工目視驗收。完整機器清單與金鑰留在忽略目錄；交付僅收錄摘要、合成渲染案例及測試日誌。

## CI、建置與發布

版本改為 2.2.0a2，避免舊 a1 EXE 混用。完整模組、測試、腳本、CI、文件與重新生成單檔一併交付。Windows GUI／CLI 必須在既有隔離 build venv 重新建置，產生新的 BUILD_INFO、來源雜湊與 SHA256SUMS；交付摘要列出實際完成結果。來源 ZIP 解壓後重新驗證測試與生成一致性。未簽章候選不算正式發布。

既有 Actions 最小權限、固定 action commit、獨立 attestation／draft 工作及正式來源門禁保留。本輪僅本機驗證，沒有執行遠端 Actions、簽章、attestation 或 GitHub 發布。門禁仍回傳預期的 FORMAL RELEASE BLOCKED。

重現命令：

```powershell
py -3 scripts/build_standalone.py --check
py -3 -m unittest discover -s tests -v
$env:WINNETDIFF_SOURCE = (Resolve-Path windows_net_diffdiag.py).Path
py -3 tests/regression/test_winnetdiff_redteam_v2.py
py -3 -m winnetdiff --self-test
py -3 windows_net_diffdiag.py --self-test
py -3 scripts/publication_audit.py
py -3 scripts/check_release_gate.py  # 預期 exit 1，保持阻止正式發布
```

選用原生驗證需在隔離 QA venv 安裝 `cmarkgfm==2025.10.22`，再執行 `scripts/validate_review_native.py --output <新的證據目錄>`。應用程式執行本身仍僅依賴標準函式庫。

## 剩餘驗證與產品限制

尚未執行實際 WinINET 寫入／恢復及衝突、標準／管理員 UAC、提升權限 WFP 匯出、乾淨 Windows VM EXE、Windows 10、WOW64 32 位程序及其他 Python 版本驗收。未授權改動目前主機來代替受控 VM。最終 GUI EXE 人工目視驗收亦未完成。

F5 廠商無關的通用 WFP／NDIS 宿主圖譜、F6 企業遠端代理與直連路徑差異、F7 可控制同 IP 重試仍為後續產品工作；目前仍保留每次嘗試 IP，並依完整相同路徑計算 E2／E3，完成順序不改變分級。已知核心名稱盤點可能漏掉改名／嵌入核心。HMAC 同安裝可關聯，軟體指紋仍可能關聯公開報告；不宣稱完全匿名。

Windows ACL 實作依據為 [Microsoft 檔案安全與存取權限](https://learn.microsoft.com/en-us/windows/win32/fileio/file-security-and-access-rights)；32 位轉向限制參照 [Microsoft WOW64 檔案系統轉向](https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector)。本輪 64 位實測不替代 WOW64 驗收。

解壓來源 ZIP 的首次驗證捕捉到偶發跨程序金鑰競爭。修正讀取 share-delete 與發布失敗時重新採用受保護的完整勝出檔案，新增 AccessDenied 勝出者回歸；沒有放寬一致金鑰斷言。首次來源／EXE 為已淘汰中途產物，最終包全數重建。
