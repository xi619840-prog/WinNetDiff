# 2.1.0b2 独立审计闭环记录

日期：2026-10-24。作者：Alden。版本定位：源码审阅预览，**暂不可用于正式发行**。

## 输入与证据边界

正式修复任务书是主要执行依据。完整 Gemini 审查报告、历史原始日志已从用户 ZIP 解压到当前仓库的 `.local_validation/audit_repair_20261024/materials/` 并完整读取。审查中的旧 P0-1 字典不等式没有执行恢复，不能验收；审查中直接恢复旧二进制 blob 的建议也未采纳。本轮使用受支持的 API 和实际方法调用回归。

用户提供的 `tests/regression/test_winnetdiff_redteam_v2.py` 按原字节保存；SHA-256 见同目录 PROVENANCE。没有修改其断言。原有合成正例补全目的 IP、测量上下文、真实关联来源或 API 状态以符合更严格证据契约，原有结论断言保留；旧的“总预算应等于 TCP 超时”错误断言改为 overall_timeout，并增加 timeout_stage 校验及反例。

## 修复前基线与本轮验收

| 证据 | 实际结果 | 用途 |
|---|---|---|
| 用户历史 `WinNetDiff_RedTeam_Baseline_14Tests.log` | 2 通过、11 断言失败、1 报错 | 历史审查附件；不是修复后验收 |
| 本轮修改前重新运行完整套件 | 168 通过 | 本机 baseline_full_tests.log |
| 本轮修改前重新运行独立 14 项 | 2 通过、11 失败、1 报错 | 本机 baseline_redteam.log；失败异常原因以本机日志为准 |
| 修复后完整套件 | 270 项通过，其中包含独立 14 项 | final_full_tests.log |
| 修复后单独运行独立脚本 | 14 项通过 | final_redteam.log；真正调用恢复方法 |
| 生成单文件内建自测 | 16 项通过 | final_embedded_tests.log；全部系统写入使用 Mock |

这些数量来自本轮命令输出，不沿用旧版“168 通过”的验收结论。完整本机证据在忽略目录，公开源码包只包含合成测试和经过整理的汇总。

## 逐项落实

| 任务 | 实现与原因 | 可执行证据 | 真机边界 |
|---|---|---|---|
| P0-A 代理恢复 | `repairs/manager.py`、`core/windows.py`、`collectors/proxy.py`：有效 API/注册表/策略状态与私有 blob 分离；语义 CAS 忽略计数器；支持的 options 1–4 恢复 flags/server/bypass/PAC，保留 UTF-16 缓冲区并通知；不写旧 blob；失败回退也拒绝外部修改 | `test_proxy_semantics.py` 的 counter drift 真正 restore、服务器/PAC/自动检测/策略反例、API 调用参数、身份与冲突、失败回退；独立 14 中正反向恢复；4 项内建代理回归 | 已真实读取 WinINET API、注册表、策略和 token；**没有写入/恢复实际代理** |
| P0-B 超时归因 | `probes/transport.py`：保留原始阶段 deadline，整体先到/同刻为 overall_timeout，TCP 完成保留 tcp_ms；TLS syscall 按先到期限分类；配置化 DNS/TCP/TLS/HTTP 与重试预算 | `test_deadline_grades.py`：TCP 刚耗尽整体、TLS 整体先到/局部先到/同刻/成功、阶段排序、预算/重试/取消、同连接上下文；独立 14 与内建回归 | 故障使用 Mock 时钟/socket；本轮未人为制造实际 TLS 故障 |
| P1-A 国际化 | `core/messages.py`、`i18n.py`、catalog/config/process/security/CLI：完整精确键、参数模板；未知原文逐字不变；静态语言名称；删除错配单字对 | `test_i18n_safety_gui.py`：三语、未知键、中文第三方身份、Message deepcopy、安全异常与 CLI 帮助 | 真正隔离 Tk 与本机中文输出；没有操作用户现有窗口 |
| P1-B 隐私 | `core/privacy.py` 共用字段分类；各 MAC、两字中文/相邻用户名、电脑名、SSID/profile、raw_columns 自定义路径、令牌/带空格密码；保留语义版本、驱动文件名和数值耗时。各文本渲染先处理结构化字段 | `test_audit_privacy_atomic.py`、GUI 实际 JSON/Markdown 导出、CLI 异常/比较输出、旧隐私回归与独立 14；默认与 full 显式选项均验证 | 真实报告保留本地；不能保证任意第三方自由文本均可公开 |
| P1-C NDI 性能 | `collectors/routes.py` 固定已核查的 Network 四个网络类及 Class 网卡类；只取实例的精确 Ndi 子键；2048 实例/14 秒界限；访问受限时保留部分元数据；metadata_errors 不改变核心 routes 完整性 | 元数据失败反例及真实 PowerShell 5.1 查询；无 -Recurse；本机 53 条元数据约 368 ms，另有辅助实例不可读明确记录 | 18 网卡、175 绑定、45 路由为本次主机观察；不是所有 Windows 安装的完整性保证 |
| P1-D 边界/日志 | 修复资格要求 API 与显式注册表一致；关闭后二者验证；prepared/applied/verified/restore_started/restored/rollback_failed 持久化；中断幂等恢复；last_backup 跳过未成功、已恢复、丢失、目录 | `test_proxy_semantics.py` 与 `test_repairs.py`：磁盘写满、意图落盘前/后失败、原子保存、并发配置变化、已恢复、删除文件及目录 | 临时备份权限原生 token SID 可读；真实写入未执行 |
| P1-E GUI | `gui/app.py`、atomic/snapshots/security：覆盖必须确认，成功写入并验证后原子替换；CLI 快照/WFP 默认拒绝；语言切换保留 profile/域名/retries；当前语言导出/手工指引；UAC 前持久化准确参数，标准 argv 引号和可读取消 | 隔离 Tk 回调、覆盖是/否、旧文件失败保留、语言与导出、UAC 取消/中文空格路径、后台取消及主线程处理 | Tk 事件循环实际执行；UAC 启动/取消的 Shell 调用为 Mock；真实 UAC/高权 WFP 未验证 |
| P2 证据 | `analysis/evidence.py` 共用分级；必须明确 host/family/IP/port/SNI/请求及阶段预算；跨目标也需相同条件；独立完整来源与启用绑定精确 Service 关联才可 E3；priority 不映射 E3，overall 不升级过滤驱动结论 | `test_deadline_grades.py`：变 IP、缺上下文、不同预算、未关联孤儿、仅状态/名字、重复同一次尝试、IPv6 间歇反例；E1/E2/E3 对齐规则/场景/层级 | E3 表示交叉佐证，仍不证明具体驱动致因 |
| P2 归属/安全 | `security.py` 将 BdNet/BdSentry/Endpoint SDK 元件线索与 Avira 主程序分开；安装路径可作为更强关联；所有高风险驱动/WFP/WMI 删除只供人工审阅 | 共享 SDK 与实际 Avira 提供者分别测试，原有 Surfshark/VirtualBox/Docker/Npcap 归属测试保留 | 未删除或禁用服务、驱动、防护或绑定 |

## 构建与交付

开发真源仍为 `winnetdiff/`。`scripts/build_standalone.py` 的显式顺序包含新 messages/atomic/privacy/evidence 模块，生成 `windows_net_diffdiag.py`；`--check` 验证逐字一致。包含 tests、scripts、pyproject.toml、完整 `.github/workflows`、MIT、README 三语及隐私/安全/验证说明。CI 分别运行全套、内建自测、独立 14 和三语帮助。`build_source_zip.py` 先做隐私预检，以独占创建生成可复现源码包；不打包真实报告、审查材料或旧 EXE。

修改前 Git tree 已保留到回滚引用 `rollback/pre-audit-2.1.0b1-20261024`（4809318e3bc10598df250aa17862688569d845e3）。原工作区及原暂存状态保留，没有 reset/删除用户修改。未推送、创建公开仓库或发布 EXE。

## 未验证项与发行门槛

**真实 WinINET 写入/恢复、真实计数器波动恢复、实际 UAC 对话框取消、高权 WFP XML、干净 Windows 11 VM EXE、Windows 10、其他 Python 版本、GitHub Runner 均未在本轮验证。** 工作电脑没有获准进行这些网络/防护修改，因此本轮不会执行。已设置 `release-gate.json` 为 false；发布 workflow 首先执行 `check_release_gate.py` 并失败阻挡。只有经单独授权的可恢复测试环境完成代理写入/恢复和干净 VM EXE 检查、证据被审阅后，才可解除。旧版本 EXE 的旧日志不构成本版本验证。

Microsoft 依据：[连接选项结构与受支持字段](https://learn.microsoft.com/en-us/windows/win32/api/wininet/ns-wininet-internet_per_conn_optionw)、[设置与查询 Internet 选项](https://learn.microsoft.com/en-us/windows/win32/wininet/setting-and-retrieving-internet-options)、[Ndi 服务相关字段](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/adding-service-related-values-to-the-ndi-key)。注册表具体层级另经本机只读核查，不将报告中的通配路径视为普遍保证。
