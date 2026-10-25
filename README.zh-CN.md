# WinNetDiff

已完成最终 GUI 修复：普通导出直接脱敏；**完整数据…** 需要重新勾选风险确认并主动导出，Enter／Esc／关闭窗口均取消。缺失保存目录须自主选择，取消／失败／不完整诊断有明确提示。[本轮验收与限制](docs/gui-final-2.2.0a3.md)。

**源码 Alpha 预览候选（尚未公开）。** 正式 Windows EXE／Release 仍受门禁阻止：尚未完成受控代理修改及回滚、干净 Windows 11 VM 验证。实际修复功能尚未获得生产环境验收。[2.2.0a3 证据](docs/gui-final-2.2.0a3.md) · [源码公开清单](docs/source-alpha-publication.md) · [验证状态](docs/validation.md)。


![启动画面](docs/images/startup-en-2.2.0a3-gui-final.jpg)

本轮实际 2.2.0a3 Windows 启动画面，英文界面，使用隔离配置。尚未扫描，不含真实设备报告或私人路径。

**定位故障发生在哪一层，并保留支持判断的证据。**

WinNetDiff 是由 **Alden** 署名的开源 Windows 网络差分诊断与修复工具。它比较代理、路由、IPv4/IPv6、DNS/TCP/TLS/HTTP 和网络过滤组件的状态，缩小排查范围。它是诊断辅助工具，不保证自动定位或修复所有 Windows 网络故障。

[English](README.md) · [繁體中文](README.zh-TW.md) · [隐私说明](PRIVACY.md) · [安全边界](docs/safety-model.md)

当前版本 **2.2.0a3** 是供审阅的预览版。真实 Windows 验证、Mock 测试、CI Runner 和实际修复操作必须分别记录，不能因为 CI 通过就宣称全部真机验证完成。参见[验证状态](docs/validation.md)和[发布说明](docs/release-notes.md)。此目录不会自动创建公开仓库或发布 Release。

## 核心功能

- 在同一目标 IP、同一条 TCP 连接上分别测量 TCP 建连、经过证书验证的 TLS 握手和 HTTP 响应，保存每次重试结果。
- 检查已启用的代理与本地监听、完整路由和跃点数、NDIS 绑定、服务、驱动、安全中心提供程序、安装程序清单及可取得的签名信息。
- 根据证据给孤儿组件分级；第三方名称、非 `ms_*` 绑定和厂商关键词都不直接等于故障。
- 保存版本化网络快照，比较新增、删除、启用、禁用和配置变化。
- 显示推理依据、其他解释、下一项可证伪检查和操作风险；可回滚修复后，以相同目标和参数重新验证。
- 可选 English、简体中文、繁體中文，并根据语言建议测试目标配置；允许独立切换配置或自定义域名。

普通模式优先显示可能问题、关键证据和下一步；专家模式提供阶段记录、路由、绑定和原始证据。截图只展示实际程序和经过审阅或合成的数据，不将设计稿当作已实现功能。

## 启动

源码要求 Windows 10/11、Python 3.10+；GUI 还需 Tcl/Tk。运行时仅依赖 Python 标准库，Windows 11 x64 是主要验证平台。

```powershell
py -3 windows_net_diffdiag.py --lang zh-CN
py -3 windows_net_diffdiag.py --lang en
py -3 windows_net_diffdiag.py --lang zh-TW
py -3 -m winnetdiff --lang zh-CN

# 本地只读审计，不执行远端探针
py -3 windows_net_diffdiag.py --cli --lang zh-CN --no-network

# 测试目标可独立于界面语言选择
py -3 windows_net_diffdiag.py --cli --lang en --profile mainland
py -3 windows_net_diffdiag.py --cli --hosts example.com,www.microsoft.com --retries 2
```

`--no-network` 仍会检查本地回送代理端口。首次启动不自动申请管理员权限；受限查询保留为未完成，不能当作配置不存在。

经过维护者审阅并发布后，普通用户可下载 `WinNetDiff.exe`，命令行用户可使用 `WinNetDiff-CLI.exe`。EXE 不要求安装 Python。除非发布说明明确标注，否则程序未签名，SmartScreen 可能显示警告。请核对来源和校验值，不要无条件忽略警告或关闭 Defender。

## 语言和测试网站

默认建议为 English → `global`、简体中文 → `mainland`、繁體中文 → `traditional`。配置采用多个可修改目标，不只依赖 Google 或百度。切换界面语言不会覆盖你手动输入的域名，开始扫描前可以查看实际目标。网站是否可访问会随地区和时间变化，单个目标失败不能代表整个网络故障。

| 建议语言 | 配置 | 默认域名 |
|---|---|---|
| English | `global` | `www.microsoft.com`、`www.cloudflare.com`、`www.wikipedia.org` |
| 简体中文 | `mainland` | `www.baidu.com`、`www.qq.com`、`www.bilibili.com` |
| 繁體中文 | `traditional` | `www.microsoft.com`、`www.cloudflare.com`、`www.yahoo.com` |

## 报告、快照与回滚

```powershell
py -3 windows_net_diffdiag.py --cli --lang zh-CN --json report.json --markdown report.md
py -3 windows_net_diffdiag.py --cli --no-network --snapshot baseline.json
py -3 windows_net_diffdiag.py --cli --compare baseline.json after.json
```

报告和快照默认脱敏，完整本地报告需要 `--full-report --confirm-private`。WFP 原始 XML 始终视为敏感数据。即使是脱敏报告，公开前也应检查；不要公开修复备份、账号、Token 或未经检查的原始日志。[快照字段与兼容性](docs/snapshot-schema.md)另有说明。

程序默认只读。明确确认后，只有符合条件的用户级失效手动代理关闭及恢复可自动执行；流程包括原始状态备份、修改前重读、执行、验证、日志和冲突保护。DNS 快取无法可靠恢复，因此清除操作默认只提供人工指导。NDIS 绑定和安全驱动没有通用一键清理按钮。[安全与恢复说明](docs/safety-model.md)介绍具体限制。

`examples/` 和 `tests/fixtures/` 使用合成数据。典型回归案例展示多目标 TCP 成功而 TLS 反复超时，同时出现疑似孤儿过滤组件时，应提高相关假设优先级；仍保留 MTU、服务器和 TLS 中间设备等解释，不宣称已经证明驱动死锁。

## 开发与测试

维护 `winnetdiff/` 模块化源码，再生成独立单文件；CLI 和 GUI 共享诊断引擎。

```powershell
py -3 scripts/build_standalone.py
py -3 scripts/build_standalone.py --check
py -3 -m unittest discover -s tests -v
py -3 windows_net_diffdiag.py --self-test
py -3 scripts/publication_audit.py
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/validate_windows.ps1
```

验证脚本只读，不执行系统修复，真实证据保存在 Git 忽略的 `.local_validation/`。参见[架构](docs/architecture.md)、[诊断方法](docs/diagnostic-methodology.md)、[贡献说明](CONTRIBUTING.md)和[路线](docs/roadmap.md)。

Windows 上运行 `scripts/build_exe.ps1` 会建立隔离的构建环境，并从 PyPI 安装固定版本构建依赖；`-NoInstall` 只使用已有构建环境。产物与 SHA-256 清单位于忽略的 `dist/`。

```powershell
Get-FileHash .\WinNetDiff.exe -Algorithm SHA256
```

请与同一发行包的 `SHA256SUMS.txt` 比对。构建来源证明只能帮助核对产物来源，不代表安全认证或代码签名。

## 作者与许可

Copyright (c) 2026 **Alden**。项目源码使用 [MIT License](LICENSE)，不包含中文本名或私人邮箱。GitHub 主页待 Alden 确认用户名后再添加。[第三方构建工具与解释器许可](docs/licensing-provenance.md)单独说明。


## 可选诊断（始于 2.2.0a2）

Fake-IP/DNS 审计结合目标地址的最长前缀路由、活动接口、DNS 配置、已知代理核心进程和实际探针结果。正常 TUN 映射属于预期模式，不能仅因命中 `198.18.0.0/15` 就称 DNS 污染；私网和本地 DNS 也可能正常。缺少可用目标路由、TCP 失败且未观察到已知核心时才报告“疑似残留”。离线模式只保留配置线索和未验证项。

PMTU 按钮仅在同一 IPv4 地址重复 TLS 超时后可用，仍需单独同意。记录 ICMP 负载与估计 IPv4 报文大小。“需要分片”说明反馈已返回；静默或大小差异不能确诊黑洞，不会自动修改 MTU、MSS 或注册表。

“复制精简诊断卡”先展示预览，再由用户点击复制。卡片仅使用固定类别、枚举、版本和数值耗时，排除原始名称、地址、域名、URL、异常和动态诊断文字。最终字符串实际校验 **≤500 字符**，不保证绝对匿名，请先审阅；不会自动上传。

```powershell
py -3 windows_net_diffdiag.py --cli --no-network --share-card
py -3 windows_net_diffdiag.py --cli --no-network --no-fake-ip-audit
py -3 windows_net_diffdiag.py --cli --pmtu --confirm-pmtu
```

语言、目标配置及审计开关互不重置。`--fake-ip-audit` 明确启用审计；普通扫描不自动追加 PMTU。CLI 保存默认拒绝覆盖；GUI 明确确认后才原子替换。README 使用本轮 2.2.0a3 的真实启动截图。


本轮联合审查证据与限制： [2.2.0a2 integration](docs/combined-review-2.2.0a2.md).

## 2.2.0a3 F5 / F6 / F7

通用宿主关联、企业 HTTP 代理路径诊断与固定同一 IP 重试已实现。默认固定地址；可用 --retry-mode rotate 轮替 DNS 地址。代理实测需要 --proxy-paths --confirm-proxy-paths 和联网 CLI 诊断。WFP 导入只作为历史关联资料。[命令、证据与限制](docs/f567-2.2.0a3.md)。
