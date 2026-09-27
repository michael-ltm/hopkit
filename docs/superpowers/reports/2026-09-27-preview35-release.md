# Preview.35 发布与设备更新记录

日期：2026-09-27。网站 https://sshm.yunmini.net 已发布 `0.8.0-cloud-preview.35` 的六平台签名下载、安装器及当前网页。Mac mini、MacBook Air、GrokBot 和本机 Linux 的程序均已更新到同一版本。

## 源码和产物

- 分支：`main`，已推送到 `michael-ltm/sshm`。
- 应用源码：`be601f54d2972a6f5601ca56d82cd8633a2b16c0`，包含本地优先凭据、迁移恢复及 macOS 稳定 Keychain 调用宿主修正。
- 发布工具：`dd4c3401d707a6fbbcc26eb56ddea7f32fce6615`，兼容 Go 构建元数据省略空的 `Value` 字段；应用源码未随工具修正改变。
- 签名安装器：`2ebd826`。
- macOS 两个架构在真实 Mac 上以 `CGO_ENABLED=1`、`MACOSX_DEPLOYMENT_TARGET=12.0` 构建，保留旧 `keychain:` 读取能力；Linux / Windows 两个架构以 CGO 关闭构建。
- 签名使用既有发布密钥。签名私钥没有离开原设备，也没有写入源码或工具输出。

本次沿用网站 cloud-preview 发布通道。GitHub `main` 已更新；旧标签发布流水线的 Darwin CGO 设置尚未适配，因此没有触发该流水线或替换 GitHub 的稳定版渠道。

| 下载文件 | SHA-256 |
| --- | --- |
| `sshm-darwin-amd64` | `6aca6e1933aa6a39742adf5ddec5397e950c41c82872ecdf5a4ee5ff0a8ecb18` |
| `sshm-darwin-arm64` | `e4acd471ac043c161de73bf8ca2d6339944ab8b22246a2a8ba38fd304466a511` |
| `sshm-linux-amd64` | `d74b723e296f53388d9f43c585c16ba6bab218bf425fb7f19362a69ada5596cc` |
| `sshm-linux-arm64` | `44361cb7a8783980c0ecf30fd7d3ebdafbb8f16c0cf574bbee1d0faa1a642d2c` |
| `sshm-windows-amd64.exe` | `b3b8362b4fd0265611588a0bfa2017475bc5533c01c2bd4df1b4b0a7a68c3437` |
| `sshm-windows-arm64.exe` | `39adc630f18aa2bb989e8288c742700611d3c9ba136ddbbbbb7449992e3b0c5e` |

## 网站验证

Cloudflare Worker 部署版本为 `5d3fc179-3a1d-405a-a236-64d7fb8b4e42`。部署后在 `2026-09-27T14:59:46.294Z` 重新下载公开发布清单和六个平台文件，验证固定公钥签名、每个文件的大小及 SHA-256，并核对在线 shell / PowerShell 安装器与本地生成内容逐字节一致。

本地产物及公开下载验证记录保存在忽略目录 `dist/releases/0.8.0-cloud-preview.35/` 和 `dist/releases/0.8.0-cloud-preview.35-evidence/live-verification.json`。原 `.34` 公开下载另有完整备份。

## 设备和实际连接

| 设备 | 安装版本 | 验证 |
| --- | --- | --- |
| Mac mini | `.35` | arm64 文件散列、新 MCP 初始化；桌面辅助服务重新启动并运行 |
| MacBook Air | `.35` | arm64 文件散列、新 MCP 初始化 |
| GrokBot | `.35` | amd64 文件散列、新 MCP 初始化 |
| 本机 Linux | `.35` | amd64 文件散列、用户服务重启、新 MCP 实际 SSH |

各次安装均保留原程序备份。GrokBot 的旧版本包含 `.33-restore`，使用正式签名安装器完成更新，避免预发布版本比较把它误判为比数字 `.35` 更新。

本机最终用户服务为 `active/running`；`service status` 显示 `running=true`、`configured=true`、`locked=false`、`startup=true`、`sync.state=ready`。

`prod-go`、`grokbot`、`aliyun-hcg-prod`、`racing-server` 分别通过全新 `.35` MCP 进程认证并执行远端命令成功。测试把 `SSH_AUTH_SOCK` 指向不存在的 socket，结果均为 `inventory_source=local`、`ssh.route=direct`，验证了本地持久凭据的实际使用。此次验证没有重新输入保险库口令，没有修改主机密钥检查。

两台 Mac 的 Codex 和 Claude SSHM 插件、GrokBot 的 Claude SSHM 插件均通过所属插件管理器更新为当前 `0.7.1` 资产；插件版本与客户端版本独立。插件文件散列与当前仓库一致，MCP 使用默认 `sshm mcp`，没有旧认证模式覆盖。Mac mini 的 Claude 插件原本禁用，保持禁用；其余原有启用状态保留。没有手工覆盖插件缓存。GrokBot 原有独立 Codex MCP 配置保留，本机管理式 AI 集成也已刷新。

## 自动化与原生验证

- 最终应用源码的完整 Linux `go test -race ./...` 和 `go vet ./...` 通过。
- 真实 macOS 上完整 `CGO_ENABLED=1 go test ./...`、`go vet ./...` 通过；构建后的客户端在两台 Mac 上运行成功。
- 发布工具 8 项 Python 回归通过，包含遗漏空构建设置的 RED/GREEN 用例。
- Cloud 类型检查、20 项 Node 测试、18 项 Vitest 测试及部署构建通过；先前同一 UI 源码的 7 组浏览器回归通过。
- 应用源码 `be601f5` 的 [CI](https://github.com/michael-ltm/sshm/actions/runs/36327213469) 在 Ubuntu、macOS、Windows 和集成任务全部通过；随后发布工具及安装器提交的 CI 也已通过，最后一次为 [`2ebd826`](https://github.com/michael-ltm/sshm/actions/runs/36327774762)。
- macOS GUI 会话中的合成 Keychain 测试创建后替换同路径 SSHM 二进制，新进程继续解密成功；ACL 所有者保留，没有添加宽泛解密授权。错误实例和篡改被拒绝，正式回归测试清理成功。

## 备份与验证边界

最新迁移后加密备份位于 `~/.local/state/sshm/backups/post-connection-recovery-20260927T141928Z`，包括 79 个文件、47 个服务器配置及全部 7 个配置引用私钥。所有归档文件均已在内存解密核对 SHA-256，未写出明文；迁移前备份和中间恢复备份继续保留。这些归档依赖同机同用户系统保护，不能当作跨机器恢复包。

已验证服务重启和新进程恢复，没有实际重启整台电脑。macOS 系统 Keychain 自身锁定或登录会话边界仍可能拒绝非交互访问；新实现不会绕过系统锁，也没有自动迁移已有 `keychain:` 项。早期一次失败的合成实验遗留一个无业务凭据的随机测试项，后续原生测试均完成清理，没有为清理它修改其他 Keychain 项。

旧 AI 会话需要重新加载进程和插件：新开 Codex 线程、重启 Claude。没有强行终止所有现有云 Agent 或终端会话。Windows 的 CI、编译和相关测试已通过，但没有把 Windows 实机凭据迁移、整机重启或所有历史 SSH 条目的恢复计入本次验收。
