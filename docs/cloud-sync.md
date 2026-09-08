# SSHM Cloud 使用说明（预览版）

控制台：<https://sshm.yunmini.net>。原有 `sshm list/connect/exec` 和 MCP 继续读取本地配置；云端数据通过 `sshm cloud …` 使用。登录不会覆盖原配置。

## 首次接入

在可信终端中运行，密码不要放在命令行参数、环境变量或聊天里：

```sh
# 第一台设备：创建账号、生成恢复码、加密导入本机记录并同步
sshm cloud register --username your-name --import-local

# 其他设备：使用相同账号密码和保险库解锁口令
sshm cloud login --username your-name --import-local
```

需要两份不同口令：账号密码用于登录；保险库解锁口令只用于客户端或浏览器的本地解密。均至少 6 字符。注册生成的恢复码直接写入受保护的本地文件，只显示路径。请移入密码管理器或离线保存。

`--import-local` 导入服务器记录及配置明确引用的私钥。相同初始连接身份合并别名并保留各设备的凭据来源；不同 SSH 用户、认证方式或代理路线分别保留。同名不同目标需要使用完整连接 ID。Agent 密钥无法导出；以前没有保存的 SSH 密码不能凭空恢复。

```sh
sshm cloud import                  # 再次导入当前本地配置，默认包含可读取的密钥
sshm cloud import --without-keys    # 只导入连接信息
sshm cloud save-password my-host    # 在终端输入 SSH 登录密码并加密保存
sshm cloud sync
sshm cloud list
sshm cloud connect my-host
sshm cloud exec my-host 'uptime'
```

有多个不同密码的连接会拒绝自动挑选；根据提示使用 `--credential <凭据ID>`。外来代理或转发配置需要核对后显式传入 `--trust-route`。云端 ProxyJump 必须对应保险库中的唯一连接；暂不支持嵌套跳板。主机指纹仍在各设备本地验证，不自动信任云端提供的主机密钥。

## 在线状态与自动同步

```sh
sshm cloud presence     # 每 30 秒发送心跳，不解锁保险库、不开放远程 Shell
sshm cloud watch        # 终端解锁一次；在当前进程中每 30 秒同步并发送心跳
```

保持进程运行；Ctrl-C 停止。控制台在 90 秒内收到心跳时显示在线，否则显示离线。系统、版本、最后心跳由客户端报告；这是 SSHM 客户端的在线状态，不代表它保存的每个 SSH 目标都可访问。当前不自动安装开机服务。

## 网页控制台

- 右上角登录；会话使用 Secure、HttpOnly、SameSite=Strict Cookie。浏览器会话与 SSHM 客户端设备分别展示。
- **设备**：搜索、系统/状态筛选、按分组查看、详情、名称/分组/标签/备注编辑、撤销访问、客户端下载与添加设备指引。
- **服务器保险库**：输入独立解锁口令，在浏览器内解密；查看、搜索、添加、修改、删除 SSH 连接及分组标签。私钥和密码保留在加密数据中，不在表格中展示。新凭据通过可信客户端导入。
- 网页修改使用签名和版本条件写入；遇到其他设备同时修改会拒绝覆盖并提示重新加载。
- 标签页隐藏超过 1 分钟，或 5 分钟未操作自动锁定。网页终端在隐藏时立即断开，关闭页面立即锁定。网页代码来自当前服务，浏览器解锁应仅在可信设备和可信部署上进行。
- **账号与安全**：管理浏览器会话，查看客户端改密、恢复及换钥命令。

客户端设备名称、分组、标签、系统、版本、CPU、内存、磁盘容量/剩余空间和心跳属于账号管理元数据，服务端可见。**服务器保险库内**的名称、主机地址、SSH 用户、分组、标签、备注、私钥和密码全部端到端加密。

## 冲突、撤销与恢复

```sh
sshm cloud status
sshm cloud conflicts
sshm cloud conflicts --resolve <完整ID> --keep local   # 或 remote
sshm cloud sync
sshm cloud devices
sshm cloud devices --revoke <设备ID>
sshm cloud change-password
sshm cloud rekey
sshm cloud logout
```

三方合并以完整连接对象为单位；不同连接的独立修改合并，同一连接的冲突保留双方并阻止直接连接。删除保留 tombstone，旧离线副本不能静默复活。待确认的上传必须先 `cloud sync` 重试，再进行新编辑。

`rekey` 更换主密钥、解锁口令和恢复码，并撤销其他设备会话。它不能收回已下载的数据；若 SSH 密钥或密码已经泄漏，还须在真实目标服务器换钥或改密。

丢失账号密码时，在新配置路径中运行 `sshm --config <新路径> cloud recover --username your-name`，在本机输入恢复码与新账号密码。原解锁口令仍有效；可随后运行 `cloud rekey --use-recovery` 设置新口令。没有口令、恢复码或已解锁设备时，管理员无法恢复保险库明文。

## 当前边界

这是可运行的云同步与设备管理预览版，不是 Tailscale 的虚拟网络实现。原来的 SSH/Tailscale/VPN 网络可达性仍然必要。

网页 Shell 从 preview.9 起通过 `sshm cloud agent --allow-shell` 显式开启。设备主动连出 WSS，以当前系统用户运行原生 PTY（Windows 使用 ConPTY）。每次会话需要解锁网页保险库并签名，命令和输出使用独立的双向 AES-GCM 密钥与递增序号。关闭页面、锁定保险库、设备断开或撤销会终止会话；preview.26 的新代理不再按总时长强制断开，旧代理需升级并重启。`presence` 仍然只发送心跳。

保险库密文上限 2 MiB，单账号最多 32 个未过期会话，CLI 会话有效期 30 天，网页 Cookie 为 1 天；历史保留最近 20 次提交用于运维保护，尚无用户版本恢复 UI。未提供邮箱验证、邮件找回、MFA、操作系统钥匙串免口令解锁、设备间免口令配对或跨设备 MCP 保险库解锁接口。旧本地私钥不因启用云同步而自动加密。

## 程序与 AI 集成更新

```sh
sshm update --check       # 手动检查签名发布
sshm update               # 显示版本，确认后更新
sshm integrations status
sshm integrations install --app all --mcp
sshm integrations refresh
```

自动检查成功后缓存 6 小时，失败后 10 分钟重试，网络检查最多等待 1.5 秒。打开终端列表发现新版时显示 Update now / Skip for now（默认 Skip），其他普通交互命令只显示提示。MCP、JSON、非交互调用以及 cloud/update/integrations 命令不会插入启动提示。可设置 `SSHM_NO_UPDATE_CHECK=1` 禁用自动检查；手动检查不受影响。

更新使用程序中固定的 Ed25519 公钥验证发布清单，再校验下载大小与 SHA-256。没有无人值守的自动替换；`--yes` 是用户主动授权的自动化选项。旧程序保留为相邻备份，激活失败会尝试恢复。Homebrew Cellar/Scoop 管理的安装要求继续通过原包管理器更新，避免破坏其文件所有权。

下载安装二进制**不会直接改动 AI 应用配置**。使用 `integrations install` 可选择 Codex 或 Claude Code 的 Skill；加 `--mcp` 后才调用对应应用的原生 CLI 注册缺少的 `sshm` 服务，已有配置保留，写入前做私有备份。

Codex Skill 路径为 `~/.agents/skills/sshm-server-ops`，Claude Code 为 `~/.claude/skills/sshm-server-ops`。SSHM 管理的文件带所有权与摘要清单；后续程序更新调用新版本的 `integrations refresh`，保留用户自行修改的文件和额外笔记。如果已有 SSHM 插件缓存，则保留插件管理方式，避免重复安装；该插件仍通过原应用的插件管理器更新，不手动改写插件缓存。

来源：[Codex Skills](https://learn.chatgpt.com/docs/build-skills)、[Codex MCP](https://learn.chatgpt.com/docs/extend/mcp?surface=cli)、[Claude Code Skills](https://code.claude.com/docs/en/skills)、[Claude Code MCP](https://code.claude.com/docs/en/mcp)。

### Interactive update choices (preview.8)

Opening `sshm` or the interactive server list offers **Update now** and
**Skip for now** when a newer, verified release is available. Skip is selected
by default and leaves the binary unchanged. Update installs the signed release,
keeps a rollback executable, refreshes SSHM-managed skills, then reopens the
inventory using the new executable. Failure reports the reason and keeps the
current running session available. Plugin-managed skills are preserved and
must be updated through their Codex/Claude plugin manager.

Successful automatic checks are cached for six hours. Network checks have a
1.5-second budget; failed checks retry after ten minutes. An unavailable update
service does not stop local work. A valid cached release can still be offered.
`sshm update --check` explicitly checks immediately; `sshm update` offers the
same Update/Skip choice, and `sshm update --yes` is explicit noninteractive
approval. `--json` remains read-only. MCP, pipes and one-off SSH operations do
not wait for update choices. `SSHM_NO_UPDATE_CHECK=1` disables automatic checks.
A current installation has no update menu until a newer version is available.

The running version is shown in the terminal list, including narrow windows,
and through both `sshm version` and `sshm --version`.

Validation used isolated old-version test binaries with the new update UI and
real production-signed manifests/downloads. macOS PTY and Windows ConPTY proved
Skip leaves binary/configuration unchanged, Update replaces the test executable
and reopens the released inventory, and its version changes to the downloaded
release. macOS also verified manual Skip and rejection of a tampered cached
signature. These tests do not require a fake release key or bypass validation.


### Browser-approved devices (preview.9)

在可信网页解锁保险库后，打开“添加设备”，复制包含 `--root-public` 的接入命令。公钥可以公开，用于阻止服务端替换保险库身份。设备显示的验证码必须与网页请求一致；批准后，主密钥经临时 P-256 ECDH / AES-GCM 通道发送给设备，批准记录同时具有保险库根签名。请求 10 分钟过期。

```sh
sshm cloud link --username your-name --root-public VERIFIED_PUBLIC_KEY --import-local
# 同一次批准后运行同步、心跳和可选网页终端：
sshm cloud link --username your-name --root-public VERIFIED_PUBLIC_KEY --import-local --serve --allow-shell
```

只有账号会话与加密快照持久化；保险库主密钥仅在进程内存中。进程退出或机器重启后需要再次本机解锁或网页批准。连接撤销不能收回已下载的资料。拥有完整系统权限的进程仍能访问该系统上的已解锁凭据。

`--harden-keys` 显式启用本地密钥迁移：先把原文件、恢复旁文件和替换密钥加密备份并确认云端提交，再向 SSH Agent 加载并验证签名，保持公钥身份不变，最后移除已有 `.passphrase` 旁文件。不可解锁或无法签名的密钥保留并报告。无明文密钥备份写入磁盘；私有迁移收据只包含路径、状态和保险库凭据 ID。AI 的 SSHM/MCP 使用本机 SSH Agent；代理重启后，尚未解锁的密钥仍需恢复到 Agent。

控制台采用白色工作区和暖灰导航，表格默认紧凑模式，支持 25/50/100 条分页、搜索和认证筛选、批量设置分组与追加标签。已有凭据保持不变；并发版本冲突拒绝覆盖。行操作位于“···”菜单，设备和服务器名称均可直接打开详情。


### 服务器系统、活动与 SSHM 安装信息

`sshm inspect --all` 通过现有 SSH 凭据检查系统，以及当前登录用户 PATH 和常用安装目录中的 SSHM。无需在目标预装 SSHM。检查不会更新成功使用时间，包括经过跳板机的情况；无法连接时保留条目及明确的错误类别，不保存原始认证错误。

网页显示彩色系统图标、最近成功连接的相对时间、最近失败原因和 SSHM 客户端状态。检测到的版本与签名发布清单相同为绿色，不同为橙色；未安装为红色；未检查或无法确认是灰色。未找到客户端仅表示检查过的安装位置没有找到，不是全磁盘搜索。

活动数据作为保险库中的独立加密元数据合并，取较新观察。网页解锁后每 30 秒刷新已签名的密文快照；打开编辑弹窗时暂缓刷新。`cloud agent` 同步本机的这些观察，但不会替代本机连接配置。

### Web deletion and device tasks (preview.15)

Server row menus now expose Delete; selected rows can be deleted together. A confirmation lists the affected aliases. The browser removes entries, their activity and conflicts, then signs and encrypts deletion tombstones. Local import skips these identities, so subsequent imports do not revive them. Original local config files, credentials shared by other entries, key files, and remote machines are retained.

The device page and vault toolbar offer signed tasks for selected cloud clients:

- Sync merges local connections and credentials into the encrypted vault and fetches cloud changes, preserving existing local config files.
- Inspect checks the receiving client's local inventory with at most four concurrent SSH connections and synchronizes observations. It does not prompt for passwords or mark probes as successful usage.
- Update pins the version reviewed in the browser, verifies the official release signature and asset hash, and uses the existing updater. It reports `restart_required` after replacement: the running agent retains its old version and must be restarted and unlocked/approved again. The master is never persisted for unattended restart.

A preview.15+ unlocked `cloud agent` or `cloud link --serve` process receives jobs even with web shell disabled. Merely installing SSHM or running presence is not sufficient. A plain SSH target must be enrolled as a cloud client to receive these commands.

Jobs wait up to 24 hours, support cancellation before execution, and have a five-minute execution budget. Receipts distinguish queued, running, completed, failed, expired, cancelled, and installed/restart required. The account keeps at most 200 jobs for seven days and at most four outstanding jobs per device. Browser requests and bounded client receipts are signed by the vault root; client execution verifies account, device, action, version and expiry. Revoking/relinking a device invalidates its pending jobs. The private receipt journal is persisted before claiming work; lost responses retry the same receipt, while interrupted actions are reported instead of automatically rerun. Only action metadata, fixed result codes and counts enter the task queue; credentials, host lists and shell output do not.

Preview.16 also bounds SSH handshakes, SOCKS negotiation and jump channel opening. A TCP listener that does not speak SSH now produces a timeout observation rather than leaving a detection task running indefinitely.

Preview.17 fixes agent exit after temporary relay HTTP 409 conflicts. The encrypted shell retries these conflicts while the independent heartbeat/sync loop remains active; authentication rejection still stops a revoked client. Initial relay handshakes time out after 20 seconds. Cloud relay message liveness expires abandoned agent sockets after 90 seconds, so they cannot keep blocking reconnects until the one-hour relay expiry.

### 系统与硬件清单（preview.18）

设备和服务器表格均有系统、CPU、内存、磁盘四列。CPU 为型号、核心/线程数，内存为系统可见总量与可用量；这是带检测时间的快照，不是实时性能监控。macOS 可用内存采用 free + inactive + speculative 估计。Linux 使用 `/proc`、`lsblk` 和 `df`，macOS 使用 `sysctl`、`diskutil`、`vm_stat` 和 `df`，Windows 使用 PowerShell 5.1 的 CIM 查询；目标不必安装 SSHM。

`sshm inspect --local` 输出本机硬件；`sshm inspect --all --timeout 15` 通过现有 SSH 认证采集目标清单，最多四路并发，不改变成功使用时间。缺失工具、权限不足、无法连接或超时显示未获取/部分结果，不把未知容量记为已用完。刷新失败保留最近有效快照并标明刷新失败，超过 15 分钟显示历史检测。设备代理每 5 分钟采集本机信息；远程服务器通过下发“检测服务器”刷新。

磁盘详情保留系统可见的磁盘、未挂载分区、映射、卷和 APFS 共享容器，不仅列系统盘。列表容量仅汇总磁盘层，卷和分区不重复相加。Linux 的 zram/RAM、eMMC 启动区、未连接零容量 NBD 在“其他块设备”中单列，不计入磁盘数量；已连接 NBD、虚拟机磁盘仍保留。容器只能看到宿主允许暴露的设备，不保证看到宿主全部物理盘。单次采集最多 512 KiB 输出、256 条磁盘记录，超出或工具受限明确标记部分/不可用。

从 preview.19 起，设备系统资源随已认证心跳上传，账号登录后即可查看，不需要解锁保险库。服务端严格筛选允许字段，不接收挂载路径或卷 UUID；不会公开给未登录用户。完整挂载信息仍仅在本地与端到端加密保险库内保存。服务器连接的硬件观察仍随加密记录保存，不把主机地址或服务器列表改为明文。锁定会清除保险库行和终端；设备资源继续可见。客户端应升级到 .19 或更新版本以发送资源心跳。`sshm cloud presence --once` 可在已登录客户端立即上报一次，不需要保险库解锁。

筛选、分页、表单选择、复选框、错误提示、撤销确认、详情、折叠箭头和悬浮提示使用统一自定义外观；选择器支持方向键、Home/End、键入查找、Escape 和焦点返回。原生 select 仅作为隐藏表单值容器，不呈现浏览器选择面板。对话框保留语义和焦点约束，禁用浏览器原生校验气泡。

### 服务器终端与磁盘剩余空间（preview.19）

服务器行菜单的“连接终端”允许选择在线、已开启 Shell 且支持 SSH 转接的可信设备。转接设备使用端到端加密保险库内的目标与凭据建立 SSH PTY；目标服务器只需要运行 SSH 服务，不必安装 SSHM。连接授权和目标/凭据选择经过签名或加密，转接前重新检查删除、冲突和当前保险库版本。自定义跳板/代理连接需要选择持有原连接配置的设备。私钥需可在转接设备的 Agent 中签名，或已作为可解密凭据存入保险库。

磁盘表格与详情显示已采集文件系统的剩余容量；APFS 共享容器只累计一次，排除重复卷和快照。未获取的数据明确显示未知，不视为零；该值不代表物理盘未分区空间。

### 跨平台 Agent 兼容性（preview.21）

显式 `SSH_AUTH_SOCK` 始终优先。没有该变量时，Linux 识别当前用户拥有的 `~/.ssh/sshm-agent.sock`，再使用 SSHM 管理的 Agent；原 socket 已失效时可回退。加密私钥会在允许的候选 Agent 内按公钥精确匹配，因此可连接但没有该密钥的 Agent 不会遮蔽后续候选。macOS 沿用当前用户 launchd Agent 和管理 Agent，Windows 使用 OpenSSH 命名管道或显式指定管道。不会读取密钥口令、自动解密私钥或扫描其他用户的 Agent。已有 Agent 中的密钥仅保留在内存，主机重启后仍需要正常的密钥解锁流程。

## 官网一键安装

官网右上角“安装 SSHM”、首页和“添加设备”均提供安装命令，无需账号登录。

macOS / Linux：

```sh
curl -fsSL https://sshm.yunmini.net/install.sh | sh && export PATH="$HOME/.local/bin:$PATH"
```

Windows（PowerShell 5.1+）：

```powershell
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; irm https://sshm.yunmini.net/install.ps1 | iex
```

安装器自动选择 x64 / ARM64；Rosetta 终端优先使用原生 ARM64。Linux 客户端静态编译，无 glibc 依赖，适用于 Ubuntu/Debian、RHEL 系、Arch、Alpine、openSUSE、64 位 Raspberry Pi OS 等发行版，WSL 走 Linux 路径。当前不提供 32 位、MIPS、RISC-V、LoongArch；这里的发行版兼容范围不表示已经逐个实机测试。极简系统需要先通过包管理器安装 curl 或 wget、CA 证书和 SHA-256 工具。

当前 Go 1.26 构建的最低平台要求为 macOS 12+、Linux 内核 3.2+、Windows 10 / Server 2016+，见 [Go 官方要求](https://go.dev/wiki/MinimumRequirements)。

默认安装到当前用户的 `~/.local/bin/sshm` 或 `%LOCALAPPDATA%\Programs\sshm\sshm.exe`，不需要 sudo、管理员或更改 PowerShell 执行策略。保留配置和密钥，替换前备份二进制。POSIX 安装后重新打开终端使 PATH 生效，网页接入命令使用完整路径可立即执行。可设置 `SSHM_INSTALL_DIR` 自定义目录，`SSHM_NO_PATH=1` 跳过 PATH 修改，`SSHM_INSTALL_INTEGRATIONS=1` 同时调用已有 AI 集成安装流程。普通安装不会自动登录云端、启用 SSH 服务或开放远程 Shell。

构建先验证发布清单的 Ed25519 签名与全部资产哈希，再将该版 SHA-256 固定写入安装器。首次引导信任 HTTPS 提供的脚本，脚本验证二进制哈希与可运行版本后才替换；Shell/PowerShell 自身不声称独立验证 Ed25519。后续 `sshm update` 继续验证签名发布。旧脚本遇到新版本资产会拒绝哈希不匹配，重新获取脚本即可。代理故障不会自动跳过 TLS 证书校验或静默改动系统代理。

手动下载同时设置 `application/octet-stream`、`Content-Disposition` 文件名和链接 `download` 文件名，避免浏览器为 Linux/macOS 无扩展名可执行文件自动添加 `.txt`。


### 新设备登录与本地列表（preview.24）

- 官网 POSIX 命令末尾在调用者 shell 执行 `export PATH="$HOME/.local/bin:$PATH"`，安装完成后当前终端即可使用 `sshm`。单独的 `curl ... | sh` 子进程不能修改父 shell；使用旧命令安装的用户执行一次上述 export 即可。
- `cloud login` / `register` 成功后询问是否同步云端连接到本地列表，回车为是；`--sync` 直接同步，`--no-sync` 跳过。`--import-local` 继续合并本地记录及密钥，同时下载连接索引。
- `cloud sync` 将加密保险库交换完成后，原子更新本地连接索引。`sshm list` 可以直接显示；默认按最近成功 SSH 连接时间倒序，同时间按别名，未连接的排最后。TCP 探测不会增加使用时间。终端交互列表的 `s` 仍可切换名称排序。
- 本地索引包含服务器元数据、账号/保险库绑定和连接 ID，不包含私钥、密码或解锁口令。凭据继续保存在加密保险库，`sshm connect` / `sshm exec` 在终端解锁后从内存使用。云端引用使用 `auth=cloud`，旧客户端无法误当作普通认证连接；原本地 key/agent 连接保持认证方式与密钥路径；匹配当前保险库后登记关联，后续云端删除会先备份再移出列表。非交互 MCP 不会偷偷解密云端凭据，尚未解锁的引用会返回明确提示。
- 按连接身份与路由匹配已有本地记录并保留原密钥路径。同名异连接使用稳定 ID 后缀，重复同步不追加重复行；冲突不自动选边。远端删除移除普通云引用与已关联本地记录；本地记录会先备份。默认连接、项目依赖等受保护记录保留，并在同步输出中提示处理。
- `cloud list` 仍用于查看所有云端连接变体和凭据数量，不承担导入本地列表的作用。


### 已安装 SSHM 的设备快速连接（preview.25）

目标设备登录后运行 `sshm cloud enable --name my-linux --description "我的 Linux"`：添加本机到保险库并开启客户端/网页加密终端。口令只进入当前进程内存，保持进程运行才能接收连接，Ctrl-C 停止；重启需要再次解锁。仅加入列表而暂不允许终端时，运行 `sshm cloud add-device --name my-linux`。也可用 `cloud add-device <设备名称或 ID>` 选其他同账号设备。

网页 devices 新增“保险库”列及“加入保险库”按钮。已加入显示绿色；未加入可直接添加；锁定时显示“解锁查看”。两种入口计算相同的稳定连接 ID；同一设备重命名不会重复添加，不同设备同名在本地使用 ID 后缀区分。客户端连接与普通 SSH 连接保留各自身份，不按名称覆盖。

其他设备执行 `sshm sync`（等同 `sshm cloud sync`），再执行 `sshm connect my-linux`。设备条目走现有 Cloudflare 加密终端中继，不依赖 IP、SSH 端口或 sshd；普通 SSH 服务器继续原配对和 SSH 主机密钥验证。原生客户端与浏览器具有独立的中继角色入口，客户端连接仍需有效账号令牌、保险库签名、在线且已启用的目标。终端帧使用 AES-256-GCM、双向独立密钥与序列计数；preview.26 新代理上的会话无固定总时长上限。账号令牌本身不能打开终端，错误保险库签名被拒绝，撤销设备会关闭连接。

此版客户端设备连接提供交互终端；无交互的设备 exec/MCP 尚未接入加密中继。已有 SSH key/agent 自动化继续原路径。添加到列表不等于允许远程终端，也不等于设备永久在线。

网页删除后，其他新版客户端运行 `sshm sync` 会删除云引用和已经与当前保险库关联的本地记录。原本地配置先写入私有 `config.toml.cloud/removed-local-*.toml` 备份，密钥文件和目标主机保持原样。尚未与该保险库关联的纯本地记录不被删除。默认连接、保护标记、项目及跳板依赖会阻止自动移除，并给出数量提示。删除目录条目不会撤销目标上的 SSH 公钥或关闭已启用的设备代理；停用远程控制应关闭目标代理或撤销设备。


### Continuous terminals and home menu (preview.26)

`sshm` with a TTY opens Home; pipes and MCP never enter the menu. Home shows
version and verified release status, optional account, locked-vault status, local
inventory / local-only / current-vault-linked counts, and a separately recorded
cloud snapshot count and last publication time. Snapshot counts are historical,
not a live unlocked vault. `sshm settings` persists `auto`, `zh-CN`, or `en` plus
color and symbol preferences. `sshm login`, `logout`, and `devices` are shortcuts;
all original `cloud` and SSH automation commands remain available.

The earlier 14-minute deadline was attached to signed session authorization.
There is no comment or tracked fix identifying it as a deadlock workaround.
Version 3 signs the literal `connection` lifetime and mode along with account,
target, epoch, random session ID and a short admission expiry. Both relay and
target reject expired opens and policy/mode tampering. Once accepted, the PTY
has no elapsed-time deadline. The relay retains account-token expiry, revocation,
root-key change, disconnect propagation, concurrency bounds and rate limits.
The former one-hour relay cap is removed. Handshake/write timeouts remain;
client and agent reads time out after 90 seconds without a relay response.
Signing validity and ongoing authorization are separate; cancellation still
closes the PTY (or Windows Job Object) and its child processes.

Only protocol-3 agents advertise continuous terminals. New callers show an
explicit upgrade/restart instruction for older agents; legacy callers retain
their signed legacy expiry. Update **both sides** and restart the target's old
`cloud enable` / `cloud agent` process to activate the new behavior. A running
process cannot adopt a replaced executable until restarted. This does not add
session resumption after network loss, persistent unlock storage, or detached
background command execution.


### Older running clients and local bindings (preview.29)

Old binaries can rewrite TOML without preserving newly added fields. UI
preferences and cloud bindings therefore have separate local JSON sidecars.
Bindings contain only a vault identity, entry ID and route fingerprint; they
contain no passwords, keys or unlocked vault master. They apply only to existing
aliases whose route has not changed. An authenticated `sshm sync` also repairs
stripped legacy references when exactly one encrypted-vault entry matches the
alias and route. Generated duplicate aliases may be consolidated when they have
no local dependencies/protection. Ambiguous matches are never guessed.

A cloud reference missing its binding is shown as needing sync, not counted as a
local-only server. Existing affected installations need one unlocked sync to
rebuild this index. Restart old MCP/agent processes after updating their binaries.
