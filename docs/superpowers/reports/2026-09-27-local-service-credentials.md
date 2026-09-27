# 本地优先凭据重构实施记录

日期：2026-09-27。对应 [设计](../specs/2026-09-27-local-service-credentials-design.md) 与 [实施计划](../plans/2026-09-27-local-service-credentials.md)。

## 实现结果

CLI、默认 MCP、SSH 执行和传输共用本机加密凭据解析器。配对或迁移后，不再因 MCP 换进程、兼容 Agent 退出、云登录过期或云端网络异常而反复要求解锁。后台服务提供可选同步和私有 Agent 接口，普通 SSH 不需要等待它。

- 本地凭据使用随机数据密钥与 AES-256-GCM，数据密钥由系统保护。Linux 优先 systemd-user，创建时可回退 Secret Service；保存所用后端后，读取失败不会切换为更弱的存储。
- 新密钥自动生成随机口令，先验证保护材料持久保存，再写加密私钥。MCP `gen_key` 不再要求用户提供口令文件，也不创建明文口令旁文件。
- 目标身份和路线分开：修改 SOCKS、跳板或 ProxyCommand 不会丢失已验证身份。原生私钥被替换后不能利用陈旧 `.pub` 文件继续误选旧凭据。
- 云端仅保存原有端到端加密快照。自动生成密钥的恢复材料也进入该密文快照，已测试在独立设备保护器中恢复并签名。
- 本地云 token 和自动同步所需主密钥进入加密存储；账号登录密码不落盘，服务端继续保存加盐 scrypt 校验值。旧 token JSON 替换前的快照也加密保存，注销时清除该账号秘密命名空间。
- `cloud logout` 停止该账号同步，保留独立 SSH 凭据。`service lock` 才主动锁定本机，重启不会解除；只有本地终端执行 `service unlock` 才解除。
- 接受的云删除停用相关本地身份；冲突保留上一次可用连接、路线和凭据，独立显示 `sync.state=conflict`。401/403、网络失败及其他同步故障退避重试，不终止本地服务。
- 服务具备私有 socket/pipe、同用户校验、并发启动协调、残留 socket 恢复及进程监督。CLI/MCP 的共享解析器不依赖这些进程活着。

修改涉及 `internal/devicekey`、`internal/localstore`、`internal/localservice`，以及 SSH、cloudsync、CLI、MCP 的接入和诊断；同步更新 README、安全/云端/AI 文档和插件参考说明。

## 验证

自动化回归测试使用合成凭据和本机临时服务器。用户随后授权恢复真实连接；本机恢复过程仅在内存中读取所需的私密材料，没有向工具输出、聊天或日志打印私钥、口令或 token。真实主机验证见下文。

已完成：

- 原工作目录的全量 `go test ./...`，包含用户原有浏览器 fixture 修改，全部通过；6 份原有网页/测试文件的复制前后 SHA-256 一致。
- `go vet ./...`。
- `go test -race ./internal/localstore ./internal/localservice ./internal/ssh ./internal/cloudsync ./internal/commands ./internal/mcp`。
- 最终主目录 Linux 本机编译、Windows amd64 / macOS arm64 的 CGO 关闭交叉编译全部通过；候选程序版本与临时配置的只读 `service status` 检查通过。交叉编译不等于原生后端验证。
- Linux 原生 systemd-user 加密：一个全新 CLI、两个独立 stdio MCP，通过实际注册的 `check_ssh` 工具连接 loopback SSH。中间停止并重启服务后继续成功；显式锁定后新的 MCP 和签名请求被拒绝。测试中没有外部 Agent 或云账号。
- 原生加密与签名云快照组合测试：已接受的冲突显示 `conflict`，本地密码凭据继续可用。
- 云端 401/超时、账号命名空间注销、删除/冲突、同目标路线变化、篡改/错误设备/错误配置实例、并发读写、原子写失败和新密钥云端恢复等回归测试。
- 独立代码审查已关闭全部确认的问题；运维参考说明的场景测试从“重启后建议再解锁”改为正确识别共享凭据、首次迁移、主动锁定及网络故障。

原生进程测试命令（需要允许本机 socket 与系统凭据后端）：

```sh
GOCACHE=/tmp/sshm-refactor-go-cache go build -o /tmp/sshm-local-service-e2e ./cmd/sshm
SSHM_DEVICEKEY_E2E=1 SSHM_E2E_BINARY=/tmp/sshm-local-service-e2e \
  GOCACHE=/tmp/sshm-refactor-go-cache go test -race ./internal/mcp ./internal/commands \
  -run 'TestNativeLocalCredentialsAcrossCLIAndMCPProcesses|TestStoredSyncReportsAcceptedConflictWithoutLosingNativePassword' -count=1 -v
```

## 验证边界

- 已验证 Linux 原生加密和进程重启；没有重启这台机器、注销桌面或进行连续 12 小时运行测试。持久身份不设置 12 小时有效期。
- Secret Service 回退、macOS Keychain、Windows DPAPI 和对应平台的原生服务管理器仍需验证。Linux systemd 用户服务已在本机安装并完成重启验证。
- macOS Keychain 后端需要在 macOS 使用 CGO/Security.framework 编译；现有 `.goreleaser.yaml` 的 CGO 关闭产物不能使用它。面向 macOS 发布前需要调整原生构建流程并验证，当前 Linux 交付不宣称完成 macOS 上线。
- `service install` 支持用户登录级 systemd/LaunchAgent/Windows 任务；`--system` 暂不支持。无人登录的开机恢复需要另外配置和验证。
- 保留原有显式浏览器授权及网页终端兼容模式；它们的会话期限未放宽。旧 `cloud agent/watch/link --serve` 没有全部改为新服务的包装命令。
- 配置/密文库的单独泄漏不能直接变成可用 SSH 私钥；完整系统保护材料被窃取，或当前用户/root 已受控，不在此保护边界内。

## 本机交付与真实连接恢复

源码改动在 `/home/ming/Documents/code/my/sshm`；用户原有网页/浏览器测试修改与恢复文件保留。候选程序是 `dist/sshm-local-first`，安装路径为 `~/.local/bin/sshm`。初版、迁移修正版、启动修正版分别备份了上一版程序，原始程序仍在 `~/.local/bin/sshm.before-local-first-20260927`。本机 SSHM Skill 的三份参考说明及原有备份也保留。

用户执行首次迁移后遇到 grokbot 私钥口令错误，并明确要求恢复直接连接；现已完成真实迁移和用户登录自动启动，无需再执行整个 setup 流程。

| 别名 | 恢复方式 | 实际验证 |
| --- | --- | --- |
| `grokbot` | 用本机已有的私密恢复旁文件验证并保存原密钥，保留原件；没有要求用户找回未知口令 | 旧 MCP、独立新 MCP 均认证并执行 `hostname` 成功 |
| `aliyun-hcg-prod` | 从迁移前加密备份恢复精确目标及路线；经现有连接追加一个新的加密密钥对应公钥，验证新凭据后改为本地独立身份 | 旧 MCP、独立新 MCP 均成功；原云删除标记没有被清除 |
| `racing-server` | 经已验证的现有连接追加新公钥，使用本机加密保存的新密钥认证成功后才切换原别名 | 旧 MCP、独立新 MCP 均认证并执行 `hostname` 成功 |

HCG 与 racing 的远端原 `authorized_keys` 都先备份为 `authorized_keys.before-sshm-local-first-20260927`，然后仅追加新公钥；全部旧授权保留。主机密钥检查未绕过。新私钥带随机口令，恢复材料在本机加密库内，不新建明文口令旁文件。

为了让已打开、仍运行旧程序的 Codex 会话立即使用，已把这三个经过验证的精确密钥加入现有同用户 Agent，其他身份保持不变。持久连接另行通过了禁用外部 Agent 的测试，不依赖这个兼容步骤。

本机 `service setup` 已完成，无需输入旧 SSH 口令。`service install` 已成功注册并启用 systemd 用户服务，接管旧后台实例，并进行了一次真实服务重启。重启后三个目标分别在全新 MCP 进程内成功认证、执行命令；每个进程的 `SSH_AUTH_SOCK` 都指向不存在的 socket。最终版本为 `0.8.0-cloud-preview.34.local-first.3`，状态为 `running=true`、`configured=true`、`locked=false`，systemd 的真实状态为 `enabled` 和 `active`。

这里验证的是后台服务重启与新进程恢复，没有重启整台电脑。自动启动属于用户登录级；当前用户在该机器上正常运行 SSHM 时，持久身份没有会话有效期。仍缺原私钥或原口令的其他旧条目会单独报告，未声称全部历史主机都已恢复。

## 首次迁移与启动安装修正

- `service setup` 默认读取并验证现有安全恢复文件。未知、缺失或错误的旧密钥口令不会中断其他连接的迁移；仅显式使用 `--ask-passphrases` 才询问已知旧口令。空输入或错误口令单独跳过，真实存储/加密故障仍报错。
- 兼容旧版 `WriteRecovery` 的两行固定注释头，不会把以 `#` 开头的真实口令误当注释。恢复文件的私有权限、大小和符号链接检查保留。
- 首次保险库解锁和后续导入都先过滤已停用身份，避免旧快照恢复用户已接受删除的云凭据。
- Linux 后台启动安装发现当前 Codex 进程缺少用户会话环境。安装器现在仅在两项环境变量都未设置时，验证 `/run/user/<uid>` 的属主、0700 权限及同用户 bus socket，然后只为子命令补入环境；显式设置不覆盖。未改变系统加密后端。
- 系统保护命令超时保留 context 错误，避免误报为设备保护不可用；取消/超时不会触发更换保护后端。

上述问题包含 RED/GREEN 回归、真实 PTY 交互用例、相应 race 测试与独立审查。最终完整 `go test ./...`、`go vet ./...` 和 Linux 构建通过；需要临时网络/socket 的测试在允许本机 socket 的执行环境中运行。跨平台的安装器修改已进行 Darwin/Windows 编译验证。

## 云同步误报超时修正

恢复连接后发现后台仍显示 `offline`。只读、带账号认证的云快照请求实际成功，耗时约 1.3 秒；逐段计时确认，一轮三次本地导入就需要约 22.1 秒，已经超过后台整轮 20 秒限制。直接解析同一加密凭据被多个目标重复执行。

修正仅在单次 `RememberVault` 调用内缓存直接解析结果（包括直接解析失败）。本地恢复文件依旧逐目标验证，不能把某个目标的恢复结果借给其他目标；新一轮导入重新解析，接受了新内容后不会使用旧缓存。目标绑定、指纹、删除标记和冲突检查保留，未延长后台超时或改变同步顺序。

真实相同数据的三次本地处理从约 22.1 秒降到 12.25 秒；每次导入仍为 21 个成功、48 条缺旧口令提示，结果一致。新回归覆盖共享凭据签名、同 ID 新内容、不同目标的恢复顺序；完整 Go 测试、vet、race 及独立审查通过。安装最终版并重启用户服务后，真实 `sync.state=ready`，systemd 为 `active/running`、`Result=success`、`NRestarts=0`。

最终验证期间 grokbot 曾出现一次 TCP/SSH 超时，随后旧 MCP 和禁用外部 Agent 的最终版 CLI 均执行命令成功。这个短时链路波动没有触发解锁，也未通过修改主机密钥检查或放宽凭据保护来处理；本次不承诺公网链路永远不超时。

## 加密备份

迁移前备份：

`/home/ming/.local/state/sshm/backups/pre-local-first-20260927T113850Z`

包含 69 个文件、48 个服务器配置、全部 6 个配置引用的私钥文件，以及原有 SSH/SSHM 数据和程序。已解密核对每个文件的 SHA-256，没有写出明文。

三台连接恢复及服务安装后的中间备份：

`/home/ming/.local/state/sshm/backups/post-connection-recovery-20260927T122806Z`

包含 78 个文件、46 个当前配置、全部 7 个配置引用的私钥文件，以及新的持久凭据库、当前/旧程序、启动单元。已执行相同的解密完整性验证。

最终版本及后台同步正常后的备份：

`/home/ming/.local/state/sshm/backups/post-connection-recovery-20260927T123608Z`

包含 79 个文件、46 个配置、全部 7 个引用的私钥文件；所有文件已解密核对 SHA-256，`plaintext_written=false`。前两份备份均保留。

备份中的归档使用随机秘密加密，该秘密再由 systemd 用户/本机保护封装。备份不包含操作系统保护密钥，属于同机同用户恢复包。每份目录有 `README.md`、`verify.py` 和 `VERIFIED.json`；验证脚本仅在显式 `--extract-to` 时向全新的私有暂存目录写明文，不覆盖运行中的配置。不要仅替换为旧程序就尝试回退：旧版不理解新的受保护云 token 引用。
