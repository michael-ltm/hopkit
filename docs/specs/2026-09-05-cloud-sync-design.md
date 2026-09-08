# SSHM Cloud 实施与验收记录

日期：2026-09-05。实现为 Cloudflare Worker + 每账号 SQLite Durable Object；未采用 D1。控制台与 API 位于 `https://sshm.yunmini.net`，精确路由 `sshm.yunmini.net/*`；原有 `*.yunmini.net/*`、ledger 和 ab-relay 路由保留。

## 实现

- CLI 新增 `cloud` 命令族，本地 schema 5、现有 SSH 命令与 MCP 路径不变。账号保险库保存在 `<configPath>.cloud/state.json`，包含密文和会话令牌；无明文私钥临时文件。
- 原子写入、进程锁；POSIX 0600，Windows 当前用户/LocalSystem 保护 DACL。网络不持有原本地配置锁。
- 客户端随机 256 位主密钥；Argon2id 64 MiB / t=3 / p=4 派生包装密钥；AES-256-GCM 加密主密钥与完整保险库。HKDF 分离数据、签名、恢复包装和账号恢复用途。
- Ed25519 签名绑定账号、基准版本、操作 ID 和整个密文；服务端 CAS，异步签名校验后再次验证会话与版本。客户端拒绝签名替换、跨账号替换、已见历史回滚和错误版本关系。
- 账号密码使用 scrypt N=32768 / r=8 / p=3，随机盐；会话只存 SHA-256 摘要。账号密码与保险库解锁口令必须不同。恢复码的账号授权派生值与解密包装派生值分离。
- 服务端限速、请求大小限制、统一认证错误、不记录请求体和任意异常、禁止跨站写入；前端自托管脚本、CSP、HttpOnly Cookie，无第三方 CDN 脚本。
- 数据按连接身份和路线保留稳定 ID。首次同连接合并别名与多凭据；完整对象三方合并，冲突保存双方，删除留 tombstone。云端始终只收到保险库密文。
- 控制台参考用户提供的 Tailscale Machines 布局：右上角登录、侧边导航、设备表格、搜索筛选、分组、标签、详情编辑、撤销、添加设备指引。设备心跳与浏览器会话区分。
- 浏览器保险库使用本地 Argon2id 与 Web Crypto，与 Go 双向互通。编辑后重新签名和加密；并发版本冲突拒绝覆盖。页面离开或闲置自动锁定。

完整操作说明见 [cloud-sync.md](../cloud-sync.md)。

## 扫描结果

通过继承本机 Agent 环境的 SSHM MCP 完成三台远端的 SSH 认证、安装路径和配置只读扫描。未导出实际私钥或密码。

| 来源 | 扫描时版本 | 记录数 | key / agent / password |
|---|---|---:|---|
| 当前 Mac | 0.7.0+3ac3c2c.copyidfix | 37 | 34 / 3 / 0 |
| Mac mini | 0.7.0+5835243 | 31 | 27 / 3 / 1 |
| GrokBot | 0.7.0 | 8 | 8 / 0 / 0 |
| att-dev | 0.7.0 | 42 | 39 / 1 / 2 |

共 118 条记录，53 个别名。host/port/user 有 49 组候选连接，加上代理和转发差异有 58 组路线配置。这不是已验证的物理服务器数量。

- grokbot 的三个别名指向同一候选连接，可以合并别名。
- ms01 多个入口有不同路线及 key/agent 认证，保留各连接方式。
- att-dev 同名记录有不同登录用户和公钥；windev 同名记录有不同地址，均不能按别名覆盖。
- 26 个同名条目旁边的 .pub 摘要不同。所有配置引用的私钥路径存在；没有逐个解锁或验证所有目标的登录。
- Agent 密钥不可导出，未保存的 SSH 密码须由用户在本机输入。

## 验证证据

- `go test ./...`、`go vet ./...`；本地原子文件保护、合并、并发删除、冲突解决、随机 nonce、错误口令和篡改拒绝。
- 本地 workerd 后端测试：注册登录、CAS 并发、幂等重试、签名拒绝、账户隔离、恢复、撤销、HttpOnly 会话、跨站拒绝、心跳及分组标签编辑。
- 线上 Go E2E：合成私钥和密码加密上传、另一客户端解密；临时 SSH 服务真实密钥/密码认证；独立修改合并、重试、轮换主密钥、恢复及撤销。测试账号完成后删除。
- Mac mini、GrokBot 和 att-dev 原生云同步测试均通过；Windows 的受保护缓存写入在实际 Windows 上通过。
- Go → 浏览器解密与编辑 → Go 解密验证通过，修改分组标签后原有合成密码完整保留。
- 浏览器新增生产依赖检查未发现已知公开漏洞；这不等于独立密码学审计。

真实用户账号、真实凭据首次整合仍需用户在可信终端设置账号密码和独立解锁口令。上述成功测试均使用明确合成数据，不能当作 118 条真实记录已完成迁移的证据。

## 尚未交付的能力与安全边界

没有网页 Shell、网络中继或任意命令代理。安全接入需要设备主动连接、逐台启用、会话授权与端点验证，不能直接复用登录令牌开放执行权限。现有 presence 仅发送心跳。

设备管理名称/标签/心跳是服务端可见的账号元信息；SSH 服务器资料全部在保险库密文中。服务端也可见请求来源、时间、密文长度及版本。加密不防御已被控制的解锁客户端；网页还依赖部署代码的完整性。新设备完全失去可信历史时，不能单靠云端证明不存在历史回滚。

撤销会话不能收回旧数据，换保险库主密钥不能撤销已泄漏的 SSH 凭据。原本地文件保持原状；当前没有强制迁移清理、MFA、邮箱找回、系统钥匙串解锁或设备配对协议。

## 构建与部署

```sh
python3 scripts/build-cloud-clients.py
pnpm --dir cloud install --frozen-lockfile
pnpm --dir cloud run types
pnpm --dir cloud run check
pnpm --dir cloud test
pnpm --dir cloud run deploy
```

Wrangler OAuth 使用 user:read、account:read、workers:write、workers_routes:write、workers_scripts:write、workers_tail:read、zone:read 和 offline_access；凭据留在 Wrangler 用户目录，不进仓库。实际下载文件位于忽略的 cloud/public/downloads，部署 Worker Static Assets；源码不包含客户配置或账号密码。

参考：[Cloudflare 路由](https://developers.cloudflare.com/workers/configuration/routing/routes/)、[SQLite Durable Objects](https://developers.cloudflare.com/durable-objects/api/sqlite-storage-api/)、[OWASP 密码存储](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)、[Argon2 RFC 9106](https://www.rfc-editor.org/info/rfc9106/)、[noble-hashes](https://github.com/paulmillr/noble-hashes)。

## 最终部署与更新验收

- 当前 Worker 部署：`0b9c766b-ba52-4a1f-82f4-4f524b657f95`。
- 当前 Mac、Mac mini、GrokBot、att-dev 有效 CLI 均已安装 `0.8.0-cloud-preview.8`；各自安装前后 `list --json` 完整结构相同，记录数分别为 37 / 31 / 8 / 42。
- 有效二进制旁保留 `.pre-cloud-20260905` 备份。未覆盖本地配置、已有私钥或已运行的旧 MCP 会话。
- 四台设备的签名更新检查均通过。隔离旧版 `0.8.0-cloud-preview.2` 实际从线上更新到 `.3`，验证下载大小与 SHA-256、保留回滚二进制、再次检查无更新；不属于仅模拟测试。
- 新增测试验证发布签名被篡改、过期清单、损坏下载和激活失败；错误时原安装保留或恢复。
- 新增 Skill 安装/刷新测试验证额外笔记保留、用户修改拒绝覆盖、已有插件不重复安装。当前用户的 Codex 与 Claude Code 已有插件缓存，未替换这些缓存或重复注册 MCP。
- 网页真实表单完成登录、三台合成设备展示、设备分组标签修改、保险库解锁及服务器分组标签的加密保存。线上保存结果由 Go 解密并验证合成 SSH 密码保持完整。后台标签页自动锁定经实测生效。

发布签名公钥固定在 `internal/updater/update.go`。私钥存于维护者的用户配置目录（仓库外、0600），不能提交或上传到 Worker。先构建客户端，再执行：

```sh
go run ./scripts/sign-cloud-release --key /path/outside-repository/signing.key
pnpm --dir cloud run deploy
```

首次生成签名密钥必须单独使用 `--init-key`，把输出的公钥固定到客户端后重新构建；不要在每次发布时重新生成信任根。发布清单有 90 天有效期。后续 CI 需要安全提供同一发布签名密钥或明确的轮换流程。

### 六字符口令更新验收

- 账号密码和新保险库解锁口令最低 6 个 Unicode 字符；后端注册、登录、改密码、恢复及网页校验一致。Argon2id、scrypt 与加密协议参数不变。
- 本地测试覆盖 5 字符拒绝、6 字符接受（ASCII、中文、表情）；完整 Go 测试、go vet 和 Cloudflare 4 项测试通过。
- 生产端以临时随机 6 字符账号密码及解锁口令完成注册、登录、加密同步、SSH 凭据验证和账号恢复，临时账号已删除。浏览器读取生产登录页，HTTP 200、minlength=6。
- 四台设备通过签名更新器从 .3 更新至 .4，逐台比较 list --json 完整结构一致；更新检查均显示最新。Windows npm .cmd MCP 参数保留测试在 att-dev 原生通过。
- 用户已在本地终端完成真实账号注册与本机导入；仅检查状态元数据，云版本为 2，无待上传修改。其他三台设备的账号接入与加密合并仍待各设备交互登录。

### Update / Skip 与版本显示验收（preview.8）

- 终端列表发现签名新版时显示 Update now / Skip for now，默认 Skip；手动 update 使用相同选择。自动更新始终需要用户选择或显式 --yes。
- macOS PTY、Windows ConPTY 使用临时旧版本测试程序验证 Skip 不替换文件、Update 真实下载并切换到正式签名发布；macOS 还验证首次联网检查、手动 Skip、篡改缓存签名不触发菜单。
- 实测一次首次自动检查因网络超时继续进入本地列表；自动检查保留 1.5 秒预算并在 10 分钟后重试。后续首次检查通过，不将网络可用性描述为无条件保证。
- 四台有效客户端均通过签名更新从 .7 升至 .8，逐台 list --json 安装前后完整相同；当前更新检查均为最新。
- 窄窗口保持运行版本显示，新增标准 --version；MCP/JSON/管道不等待更新菜单。插件管理的 Skill 仍通过原应用更新。
