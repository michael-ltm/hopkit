# 保险库解锁后 SSH 全断 — 原因与 Mac 恢复步骤

日期：2026-09-09。账号与保险库仍在本机；不要把解锁口令、恢复码或私钥发到聊天、提交或文档里。

## 现象

GrokBot（Linux）上 MCP / `sshm exec` 对几乎所有主机失败。典型错误：

- `auth=key`：私钥已加密，ssh-agent 里没有对应身份
- `auth=cloud`：`unsupported auth "cloud"` 或 `cloud credential is locked`

TCP 往往是通的。问题在认证，不在网络（Tailscale/内网主机除外）。

## 根因

提交 `7cf8f30`（encrypted cloud management）把 `CloudEntry` 做成了硬锁：`buildAuth` 一看到云端索引就拒绝本地 key/agent，并提示去解锁保险库。MCP 不会解锁保险库，所以普通 SSH 路径被掐断。

同时存在三条独立限制：

1. **清单发布**把大量记录改成 `auth=cloud` 且清掉 `key_path`。旧 MCP 进程写配置时还丢掉了 `cloud_entry`。
2. **GrokBot 本地 8 把加密钥**（`prod-go`、`dps-ts`、`elons-mac-mini`、`macbookair`、`aivbrowser`、`msg-linux`、`prod-7w`、`prod-dev`）是 GrokBot 自己生成的。公钥和保险库里可解密的那 12 把不是同一套。保险库里也没有它们的 passphrase sidecar。Linux 的 agent 不持久，进程一死钥匙就没了。
3. **设计本意**是「输入保险库口令就能连」。CLI `sshm connect` / `sshm cloud connect` 会提示口令；MCP 不会。Linux 上必须有一个保持运行的 `sshm cloud agent` 把身份装进 session agent。

## 本次代码修复（已提交）

- `CloudEntry` 不再一票否决本地 key/agent。
- `auth=cloud` 可走本地钥匙，或按 `~/.ssh/sshm-keys/<alias>.pub` 以及同名 `alias~xxxxxxxx.pub` 在 agent 里精确匹配。
- `sshm cloud agent` / `link --serve` 解锁后：启动 session agent（没有 `ssh-agent` 二进制时用进程内 agent），把保险库里能解密的身份装进去，**不改私钥文件、不跑 `--harden-keys`**。
- 也会尝试用保险库里 `kind=password` 的 sidecar 去解本地加密钥。GrokBot 这批钥实测对不上，所以仍然解不开。
- `sshm connect` 对 `auth=cloud` 即使缺少 `cloud_entry` 也会按别名去保险库查找。

Mac 的优势：`ssh-add --apple-use-keychain` 能把口令留在登录钥匙串里，重启后不必再靠 GrokBot 那批丢失的 sidecar。

## 在 MacBook Air 上做什么

当前仓库 `main` 已包含上述修复。Mac 上不要用旧的 `0.8.0-cloud-preview.33` 去判断「保险库解锁后 MCP 该不该能连」。

```sh
cd /path/to/sshm
git pull origin main
go test ./internal/ssh ./internal/cloudsync ./internal/keystore ./internal/mcp
go build -ldflags "-X github.com/michael-ltm/sshm/internal/commands.Version=0.8.0-cloud-preview.33-restore" -o "$HOME/.local/bin/sshm" ./cmd/sshm
sshm version   # 应显示 0.8.0-cloud-preview.33-restore
```

在本机终端解锁（口令只打在这个提示里）：

```sh
sshm cloud agent
```

看到 `Loaded N vault identities` 后保持进程运行，另开一个终端：

```sh
sshm exec ttbee-new hostname
sshm exec prod-7w hostname
sshm exec prod-go hostname
sshm exec elons-mac-mini hostname
```

Mac 若曾用同一保险库导入过钥匙，`prod-go` 等 GrokBot 加密钥**有可能在 Mac 上能连**（钥匙串或当时导入的可解密凭据）。那就是这台 Linux 上缺的东西。

连上 `prod-go` 之后，把当前 Mac 的公钥补进 GrokBot 也能用的 `authorized_keys`，或把可解密身份留在保险库里，Linux 才能重新连。不要把私钥拷进聊天。

## GrokBot 上已验证（2026-09-09）

保险库解锁后装入 **12** 个身份。CLI 已通：

`ttbee-new`、`bandwagon-relay`、`xm-prod`、`ajie_new_prod`、`aliyun-hcg-prod`、`armbian`、`james-81`、`prod-7w`（走保险库身份，不是 GrokBot 本地钥）、`ms01-pve-ts~877b50fd`

网络超时（不像认证失败）：`grokbot`、`iphonex`、`openwrt`、`yzh`、`fp-browser-vultr`

GrokBot 本地加密钥、保险库对不上、因此这台 Linux 仍失败：

`prod-go`、`dps-ts`、`elons-mac-mini`、`macbookair`、`aivbrowser`、`msg-linux`、`prod-dev`

`sshm test` 只证明 TCP，不证明 SSH 认证。请用 `sshm exec <alias> hostname`。

## 不要做的事

- 不要再跑 `sshm cloud link --harden-keys`。那会加密本地钥并删 `.passphrase` sidecar。
- 不要把保险库口令、恢复码、私钥放到命令行参数、环境变量或聊天里。
- 不要以为关掉 `sshm cloud agent` 后 Linux MCP 还能继续用刚装进内存的钥匙。
- 当前 Grok 会话里的 MCP 若仍显示 `runtime_version: 0.8.0-cloud-preview.33`（没有 `-restore`），需要重启 MCP 才会加载新二进制。

## 相关代码

- `internal/ssh/client.go` — 去掉 CloudEntry 硬锁；cloud/agent 回退
- `internal/cloudsync/load_agent.go` — 解锁后装入 agent
- `internal/keystore/ensure_unix.go` — 无 `ssh-agent` 时的 session agent
- `internal/commands/cloud_link.go` — `runCloudAgent` 里加载身份
- `internal/commands/connect.go` — cloud 记录按别名解锁
