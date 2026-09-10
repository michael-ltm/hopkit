# prod-go / prod-dev SSH 密钥丢失恢复 — 分析交接文档

日期：2026-09-09
状态：历史诊断记录；不代表当前运行状态。敏感地址、保险库标识和恢复材料位置已脱敏。
目标：恢复对两台服务器的 SSH 登录，**不走救援模式**，只从「当前电脑 / macmini / grokbot」本地找。

---

## 1. 问题与目标

sshm 的 cloud sync 把两台服务器的私钥收进云保险库并删了本地引用，现在：

- **prod-go** = `<host-address>`（root，port 22）
- **prod-dev** = `<host-address>`（root，port 22）

私钥找不到了。要求从本地三台机器找回（不做 VPS 救援）。

对照（正常）：**prod-7w** = `<host-address>`，密钥 `~/.ssh/id_ed25519_prod7w_new`，目前可用。

---

## 2. 已确认的事实（带证据）

### 2.1 配置里两台条目已被移除
- 当前 `~/.config/sshm/config.toml`：**只剩 prod-7w**，prod-go/prod-dev 已被删。
- 备份 `~/.config/sshm/config.toml.bak-repair-20260909`（第 897 行起 prod-dev、第 926 行起 prod-go）：
  - prod-dev：`host=<host-address>`、`auth=cloud`、`cloud_entry=<vault-record-id>`
  - prod-go：`host=<host-address>`、`auth=cloud`、`cloud_entry=<vault-record-id>`
  - 两者 `cloud_vault=<vault-record-id>`
- 移除时本地备份：`~/.config/sshm/config.toml.cloud/removed-local-<local-id>.toml`（第 894/923 行有 prod-dev/prod-go）。

### 2.2 云保险库里没有这两台（已解锁核实）
`sshm cloud list --use-recovery` 输出里 **没有 prod-go、没有 prod-dev**；只有 prod-7w（两条，`.225`）。用户确认 prod-go 之前被手动从 cloud 删了。prod-dev 也不在。

### 2.3 当前电脑 ~/.ssh
- `id_ed25519_prod-go`：**今天 09:11 重新生成的**，其公钥与服务器上该有的 `~/.ssh/sshm-keys/prod-go.pub` **对不上**（是无效新钥）。有 `.passphrase` sidecar。
- **没有** `id_ed25519_prod-dev`。
- 服务器应有公钥（`~/.ssh/sshm-keys/`）：
  - `prod-go.pub` → SHA256:`<public-key-fingerprint>`
  - `prod-dev.pub` → SHA256:`<public-key-fingerprint>`
  - 这两个公钥对应的**私钥已丢失**（不在 vault、不在本地、不在 macmini）。

### 2.4 elons-mac-mini（<host-address>，用户 elonjack，可直连）
`~/.ssh/` 和 `~/.ssh/sshm-sync/` 里只有 prod-7w / ajie_new_prod / xm-prod / discord-prod / lilishop-prod / aliyun-hcg-prod 等，**没有 prod-go/prod-dev**。

### 2.5 按文档，这两把是「GrokBot 本地生成的 8 把加密钥」之一
见 `docs/2026-09-09-vault-unlock-ssh-recovery.md`（本次代码仓库里）：
> GrokBot 本地 8 把加密钥：`prod-go`、`dps-ts`、`elons-mac-mini`、`macbookair`、`aivbrowser`、`msg-linux`、`prod-7w`、`prod-dev`，是 GrokBot 自己生成的，公钥与保险库里可解密的那 12 把不是同一套。

→ **私钥最可能在 GrokBot 的本地 `~/.ssh/`（加密钥 + 可能的 `.passphrase` sidecar）。**

---

## 3. 关键文件 / 路径清单

| 用途 | 路径 |
|---|---|
| 恢复码（能解锁保险库） | `<local-recovery-file>`（本地恢复材料，不应提交其内容） |
| sshm 二进制 | `~/.local/bin/sshm`（版本 `0.8.0-cloud-preview.33-restore12`） |
| 当前配置 | `~/.config/sshm/config.toml` |
| 修复前备份配置 | `~/.config/sshm/config.toml.bak-repair-20260909` |
| 移除的本地配置 | `~/.config/sshm/config.toml.cloud/removed-local-*.toml` |
| 服务器应有公钥 | `~/.ssh/sshm-keys/prod-go.pub`、`prod-dev.pub` |
| 上次同类事故（prod-7w）记录 | `~/.claude/projects/-Users-ming/memory/project_ssh_keys_encrypted.md`、`project_sshm.md` |

---

## 4. 可用的访问通道

- **elons-mac-mini**：Tailscale `<host-address>`，user `elonjack`，key `~/.ssh/id_ed25519`，直连可用。
- **GrokBot（grokbot-ming）**：
  - Tailscale `<host-address>`（linux，active）。旧 removed-local 配置：user `box`、port 22、key `~/.ssh/id_ed25519_grokbot-ming`。
  - ⚠️ 实测 **22 端口 Connection refused**（sshd 没起或没绑到 tailscale0 网卡）。
- **GrokBot（sshm 云设备）**：别名 `GrokBot`，`auth=cloud`，host `sshm-device-*.invalid`。MCP 报 `cloud credential is locked`。

---

## 5. 恢复步骤建议（按优先级）

### 步骤 A：解锁保险库，让 sshm 云能连 GrokBot
```sh
sshm cloud agent --use-recovery
```
在本地交互终端输入恢复码，**保持进程运行**（会打印 `Loaded N vault identities`）。解锁后即可经 sshm（CLI 或 MCP）连云设备「GrokBot」去搜它 `~/.ssh`。

### 步骤 B：搜 GrokBot 本地
在 GrokBot 上找 `id_ed25519_prod-go`、`id_ed25519_prod-dev` 及同名 `.passphrase` sidecar：
```sh
ls -la ~/.ssh/ | grep -iE 'prod|ed25519'
find ~/.ssh -maxdepth 2 -iname '*prod*'
```
（若走 Tailscale 直连，需先把 grokbot 的 sshd 拉起来，或确认端口。）

### 步骤 C：验证找回来的钥匙能不能连
```sh
ssh -i <找回的私钥> -o BatchMode=yes root@<host-address> 'hostname'
ssh -i <找回的私钥> -o BatchMode=yes root@<host-address> 'hostname'
```
- prod-dev `.205` 实测可达，`Permission denied (publickey,password)`——密码登录也开着，若知道 root 密码可先登进去补 authorized_keys。
- prod-go `.119` 实测 `Connection closed by <host-address> port 22`（连接被服务器直接关掉，疑似 fail2ban/端口敲门/sshd 配置问题，需排查）。

### 步骤 D：兜底
若钥匙确实彻底丢了：重新生成新钥 + 把公钥装到服务器。prod-dev 有密码登录可走；prod-go 需先解决 `.119` 连接被关的问题。

---

## 6. 注意事项（不要做）

- **不要**盲目跑 `sshm cloud sync`——`sshm cloud status` 显示 `unsynced: true`，直接 sync 可能把「prod-go/prod-dev 已删」推上云端，永久删掉。
- **不要**跑 `sshm cloud link --harden-keys`——会加密本地钥并删 `.passphrase` sidecar。
- **不要**把恢复码/口令/私钥明文写进聊天、命令行参数或提交。
- 上次 prod-7w 事故（7-8）的恢复方式是「改用预先装好的恢复钥 `id_ed25519_prod7w_new`」，可参考同思路。
