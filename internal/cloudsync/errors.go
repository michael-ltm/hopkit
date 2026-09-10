package cloudsync

import "fmt"

// Message explains service errors without changing their machine-readable code.
func (e *APIError) Message(language string) string {
	en, zh := "cloud request failed; please try again", "云端请求失败，请重试"
	switch e.Code {
	case "invalid_login":
		en, zh = "account does not exist or password is incorrect; check your username and account password", "账号不存在或密码错误，请检查用户名和账号密码"
	case "unauthorized":
		en, zh = "cloud login has expired or was revoked; run sshm cloud login", "云端登录已过期或已被撤销，请运行 sshm cloud login 重新登录"
	case "account_unavailable":
		en, zh = "username is unavailable; choose another username or run sshm cloud login", "该用户名不可用，请更换用户名；已有账号请运行 sshm cloud login"
	case "registration_closed":
		en, zh = "cloud registration is currently closed", "云端暂未开放注册"
	case "invalid_recovery":
		en, zh = "account or recovery code is incorrect; check the username and recovery code", "账号或恢复码不正确，请检查用户名和恢复码"
	case "invalid_password":
		en, zh = "account password must contain 6-256 characters", "账号密码需要 6–256 个字符"
	case "invalid_account":
		en, zh = "username must contain 3-64 lowercase letters, digits, dots, underscores or hyphens, starting with a letter or digit", "用户名需为 3–64 位小写字母、数字、点、下划线或连字符，且以字母或数字开头"
	case "rate_limited", "link_limit":
		en, zh = "too many requests; please try again later", "操作过于频繁，请稍后重试"
	case "device_limit":
		en, zh = "account device limit reached; revoke an unused device with sshm cloud devices --revoke <device-id>", "账号设备数量已达上限，请用 sshm cloud devices --revoke <device-id> 撤销不用的设备"
	case "revision_conflict":
		en, zh = "cloud data has changed; run sshm cloud sync and resolve any conflicts before retrying", "云端数据已有更新，请运行 sshm cloud sync 并处理冲突后重试"
	case "operation_mismatch":
		en, zh = "sync operation does not match the previous upload; preserve local data and retry sshm cloud sync", "同步操作与上次上传不一致，请保留本地数据并重试 sshm cloud sync"
	case "device_relay_unavailable":
		en, zh = "target device is offline or its relay is unavailable; check the device agent and try again", "目标设备离线或连接服务不可用，请检查设备代理后重试"
	case "relay_unavailable":
		en, zh = "device relay is unavailable or already connected; check the running agent and try again", "设备连接服务不可用或已有连接，请检查正在运行的代理后重试"
	case "invalid_device":
		en, zh = "device information is invalid; check the device ID, label and metadata", "设备信息无效，请检查设备 ID、名称和其他信息"
	case "invalid_link", "link_revoked":
		en, zh = "device link is invalid, expired or revoked; start sshm cloud link again", "设备关联请求无效、已过期或已撤销，请重新运行 sshm cloud link"
	case "link_exists", "link_already_approved", "link_changed":
		en, zh = "device link already exists or has changed; check its status or start sshm cloud link again", "设备关联请求已存在或状态已改变，请检查状态或重新运行 sshm cloud link"
	case "invalid_signature", "invalid_rotation", "invalid_grant":
		en, zh = "cloud security verification failed; check the account and vault, then sync before retrying", "云端安全验证失败，请核对账号和保险库，同步后重试"
	case "client_required":
		en, zh = "this operation requires the sshm command-line client", "此操作需要使用 sshm 命令行客户端"
	case "not_allowed", "origin_denied":
		en, zh = "this session is not permitted to perform the operation", "当前会话无权执行此操作"
	case "not_found":
		en, zh = "requested cloud resource no longer exists; refresh and try again", "请求的云端资源不存在或已被删除，请刷新后重试"
	default:
		switch {
		case e.Status == 429:
			en, zh = "too many requests; please try again later", "操作过于频繁，请稍后重试"
		case e.Status >= 500:
			en, zh = "cloud service is temporarily unavailable; please try again later", "云端服务暂时不可用，请稍后重试"
		case e.Status == 400:
			en, zh = "cloud request is invalid; check your input and client version", "云端请求无效，请检查输入和客户端版本"
		}
	}
	if language == "zh-CN" {
		en = zh
	}
	return fmt.Sprintf("%s (HTTP %d, %s)", en, e.Status, e.Code)
}
