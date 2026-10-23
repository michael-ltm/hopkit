const failures={ssh_credential:'所选设备尚未解锁对应 SSH 密钥，请先在该设备加载 SSH Agent',invalid_target:'连接信息无效',vault_unavailable:'设备无法获取或验证保险库，请稍后重试',target_removed:'连接已删除，请刷新保险库',target_conflict:'此连接存在同步冲突，请先处理',source_device_required:'此连接使用本地代理配置，请选择保存原配置的设备',choose_credential:'有多个密码，请选择要使用的凭据',invalid_credential:'凭据已改变，请刷新保险库',key_locked:'私钥尚未解锁，请在所选设备加载对应 SSH Agent 密钥，或使用可解密的云端凭据',password_unavailable:'保险库尚未保存此服务器的密码',pty_unavailable:'服务器未能打开交互终端',ssh_authentication:'SSH 认证失败，请检查所选设备的密钥或保存的凭据',ssh_host_key:'服务器主机密钥校验失败，请先在可信客户端核对',ssh_timeout:'SSH 连接超时，请更换能访问目标的设备',ssh_connection:'所选设备无法连接 SSH 目标',ssh_refused:'目标拒绝 SSH 连接，请检查端口和服务',ssh_dns:'无法解析目标地址',ssh_unknown:'SSH 连接未成功',connection_failed:'连接未成功，请检查所选设备和目标服务器'};
export function terminalFailureMessage(payload) {
 const d=payload.diagnostics;
 if(payload.data==='pty_unavailable' && d?.ssh_authenticated===true){
  if(d.reason_code==='cancelled')return 'SSH 认证成功，终端连接已取消';
  if(d.reason_code==='timeout')return 'SSH 认证成功，终端启动超时';
  if(d.stage==='pty_request' && d.pty_requested===true && d.pty_granted===false){
   if(d.reason_code==='pty_denied' && d.suggested_action==='explicit_exec')return 'SSH 认证成功，但服务器拒绝分配交互终端。受限账号可在本地使用 sshm exec <alias> --raw-environment <command> 执行明确获准的命令。';
   if(d.reason_code==='pty_request_failed')return 'SSH 认证成功，但终端请求未完成，请检查连接状态';
  }
  if(d.stage==='shell_start' && d.reason_code==='shell_start_failed' && d.pty_granted===true)return 'SSH 认证成功且终端已分配，但远端 shell 启动失败';
  if(d.stage==='session_open' && d.reason_code==='session_open_failed')return 'SSH 认证成功，但无法打开远端会话';
  if(d.stage==='stdin_pipe' && d.reason_code==='stdin_pipe_failed')return 'SSH 认证成功且终端已分配，但输入通道无法打开';
  if(d.stage==='terminal_size' && d.reason_code==='terminal_size_failed')return '终端尺寸无效，请调整窗口后重试';
 }
 return Object.hasOwn(failures,payload.data)?failures[payload.data]:failures.connection_failed;
}
