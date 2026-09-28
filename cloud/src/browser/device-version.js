// Installation reports, live relay processes and legacy heartbeats have different
// meanings. Never infer an installed version from an arbitrary old heartbeat.
export function deviceVersion(d,agent,latest,now=Date.now()){
 const installed=d.installed_version||'',checked=d.installed_checked_at||0;
 const recent=!!checked&&now-checked<90_000;
 const runtime=agent?.runtime_version||'';
 const restart=!!installed&&!!runtime&&installed!==runtime;
 const detail=!agent?'网页终端未连接（可选）':
  (restart?'网页终端待重启':'网页终端已连接')+' · '+(runtime?'运行 '+runtime:'版本未上报');
 return {installed,checked,recent,runtime,restart,detail,
  label:installed||'安装版本未确认',
  kind:!installed||!latest||!recent?'unknown':installed===latest?'latest':'outdated',
  help:!installed?'安装版本尚未确认。运行 sshm cloud report-version 可刷新安装信息。':
   '最近确认的客户端安装版本。网页终端为可选功能，不影响本地 SSH 和后台同步。'};
}
