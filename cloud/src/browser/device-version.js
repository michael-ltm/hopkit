// Installation reports, live relay processes and legacy heartbeats have different
// meanings. Never infer an installed version from an arbitrary old heartbeat.
export function deviceVersion(d,agent,latest,now=Date.now()){
 const installed=d.installed_version||'',checked=d.installed_checked_at||0;
 const recent=!!checked&&now-checked<90_000;
 const runtime=agent?.runtime_version||'';
 const restart=!!installed&&!!runtime&&installed!==runtime;
 let detail=agent?(runtime?'代理 '+runtime:'旧代理在线 · 版本未上报 · 请重启新版'):'代理未连接';
 if(restart)detail+=' · 待重启';
 if(!agent&&d.version)detail+=' · 上报进程 '+d.version;
 return {installed,checked,recent,runtime,restart,detail,
  label:installed||'安装版本未确认',
  kind:!installed||!latest||!recent?'unknown':installed===latest?'latest':'outdated',
  help:!installed?'旧客户端仅上报进程版本。运行新版 sshm 或 cloud report-version 可刷新安装信息。':
   '最近确认的客户端安装版本；代理及 MCP 进程需要重新启动才会加载新版本。'};
}
