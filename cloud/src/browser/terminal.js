import { Terminal } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';
import { b64,signVault,shellCipher } from './vault.js';
const bytes=s=>Uint8Array.from(atob(s.replaceAll('-','+').replaceAll('_','/')),c=>c.charCodeAt(0));
const failures={ssh_credential:'所选设备尚未解锁对应 SSH 密钥，请先在该设备加载 SSH Agent',invalid_target:'连接信息无效',vault_unavailable:'设备无法获取或验证保险库，请稍后重试',target_removed:'连接已删除，请刷新保险库',target_conflict:'此连接存在同步冲突，请先处理',source_device_required:'此连接使用本地代理配置，请选择保存原配置的设备',choose_credential:'有多个密码，请选择要使用的凭据',invalid_credential:'凭据已改变，请刷新保险库',key_locked:'私钥尚未解锁，请在所选设备加载对应 SSH Agent 密钥，或使用可解密的云端凭据',password_unavailable:'保险库尚未保存此服务器的密码',pty_unavailable:'服务器未能打开交互终端',ssh_authentication:'SSH 认证失败，请检查所选设备的密钥或保存的凭据',ssh_host_key:'服务器主机密钥校验失败，请先在可信客户端核对',ssh_timeout:'SSH 连接超时，请更换能访问目标的设备',ssh_connection:'所选设备无法连接 SSH 目标',ssh_refused:'目标拒绝 SSH 连接，请检查端口和服务',ssh_dns:'无法解析目标地址',ssh_unknown:'SSH 连接未成功',connection_failed:'连接未成功，请检查所选设备和目标服务器'};
export async function openTerminal(v,device,agent,container,status,target){
 if(!agent.continuous)throw new Error('目标代理需升级：在目标设备运行 sshm update，停止旧代理后重新运行 sshm cloud enable');
 const session=b64(crypto.getRandomValues(new Uint8Array(18))),expires=Date.now()+2*60_000;
 const request={type:'open',lifetime:'connection',device:device.id,epoch:agent.epoch,session,expires};if(target)request.mode='ssh';
 request.signature=await signVault(v,`sshm-shell-v3\n${v.user}\n${device.id}\n${agent.epoch}\n${session}\n${expires}\n${target?'ssh':''}\nconnection`);
 const sendCipher=await shellCipher(v,request,'c2a'),recvCipher=await shellCipher(v,request,'a2c');
 const url=new URL('/v1/relay',location.href);url.protocol=location.protocol==='https:'?'wss:':'ws:';url.searchParams.set('role','browser');url.searchParams.set('session',session);
 const ws=new WebSocket(url),term=new Terminal({cursorBlink:true,fontSize:13,fontFamily:'ui-monospace, SFMono-Regular, Consolas, monospace',scrollback:1500,allowProposedApi:false,theme:{background:'#15191f',foreground:'#e5e9ef',cursor:'#8be9b3'}}),fit=new FitAddon();term.loadAddon(fit);container.replaceChildren();term.open(container);
 let lastMessage=Date.now(),closed=false,ready=false,selected=false,disposed=false,sendQueue=Promise.resolve(),readQueue=Promise.resolve();
 const end=(reason='会话已结束')=>{if(closed)return;closed=true;clearInterval(ping);clearTimeout(handshake);observer.disconnect();if(ws.readyState===WebSocket.OPEN)ws.send(JSON.stringify({type:'close'}));ws.close();term.options.disableStdin=true;sendCipher.close();recvCipher.close();status.textContent=reason;};
 const stop=()=>{end();if(!disposed){disposed=true;term.dispose();container.replaceChildren();}};
 const send=payload=>{if(closed||(!ready&&payload.type!=='connect'))return;sendQueue=sendQueue.then(async()=>{if(closed)return;const f=await sendCipher.seal(payload);if(!closed)ws.send(JSON.stringify(f));}).catch(()=>end('加密发送失败，会话已关闭'));};
 const size=()=>({cols:Math.max(20,Math.min(300,term.cols)),rows:Math.max(5,Math.min(150,term.rows))});
 const resize=()=>{if(closed)return;fit.fit();send({type:'resize',...size()});};
 const observer=new ResizeObserver(resize);observer.observe(container);resize();
 term.onData(text=>{const b=new TextEncoder().encode(text);for(let i=0;i<b.length;i+=8192)send({type:'input',data:b64(b.subarray(i,i+8192))});});
 term.parser.registerOscHandler(52,()=>true);
 const ping=setInterval(()=>{if(Date.now()-lastMessage>90_000){end('连接心跳超时，请重新连接');return;}if(ws.readyState===WebSocket.OPEN)ws.send('{"type":"ping"}');},25000),handshake=setTimeout(()=>{if(!ready)end('连接超时，请确认代理版本及目标网络');},target?45000:15000);
 ws.onopen=()=>{status.textContent='正在验证设备并建立加密会话…';ws.send(JSON.stringify(request));};
 ws.onmessage=e=>{lastMessage=Date.now();readQueue=readQueue.then(async()=>{if(closed)return;const m=JSON.parse(e.data);if(m.type==='pong')return;if(m.type==='close'){end();return;}const p=await recvCipher.open(m);if(closed)return;
  if(p.type==='select'&&target&&!selected){selected=true;status.textContent='正在通过 '+device.label+' 连接 '+target.label+'…';send({type:'connect',target:target.id,credential:target.credential||'',...size()});}
  else if(p.type==='ready'&&(!target||selected)){ready=true;clearTimeout(handshake);status.textContent='已加密连接 · '+(target?target.label+' · 经 '+device.label:device.label)+' · 无固定时长上限';resize();term.focus();}
  else if(p.type==='error'){end(failures[p.data]||failures.connection_failed);}
  else if(p.type==='output'&&ready)term.write(bytes(p.data));else end('终端协议校验失败');
 }).catch(()=>end('加密会话校验失败，会话已关闭'));};
 ws.onerror=()=>end('连接失败，请确认设备代理仍在运行');ws.onclose=()=>{readQueue.finally(()=>end());};
 return stop;
}
