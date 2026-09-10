import { deviceVersion } from './device-version.js';
import { installControls, refreshControls, closeControls, confirmAction } from './controls.js';
import { hardwareCells, closeHardware } from './hardware.js';
import { openTerminal } from './terminal.js';
import { addDeviceEntry, deviceConnectionId } from './device-entry.js';
import { createUnlockFlow } from './unlock-flow.js';
import { unlockVault, refreshVault, latestRelease, encryptVault, b64, createLinkGrant, linkCode, signVault, verifyJobReceipt } from './vault.js';
const $=s=>document.querySelector(s),$$=s=>[...document.querySelectorAll(s)];
let session=null,devices=[],vault=null,page='devices',group='',lockTimer,backgroundTimer,flashTimer,unlockEpoch=0;
let agents=[],terminalStop=null,terminalEpoch=0,pendingLink=null,approvalEpoch=0;
let releaseVersion=null,releaseChecked=0;
let serverPage=0,devicePage=0,pageSize=25;const selectedServers=new Set();
const names={macos:'macOS',darwin:'macOS',linux:'Linux',windows:'Windows',browser:'浏览器',freebsd:'FreeBSD'},icons={darwin:'M',linux:'L',windows:'⊞',browser:'◉'};
const node=(tag,cls,text)=>{const e=document.createElement(tag);if(cls)e.className=cls;if(text!==undefined)e.textContent=text;return e;};
const tags=s=>[...new Set(s.split(/[,，]/).map(s=>s.trim()).filter(Boolean))];
const online=d=>!!d.last_seen && Date.now()-d.last_seen<90_000;
const time=n=>{if(!n)return '尚无记录';const seconds=Math.max(0,Math.floor((Date.now()-n)/1000));if(seconds<60)return '刚刚';if(seconds<3600)return Math.floor(seconds/60)+' 分钟前';if(seconds<86400)return Math.floor(seconds/3600)+' 小时前';return Math.floor(seconds/86400)+' 天前';};
function timestamp(n,label){const el=node('div','sub',n?label+' '+time(n):'尚无'+label+'记录');if(n)el.title=label+'：'+new Date(n).toLocaleString();return el;}
function flash(text){$('#flash').textContent=text;$('#flash').hidden=false;clearTimeout(flashTimer);flashTimer=setTimeout(()=>$('#flash').hidden=true,6500);}
async function api(path,method='GET',body){const headers={'Content-Type':'application/json'};if(session)headers['X-SSHM-Account']=session.username;const r=await fetch('/v1/'+path,{method,headers,body:method==='GET'?undefined:JSON.stringify(body||{}),credentials:'same-origin',cache:'no-store'});const d=await r.json();if(!r.ok){const e=Error(r.status===429?'操作过于频繁，请稍后重试。':r.status===401?'登录已过期或凭据不正确，请重新登录。':r.status===409?'云端已有更新。请重新解锁并核对最新内容，当前编辑尚未保存。':'操作未完成，请检查输入或稍后重试。');e.status=r.status;throw e;}return d;}
let unlocking=false;
const unlockFlow=createUnlockFlow({isUnlocked:()=>!!vault,show:label=>{
 $('#action-unlock-purpose').textContent='解锁后继续：'+label;
 $('#action-unlock-error').textContent='';$('#action-unlock-form').reset();
 $('#action-unlock-dialog').showModal();$('#action-unlock-form').elements.phrase.focus();
}});
function ensureVault(label,action){return unlockFlow.run(label,action).catch(e=>flash(e.message));}
function cancelUnlock(){
 if(unlockFlow.ticket()!==null||unlocking)unlockEpoch++;
 unlockFlow.cancel();$('#action-unlock-form').reset();$('#unlock-form').reset();
 $('#action-unlock-error').textContent='';
 if($('#action-unlock-dialog').open)$('#action-unlock-dialog').close();
}
$('#action-unlock-dialog').addEventListener('cancel',event=>{event.preventDefault();cancelUnlock();});
$('#action-unlock-dialog').addEventListener('close',()=>{if(unlockFlow.ticket()!==null)cancelUnlock();});
function showLogin(){ $('#login-error').textContent='';$('#login-dialog').showModal();setTimeout(()=>$('#login-form').elements.username.focus(),20); }
function routeFromPath(){return ['devices','servers','settings'].includes(location.pathname.slice(1))?location.pathname.slice(1):'landing';}
function navigate(name,{replace=false,writeHistory=true}={}){
 if(name!==page){cancelUnlock();approvalEpoch++;pendingLink=null;if($('#link-dialog').open)$('#link-dialog').close();}
 page=name;const home=name==='landing';
 for(const id of ['devices','servers','settings'])$('#'+id).hidden=!session||id!==name;
 $('#landing').hidden=!!session&&!home;$('#sidebar').hidden=!session||home;
 $('#top-login').hidden=!!session;$('#top-logout').hidden=!session;$('#account-chip').hidden=!session;
 if(session){$('#account-chip .user-label').textContent=session.username;$('#account-chip .avatar').textContent=session.username[0].toUpperCase();$('#settings-user').textContent=session.username;}
 $$('[data-nav]').forEach(b=>(b.classList.toggle('active',b.dataset.nav===name),b.setAttribute('aria-current',b.dataset.nav===name?'page':'false')));
 const path=home?'/':'/'+name;
 if(writeHistory&&(session||home)&&location.pathname!==path)history[replace?'replaceState':'pushState']({},'',path);
}
window.addEventListener('popstate',()=>{navigate(routeFromPath(),{writeHistory:false});if(!session&&page!=='landing'&&!$('#login-dialog').open)showLogin();});
function lock(){approvalEpoch++;cancelUnlock();closeControls();closeHardware();if($('#server-terminal-dialog').open)$('#server-terminal-dialog').close();serverTarget=null;clearTimeout(backgroundTimer);pendingLink=null;if($('#link-dialog').open)$('#link-dialog').close();document.querySelector('.row-menu')?.remove();stopTerminal();unlockEpoch++;selectedServers.clear();serverPage=0;$('#server-bulkbar').hidden=true;for(const id of ['delete-dialog','job-dialog'])if($('#'+id).open)$('#'+id).close();deleteIDs=[];if($('#bulk-dialog').open)$('#bulk-dialog').close();clearTimeout(lockTimer);$('#unlock-form').reset();$('#server-form').reset();$('#server-group').replaceChildren(new Option('所有分组',''));$('#server-search').value='';vault?.close();vault=null;$$('#pending-links button.primary').forEach(b=>{b.disabled=false;b.textContent='解锁并批准';});$('#vault-unlock').hidden=false;$('#vault-content').hidden=true;$('#vault-lock').hidden=true;$('#add-server').hidden=true;$('#server-rows').replaceChildren();if($('#server-dialog').open)$('#server-dialog').close();renderDevices();}
function active(){if(vault){clearTimeout(lockTimer);lockTimer=setTimeout(()=>{lock();flash('保险库因闲置已自动锁定。');},300_000);}}
for(const event of ['pointerdown','keydown'])document.addEventListener(event,active);document.addEventListener('visibilitychange',()=>{clearTimeout(backgroundTimer);if(document.hidden){stopTerminal();backgroundTimer=setTimeout(lock,60_000);}});window.addEventListener('pagehide',lock);
async function refresh(forceRelease=false){if(forceRelease||Date.now()-releaseChecked>300_000){releaseChecked=Date.now();latestRelease().then(v=>{releaseVersion=v;renderDevices();renderServers();}).catch(()=>{});}const [d,a]=await Promise.all([api('devices'),api('agents')]);devices=d.devices;agents=a.agents;renderDevices();renderSessions();await renderLinks();await refreshUnlockedVault();await refreshJobs();}
let refreshingVault=false,savingVault=false;
async function refreshUnlockedVault(){if(!vault||refreshingVault||savingVault||document.querySelector('dialog[open]'))return;const current=vault,revision=current.snapshot.revision;refreshingVault=true;try{const snapshot=await api('vault');if(snapshot.revision===revision)return;const opened=await refreshVault(current,snapshot);if(vault!==current||savingVault||current.snapshot.revision!==revision||document.querySelector('dialog[open]'))return;current.data=opened.data;current.snapshot=snapshot;current.envelope=opened.envelope;renderServers();renderDevices();}finally{refreshingVault=false;}}
function renderDevices(){
 const clients=devices.filter(d=>d.kind!=='browser'),query=$('#device-search').value.trim().toLowerCase(),status=$('#device-status').value,platform=$('#device-platform').value;
 const visible=clients.filter(d=>(!group||d.group===group)&&(status==='all'||online(d)===(status==='online'))&&(platform==='all'||d.platform===platform)&&[d.label,d.group,...(d.tags||[]),d.version,d.installed_version].join(' ').toLowerCase().includes(query)).sort((a,b)=>a.label.localeCompare(b.label));
 devicePage=Math.min(devicePage,Math.max(0,Math.ceil(visible.length/pageSize)-1));
 $('#device-summary').textContent=clients.length+' 台设备 · '+clients.filter(online).length+' 台在线'+(group?' · '+group:'')+' · 显示 '+visible.length+' 台';
 $('#device-empty').hidden=visible.length>0;$('#device-empty h2').textContent=clients.length?'没有匹配的设备':'连接你的第一台设备';$('#device-empty p').textContent=clients.length?'调整搜索、分组或状态筛选。':'安装 SSHM，在这里批准设备接入。';$('#empty-add').hidden=clients.length>0;
 const rows=$('#device-rows');rows.replaceChildren();
 for(const d of visible.slice(devicePage*pageSize,(devicePage+1)*pageSize)){
  const tr=node('tr'),identity=node('td'),wrap=node('div','device-name'),text=node('div');wrap.append(systemIcon(d.platform));const label=node('button','name link-name',d.label);label.title=d.label;label.onclick=()=>editDevice(d);text.append(label,node('div','sub',d.id===session.device?'当前客户端':session.username));wrap.append(text);identity.append(wrap);
  const grouping=node('td');grouping.append(node('div','sub',d.group||'未分组'),compactTags(d.tags));const system=node('td');system.append(deviceVersionCell(d,agents.find(a=>a.device_id===d.id)));
  const state=node('td'),badge=node('span','status'+(online(d)?' online':''));badge.append(node('i','dot'),node('span','',online(d)?'在线':'离线'));state.append(badge,timestamp(d.last_seen,'活跃'));
  const action=node('td','table-actions'),agent=agents.find(a=>a.device_id===d.id);action.append(rowMenu(d.label,[['加入服务器保险库',()=>addDeviceToVault(d)],['编辑设备',()=>editDevice(d)],['立即同步',()=>openJobs(d.id,'sync')],['检测服务器',()=>openJobs(d.id,'inspect')],['更新客户端',()=>openJobs(d.id,'update')],...(agent?[['打开终端',()=>startTerminal(d,agent)]]:[]),['撤销访问',()=>revoke(d),'danger']]));tr.append(identity,grouping,...hardwareCells(d.hardware||vault?.data.hardware?.[d.id],d.platform,d.label),system,deviceMembership(d),state,action);rows.append(tr);
 }
 pagination('device-pagination',visible.length,devicePage,p=>{devicePage=p;renderDevices();});
 const nav=$('#group-links');nav.replaceChildren();for(const label of [...new Set(clients.map(d=>d.group).filter(Boolean))].sort()){const b=node('button','nav-btn'+(group===label?' active':''),label);b.onclick=()=>{group=group===label?'':label;devicePage=0;navigate('devices');renderDevices();};nav.append(b);}
}
function renderSessions(){const list=$('#session-rows');list.replaceChildren();for(const d of devices.filter(d=>d.kind==='browser')){const row=node('div','mock-row');row.append(node('span','',d.label+(d.id===session.device?' · 当前浏览器':'')),node('span','muted',time(d.last_seen||d.created)));const b=node('button','danger','撤销');b.onclick=()=>revoke(d);row.append(b);list.append(row);}if(!list.children.length)list.append(node('p','muted','暂无浏览器会话'));}
function editDevice(d){const f=$('#device-form');f.elements.id.value=d.id;for(const k of ['label','group','note'])f.elements[k].value=d[k]||'';f.elements.tags.value=(d.tags||[]).join(', ');$('#device-detail-state').textContent=(names[d.platform]||'未报告系统')+' · '+deviceVersion(d,agents.find(a=>a.device_id===d.id),releaseVersion).label+' · '+deviceVersion(d,agents.find(a=>a.device_id===d.id),releaseVersion).detail+' · '+(online(d)?'在线':'离线');$('#device-error').textContent='';$('#device-dialog').showModal();}
async function revoke(d){if(!await confirmAction('撤销设备访问','撤销“'+d.label+'”的云端访问？已下载的数据无法远程收回。'))return;try{await api('devices/'+encodeURIComponent(d.id),'DELETE');if(d.id===session.device){await logout();return;}$('#device-dialog').close();await refresh();flash('已撤销设备。必要时在可信客户端换钥，并更换可能泄漏的服务器凭据。');}catch(e){flash(e.message);}}
$('#device-form').onsubmit=async e=>{e.preventDefault();const f=e.currentTarget,b=f.querySelector('button.primary');b.disabled=true;try{await api('devices/'+encodeURIComponent(f.elements.id.value),'POST',{label:f.elements.label.value.trim(),group:f.elements.group.value.trim(),tags:tags(f.elements.tags.value),note:f.elements.note.value.trim()});$('#device-dialog').close();await refresh();flash('设备信息已保存。');}catch(e){$('#device-error').textContent=e.message;}finally{b.disabled=false;}};
$('#revoke-device').onclick=()=>revoke(devices.find(d=>d.id===$('#device-form').elements.id.value));
async function logout(){try{await api('web/logout','POST');}catch(e){flash(e.message);return;}lock();session=null;devices=[];navigate('landing',{replace:true});$$('dialog[open]').forEach(d=>d.close());}
$('#login-form').onsubmit=async e=>{e.preventDefault();const f=e.currentTarget,b=f.querySelector('button');b.disabled=true;$('#login-error').textContent='正在登录…';try{const username=f.elements.username.value.trim().toLowerCase();const passwordLength=[...f.elements.password.value].length;if(passwordLength<6||passwordLength>256)throw Error("账号密码需要 6–256 个字符。");const r=await fetch('/v1/web/login',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json','X-SSHM-Account':username},body:JSON.stringify({password:f.elements.password.value,device_id:'browser_'+crypto.randomUUID(),label:'网页控制台'})});const d=await r.json();if(!r.ok)throw Error(r.status===429?'请求过于频繁，请稍后再试。':'用户名或密码不正确。');session={username,device:d.device_id};$('#login-dialog').close();navigate(page==='landing'?'devices':page);await api('heartbeat','POST',{platform:'browser',version:'web-preview'});await refresh();}catch(e){$('#login-error').textContent=e.message;}finally{b.disabled=false;f.elements.password.value='';}};
function install(){
 const target=$('#install-os').value,windows=target.startsWith('windows'),filename='sshm-'+target;
 $('#download-client').href='/downloads/'+filename;$('#download-client').download=filename;
 $('#installer-command').textContent=windows?'[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; irm https://sshm.yunmini.net/install.ps1 | iex':'curl -fsSL https://sshm.yunmini.net/install.sh | sh && export PATH="$HOME/.local/bin:$PATH"';
 $('#installer-help').textContent=windows?'在 PowerShell 中运行；自动识别系统架构，安装到当前用户目录。无需关闭执行策略。':'在 macOS / Linux 的终端运行；自动识别系统与架构，安装到 ~/.local/bin。无需 sudo。';
 const executable=windows?'& "$env:LOCALAPPDATA\\Programs\\sshm\\sshm.exe"':'"$HOME/.local/bin/sshm"';
 $('#install-login').textContent=executable+(vault?' cloud link --username '+session.username+' --root-public '+vault.snapshot.root_public+' --import-local':' cloud login --username '+(session?.username||'your-name')+' --import-local');
 $('#link-help').textContent=vault?'安装完成后运行。核对设备验证码，在设备页批准。':'已安装后可以跳过此步，仅在本地使用；登录可同步保险库。网页解锁后可生成设备批准命令。';
}
function addDevice(){install();$('#add-dialog').showModal();}
for(const id of ['add-device','empty-add','top-install','landing-install'])$('#'+id).onclick=addDevice;$('#login-download').onclick=()=>{$('#login-dialog').close();addDevice();};$('#install-os').value=/Windows/i.test(navigator.userAgent)?'windows-amd64.exe':/Mac/i.test(navigator.userAgent)?'darwin-arm64':'linux-amd64';$('#install-os').onchange=install;$('#copy-installer').onclick=()=>navigator.clipboard.writeText($('#installer-command').textContent).then(()=>flash('安装命令已复制。'),()=>flash('请手动复制命令。'));$('#copy-install').onclick=()=>navigator.clipboard.writeText($('#install-login').textContent).then(()=>flash('命令已复制。'),()=>flash('请手动复制命令。'));
for(const id of ['device-search','device-status','device-platform'])$('#'+id).oninput=()=>{devicePage=0;renderDevices();};$('#refresh').onclick=()=>refresh(true).catch(e=>flash(e.message));for(const b of $$('[data-nav]'))b.onclick=()=>{group='';navigate(b.dataset.nav);renderDevices();};for(const b of $$('[data-close]'))b.onclick=()=>{const dialog=b.closest('dialog');if(dialog.id==='action-unlock-dialog')cancelUnlock();else dialog.close();};$('#top-login').onclick=showLogin;$('#start').onclick=()=>{if(session)navigate('devices');else{page='devices';showLogin();}};$('#top-logout').onclick=logout;
async function submitUnlock(event){
 event.preventDefault();if(unlocking)return;
 const form=event.currentTarget,modal=form.id==='action-unlock-form',error=$(modal?'#action-unlock-error':'#unlock-error'),button=form.querySelector('button.primary');
 const epoch=unlockEpoch,account=session?.username,ticket=unlockFlow.ticket();
 if(!account){error.textContent='登录已过期，请重新登录。';return;}
 unlocking=true;button.disabled=true;error.textContent='正在本机派生解锁密钥…';
 const phrase=form.elements.phrase.value;form.elements.phrase.value='';
 try{
  const snapshot=await api('vault');
  if(epoch!==unlockEpoch||session?.username!==account)return;
  const opened=await unlockVault(account,snapshot,phrase,p=>{if(epoch===unlockEpoch)error.textContent='正在本机解锁 '+Math.round(p*100)+'%';});
  if(epoch!==unlockEpoch||session?.username!==account){opened.close();return;}
  vault=opened;error.textContent='';$('#vault-unlock').hidden=true;$('#vault-content').hidden=false;$('#vault-lock').hidden=false;$('#add-server').hidden=false;
  active();renderServers();renderDevices();install();
  // Consume the ticket before closing; the close event must not cancel success.
  const continuation=unlockFlow.resume(ticket);
  if(modal)$('#action-unlock-dialog').close();
  await continuation;await renderLinks();
 }catch(e){if(epoch===unlockEpoch){if(modal&&!$('#action-unlock-dialog').open)flash(e.message);else error.textContent=e.message;}}
 finally{form.elements.phrase.value='';button.disabled=false;unlocking=false;}
}
$('#unlock-form').onsubmit=submitUnlock;
$('#action-unlock-form').onsubmit=submitUnlock;
$('#vault-lock').onclick=lock;
function renderServers(){
 if(!vault)return;
 for(const id of selectedServers)if(!vault.data.entries[id])selectedServers.delete(id);
 const entries=Object.values(vault.data.entries),groupSelect=$('#server-group'),selected=groupSelect.value;
 groupSelect.replaceChildren(new Option('所有分组',''));
 for(const g of [...new Set(entries.map(e=>e.server.Group).filter(Boolean))].sort())groupSelect.add(new Option(g,g));
 groupSelect.value=[...groupSelect.options].some(o=>o.value===selected)?selected:'';
 const query=$('#server-search').value.trim().toLowerCase(),auth=$('#server-auth').value;
 const visible=entries.filter(e=>(!groupSelect.value||e.server.Group===groupSelect.value)&&(!auth||(auth==='device'?!!deviceConnectionId(e.server):!deviceConnectionId(e.server)&&e.server.Auth===auth))&&[...e.aliases,e.server.Host,e.server.User,e.server.Group,e.server.Description,...(e.server.Tags||[])].join(' ').toLowerCase().includes(query)).sort((a,b)=>a.aliases[0].localeCompare(b.aliases[0]));
 serverPage=Math.min(serverPage,Math.max(0,Math.ceil(visible.length/pageSize)-1));
 const shown=visible.slice(serverPage*pageSize,(serverPage+1)*pageSize),rows=$('#server-rows');rows.replaceChildren();
 for(const e of shown){
  const s=e.server,tr=node('tr'),check=node('td','check-cell'),box=document.createElement('input');box.type='checkbox';box.checked=selectedServers.has(e.id);box.setAttribute('aria-label','选择 '+e.aliases[0]);box.onchange=()=>{if(box.checked)selectedServers.add(e.id);else selectedServers.delete(e.id);renderServers();};check.append(box);tr.classList.toggle('selected',box.checked);
  const name=node('td'),primary=node('button','name link-name',e.aliases[0]+(e.aliases.length>1?' +'+(e.aliases.length-1):''));primary.title=e.aliases.join(', ');primary.disabled=!!vault.data.conflicts[e.id];primary.onclick=()=>editServer(e);const description=node('div','sub',s.Description||'');description.title=s.Description||'';const identity=node('div','device-name'),details=node('div');details.append(primary,description);identity.append(systemIcon(vault.data.activity?.[e.id]?.platform),details);name.append(identity);
  const deviceTarget=deviceConnectionId(s);const host=node('td'),address=node('div','mono',deviceTarget?'SSHM 客户端':s.Host+':'+s.Port);address.title=address.textContent;host.append(address,node('div','sub',deviceTarget?'密钥签名 · 端到端加密':s.User+' · '+({key:'私钥',password:'密码',agent:'Agent'}[s.Auth]||s.Auth)));
  const grouping=node('td'),groupLabel=node('div','sub',s.Group||'未分组');groupLabel.title=s.Group||'';grouping.append(groupLabel,compactTags(s.Tags));
  const activity=vault.data.activity?.[e.id]||{},authentication=node('td');const observation=activityStatus(activity);authentication.append(node('div','connection-state '+observation.kind,observation.label),timestamp(activity.last_connected,'成功连接'));authentication.title=(names[activity.platform]||'系统待识别')+' · '+observation.detail+(activity.last_seen?'；最近可达：'+new Date(activity.last_seen).toLocaleString():'');
  const action=node('td','table-actions');if(vault.data.conflicts[e.id])action.append(node('span','tag','冲突'));action.append(rowMenu(e.aliases[0],[...(vault.data.conflicts[e.id]?[]:[['编辑连接',()=>editServer(e)]]),['连接终端',()=>openServerTerminal(e)],['删除连接',()=>openDelete([e.id]),'danger'],[deviceTarget?'复制设备名称':'复制连接地址',()=>navigator.clipboard.writeText(deviceTarget?e.aliases[0]:s.User+'@'+s.Host+':'+s.Port).then(()=>flash('连接地址已复制。'),()=>flash('复制失败。'))]]));const installation=node('td');installation.append(clientBadge(activity));tr.append(check,name,host,grouping,...hardwareCells(activity.hardware,activity.platform,e.aliases[0]),authentication,installation,action);rows.append(tr);
 }
 $('#server-empty').hidden=shown.length>0;$('#server-summary').textContent=visible.length+' / '+entries.length+' 个连接 · 云版本 '+vault.snapshot.revision+(Object.keys(vault.data.conflicts).length?' · '+Object.keys(vault.data.conflicts).length+' 个冲突':'');
 $('#server-table').closest('.table-wrap').classList.toggle('comfortable',$('#server-density').value==='comfortable');
 const all=$('#server-select-page');all.checked=shown.length>0&&shown.every(e=>selectedServers.has(e.id));all.indeterminate=!all.checked&&shown.some(e=>selectedServers.has(e.id));all.disabled=!shown.length;all.onchange=()=>{for(const e of shown){if(all.checked)selectedServers.add(e.id);else selectedServers.delete(e.id);}renderServers();};
 $('#server-bulkbar').hidden=!selectedServers.size;$('#server-selected-count').textContent='已选 '+selectedServers.size+' 个连接';
 pagination('server-pagination',visible.length,serverPage,p=>{serverPage=p;renderServers();});
}
for(const id of ['server-search','server-group','server-auth'])$('#'+id).oninput=()=>{serverPage=0;renderServers();};$('#server-density').onchange=renderServers;
function editServer(e){const f=$('#server-form'),s=e?.server||{};f.reset();f.elements.id.value=e?.id||'';f.elements.alias.value=e?.aliases[0]||'';for(const [field,key] of [['host','Host'],['user','User'],['group','Group'],['description','Description']])f.elements[field].value=s[key]||'';f.elements.port.value=s.Port||22;f.elements.auth.value=s.Auth||'agent';f.elements.auth.disabled=!!e;for(const key of ['host','port','user'])f.elements[key].disabled=!!deviceConnectionId(s);for(const key of ['host','port','user','auth'])f.elements[key].closest('label').hidden=!!deviceConnectionId(s);f.elements.tags.value=(s.Tags||[]).join(', ');$('#server-dialog-title').textContent=e?'编辑服务器':'添加服务器';$('#delete-server').hidden=!e;$('#server-error').textContent='';$('#server-dialog').showModal();}
$('#add-server').onclick=()=>editServer();
async function saveVault(next){savingVault=true;try{await commitVault(next);}finally{savingVault=false;}}
async function commitVault(next){const current=vault;if(!current)throw Error('保险库已锁定，请重新解锁。');const temporary={...current,data:next};const payload=await encryptVault(temporary);if(vault!==current)throw Error('保险库已锁定，未提交。');const out=await api('vault','PUT',payload);if(out.blob!==payload.blob||out.signature!==payload.signature||out.revision!==payload.base_revision+1)throw Error('云端确认校验失败。');if(vault!==current)return;current.data=next;current.snapshot=out;current.envelope=JSON.parse(out.blob);renderServers();renderDevices();}
$('#server-form').onsubmit=async e=>{e.preventDefault();const f=e.currentTarget,b=f.querySelector('button.primary');b.disabled=true;try{if(!vault)throw Error('保险库已锁定。');const next=structuredClone(vault.data),existing=next.entries[f.elements.id.value];let entry=existing||{id:b64(crypto.getRandomValues(new Uint8Array(24))),aliases:[],server:{},credentials:[],sources:{}};const s=entry.server;Object.assign(s,{Host:f.elements.host.value.trim().toLowerCase(),Port:Number(f.elements.port.value),User:f.elements.user.value.trim(),Group:f.elements.group.value.trim(),Tags:tags(f.elements.tags.value),Description:f.elements.description.value,KeyPath:''});if(!existing){s.Auth=f.elements.auth.value;const identity=JSON.stringify({Host:s.Host,Port:s.Port,User:s.User,Auth:s.Auth,Jump:'',Command:'',Proxy:'',Forwards:null}).replace(/[<>&\u2028\u2029]/g,c=>'\\u'+c.charCodeAt(0).toString(16).padStart(4,'0'));entry.id=[...new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(identity)))].map(b=>b.toString(16).padStart(2,'0')).join('');}if(s.Tags.length>32||s.Tags.some(t=>t.length>64)||/[\x00-\x1f\x7f]/.test(s.Host+s.User+s.Group+s.Tags.join('')))throw Error('请检查主机、分组和标签的格式。');entry.aliases=[...new Set([f.elements.alias.value.trim(),...entry.aliases.slice(1)])];if(!existing){const match=Object.values(next.entries).find(e=>e.server.Host===s.Host&&e.server.Port===s.Port&&e.server.User===s.User&&e.server.Auth===s.Auth&&!e.server.ProxyJump&&!e.server.ProxyCommand&&!e.server.Proxy&&!(e.server.Forwards||[]).length);if(match)throw Error('已有相同连接，请编辑现有记录。');}next.entries[entry.id]=entry;await saveVault(next);$('#server-dialog').close();flash('服务器信息已加密保存。其他设备同步后即可读取。');}catch(e){$('#server-error').textContent=e.message;}finally{b.disabled=false;}};
$('#delete-server').onclick=()=>openDelete([$('#server-form').elements.id.value]);
setInterval(async()=>{if(!session||document.hidden)return;try{await api('heartbeat','POST',{platform:'browser',version:'web-preview'});await refresh();}catch(e){if(e.status===401){lock();session=null;navigate('devices');flash('登录已过期，请重新登录。');}}},30_000);
(async()=>{page=routeFromPath();try{const me=await api('web/me');session={username:me.username,device:me.device.id};navigate(page,{replace:true});await refresh();}catch{navigate(page,{replace:true});if(location.pathname!=='/')showLogin();}})();

function compactTags(list=[]){list=list||[];const wrap=node('div','tag-stack');wrap.title=list.join(', ');for(const t of list.slice(0,2))wrap.append(node('span','tag',t));if(list.length>2)wrap.append(node('span','tag','+'+(list.length-2)));return wrap;}
function pagination(id,count,current,change){const wrap=$('#'+id);wrap.replaceChildren();if(!count){wrap.hidden=true;return;}wrap.hidden=false;const total=Math.ceil(count/pageSize),label=node('span','',((current*pageSize)+1)+'–'+Math.min(count,(current+1)*pageSize)+' / '+count),size=document.createElement('select');size.setAttribute('aria-label','每页条数');for(const n of [25,50,100])size.add(new Option(n+' 条 / 页',String(n)));size.value=String(pageSize);size.onchange=()=>{pageSize=Number(size.value);serverPage=0;devicePage=0;renderDevices();renderServers();};const prev=node('button','','上一页'),next=node('button','','下一页');prev.disabled=!current;next.disabled=current>=total-1;prev.onclick=()=>change(current-1);next.onclick=()=>change(current+1);wrap.append(label,size,prev,node('span','',(current+1)+' / '+total),next);}
$('#server-clear-selection').onclick=()=>{selectedServers.clear();renderServers();};
$('#server-bulk-edit').onclick=()=>{$('#bulk-form').reset();$('#bulk-error').textContent='';$('#bulk-description').textContent='整理所选 '+selectedServers.size+' 个连接，保留现有凭据与连接方式。';$('#bulk-dialog').showModal();};
$('#bulk-form').onsubmit=async event=>{event.preventDefault();const form=event.currentTarget,button=form.querySelector('button.primary');button.disabled=true;try{if(!vault)throw Error('请重新解锁保险库。');const next=structuredClone(vault.data),newGroup=form.elements.group.value.trim(),newTags=tags(form.elements.tags.value);if(!newGroup&&!newTags.length)throw Error('请填写分组或追加标签。');if(/[\x00-\x1f\x7f]/.test(newGroup+newTags.join(''))||newTags.some(t=>t.length>64))throw Error('分组或标签格式不正确。');for(const id of selectedServers){const entry=next.entries[id];if(!entry)continue;if(next.conflicts[id])throw Error('所选连接包含冲突，请先在客户端解决。');if(newGroup)entry.server.Group=newGroup;entry.server.Tags=[...new Set([...(entry.server.Tags||[]),...newTags])];if(entry.server.Tags.length>32)throw Error('一个连接最多支持 32 个标签。');}await saveVault(next);selectedServers.clear();renderServers();$('#bulk-dialog').close();flash('所选连接已加密保存。');}catch(error){$('#bulk-error').textContent=error.message;}finally{button.disabled=false;}};

async function renderLinks(){
 const box=$('#pending-links');if(!session){box.hidden=true;return;}const {requests}=await api('links');box.replaceChildren();box.hidden=!requests.length;if(!requests.length)return;
 box.append(node('h3','','等待批准的设备'),node('p','tip',vault?'仅批准你刚刚发起、验证码完全一致的请求。':'点击批准即可在当前页面解锁，再核对设备验证码。'));
 for(const r of requests){const row=node('div','link-request'),text=node('div');text.append(node('strong','',r.label),node('div','sub',(names[r.platform]||r.platform)+(r.allow_shell?' · 请求启用网页终端':'')),node('code','',await linkCode(r.public_key)));const approve=node('button','primary',vault?'核对并批准':'解锁并批准');approve.dataset.request=r.id;approve.onclick=()=>ensureVault('批准设备“'+r.label+'”',()=>openLinkApproval(r));const reject=node('button','','拒绝');reject.onclick=()=>api('link/'+r.id,'DELETE').then(refresh).catch(e=>flash(e.message));row.append(text,approve,reject);box.append(row);}
}
function stopTerminal(){terminalEpoch++;terminalStop?.();terminalStop=null;if($('#terminal-dialog').open)$('#terminal-dialog').close();}
async function currentLink(request){
 const {requests}=await api('links');
 const latest=requests.find(r=>r.id===request.id);
 if(!latest||latest.public_key!==request.public_key||latest.device_id!==request.device_id||latest.expires!==request.expires||latest.expires<=Date.now()||latest.label!==request.label||latest.platform!==request.platform||latest.allow_shell!==request.allow_shell)throw Error('设备请求已过期、被撤销或发生变化，请让客户端重新发起审批。');
 return latest;
}
async function openLinkApproval(request){
 const current=vault,epoch=unlockEpoch,approval=++approvalEpoch;
 const latest=await currentLink(request);
 if(!current||vault!==current||epoch!==unlockEpoch||approval!==approvalEpoch)return;
 pendingLink=latest;$('#link-form').reset();$('#link-error').textContent='';
 $('#link-device-description').textContent=latest.label+' · '+(names[latest.platform]||latest.platform)+(latest.allow_shell?' · 本机已启用网页终端':'');
 $('#link-dialog').showModal();$('#link-form').elements.code.focus();
}
async function startTerminal(device,agent,target){if(!vault)return ensureVault('打开设备终端',()=>{const latest=devices.find(d=>d.id===device.id),activeAgent=agents.find(a=>a.device_id===device.id);if(!latest||!activeAgent)throw Error('设备已离线，请刷新后重试。');return startTerminal(latest,activeAgent,target);});stopTerminal();const epoch=terminalEpoch;$('#terminal-dialog h2').textContent=target?'服务器终端 · '+target.label:'设备终端 · '+device.label;$('#terminal-dialog').showModal();$('#terminal-status').textContent='准备加密终端…';try{const stop=await openTerminal(vault,device,agent,$('#terminal-container'),$('#terminal-status'),target);if(epoch!==terminalEpoch||!vault){stop();return;}terminalStop=stop;}catch(e){stopTerminal();flash('无法打开终端，请检查设备代理。');}}
$('#terminal-dialog').addEventListener('close',()=>{terminalEpoch++;terminalStop?.();terminalStop=null;});
window.addEventListener('pagehide',stopTerminal);

function rowMenu(label,items){const b=node('button','row-menu-button','···');b.setAttribute('aria-label',label+' 的操作');b.setAttribute('aria-haspopup','menu');b.onclick=()=>{document.querySelector('.row-menu')?.remove();const menu=node('div','row-menu');menu.popover='auto';menu.setAttribute('role','menu');for(const [text,action,cls] of items){const item=node('button',cls||'',text);item.setAttribute('role','menuitem');item.onclick=()=>{menu.hidePopover();menu.remove();action();};menu.append(item);}document.body.append(menu);const r=b.getBoundingClientRect();menu.style.left=Math.max(8,Math.min(innerWidth-190,r.right-180))+'px';menu.style.top=Math.max(8,Math.min(innerHeight-items.length*34-22,r.bottom+5))+'px';menu.showPopover();menu.querySelector('button').focus();menu.onkeydown=e=>{const all=[...menu.querySelectorAll('button')],at=all.indexOf(document.activeElement);if(e.key==='ArrowDown'||e.key==='ArrowUp'){e.preventDefault();all[(at+(e.key==='ArrowDown'?1:-1)+all.length)%all.length].focus();}if(e.key==='Escape')b.focus();};};return b;}
const navPaths={devices:'<rect x="3" y="4" width="18" height="13" rx="2"/><path d="M8 21h8m-4-4v4"/>',servers:'<rect x="4" y="3" width="16" height="7" rx="2"/><rect x="4" y="14" width="16" height="7" rx="2"/><path d="M7 6.5h.01M7 17.5h.01M11 6.5h6M11 17.5h6"/>',settings:'<path d="M12 3l7 3v6c0 5-7 9-7 9s-7-4-7-9V6l7-3Z"/><path d="m8 12 3 3 5-6"/>'};for(const b of $$('[data-nav]'))b.querySelector('.nav-icon').innerHTML='<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">'+navPaths[b.dataset.nav]+'</svg>';

$('#link-dialog').addEventListener('close',()=>{pendingLink=null;approvalEpoch++;});
$('#link-dialog').addEventListener('cancel',()=>{pendingLink=null;approvalEpoch++;});
$('#link-form').onsubmit=async event=>{event.preventDefault();const form=event.currentTarget,button=form.querySelector('button.primary'),r=pendingLink;button.disabled=true;try{const current=vault,epoch=unlockEpoch;if(!current||!r)throw Error('请先解锁并重新选择设备。');await currentLink(r);if(current!==vault||epoch!==unlockEpoch||pendingLink!==r)throw Error('审批已取消，请重新选择设备。');if(form.elements.code.value.trim().toUpperCase()!==await linkCode(r.public_key))throw Error('验证码不一致，未批准。');const grant=await createLinkGrant(current,r);if(epoch!==unlockEpoch||current!==vault||pendingLink!==r||!$('#link-dialog').open)throw Error('保险库已锁定或审批已取消。');await api('link/'+r.id,'POST',grant);$('#link-dialog').close();pendingLink=null;flash('已加密批准设备，等待客户端完成同步。');await refresh();}catch(e){$('#link-error').textContent=e.message;}finally{button.disabled=false;}};

function systemIcon(platform){
 const drawings={
 windows:'<path d="M3 5l8-1v7H3zm10-1.3L21 2v9h-8zM3 13h8v7l-8-1zm10 0h8v9l-8-1.7z" fill="currentColor" stroke="none"/>',
 macos:'<path d="M16.3 2.5c.2 2-1.5 3.8-3.5 3.8-.2-1.9 1.7-3.8 3.5-3.8ZM18.7 12.8c0-2 1.6-3 1.7-3.1-1-1.5-2.6-1.7-3.2-1.7-1.4-.2-2.8.8-3.5.8-.7 0-1.8-.8-3-.8-2.2 0-4.4 1.8-4.4 5 0 3.5 2.5 8 4.3 8 1 0 1.4-.7 2.8-.7 1.4 0 1.7.7 2.8.7 1.6 0 3.2-2.9 3.8-4.7-1.3-.6-2.3-1.8-2.3-3.5Z" fill="currentColor" stroke="none"/>',
 linux:'<path d="M8 10V7a4 4 0 0 1 8 0v3l3 7-3 3H8l-3-3z"/><ellipse cx="12" cy="15" rx="3.5" ry="5"/><path d="m10 8 2 2 2-2M8 19l-3 2h5m6-2 3 2h-5"/><path d="M10 6h.01M14 6h.01" stroke-width="2.5"/>',
 unknown:'<rect x="4" y="3" width="16" height="7" rx="2"/><rect x="4" y="14" width="16" height="7" rx="2"/><path d="M8 6.5h.01M8 17.5h.01M12 6.5h5m-5 11h5"/>'
 };
 const kind=platform==='darwin'?'macos':platform,el=node('span','os-icon os-'+(Object.hasOwn(drawings,kind)?kind:'unknown'));el.title=names[platform]||'系统待识别';el.setAttribute('role','img');el.setAttribute('aria-label',el.title);
 el.innerHTML='<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">'+(drawings[kind]||drawings.unknown)+'</svg>';return el;
}

function activityStatus(a){
 const errors={timeout:'连接超时',authentication:'认证失败',credential:'凭据不可用',refused:'连接被拒绝',dns:'地址解析失败',host_key:'主机指纹需核对',connection:'连接失败'};
 if(a.ssh_error)return {kind:'failed',label:errors[a.ssh_error]||'连接失败',detail:(a.last_connected?'最近 SSH 尝试失败':'暂无成功 SSH 连接记录')+'；检查于 '+new Date(a.ssh_checked_at).toLocaleString()};
 if(a.status==='offline')return {kind:'failed',label:'最近探测失败',detail:'最近探测未能到达目标，不代表服务器永久离线'};
 if(a.last_seen)return {kind:'seen',label:'最近可达',detail:'仅表示最近一次检查可达，并非实时在线状态'};
 return {kind:'unknown',label:'尚未检测',detail:'尚无连接或探测结果'};
}

function deviceVersionCell(d,agent){
 const v=deviceVersion(d,agent,releaseVersion),wrap=node('div','device-version');
 const badge=node('span','client-version '+v.kind,v.label);badge.title=v.help+(releaseVersion?' 最新发布：'+releaseVersion:'');
 wrap.append(badge,node('div','sub'+(v.restart?' version-restart':''),v.detail));
 if(v.checked)wrap.append(timestamp(v.checked,v.recent?'确认':'上次确认'));
 else if(d.last_seen)wrap.append(timestamp(d.last_seen,'进程上报'));
 return wrap;
}

function clientBadge(a){
 const version=a.sshm_version,status=a.sshm_status;let label,kind;
 if(status==='missing'){label='未安装';kind='missing';}
 else if(status==='installed'&&version){label=version;kind=!releaseVersion?'unknown':version===releaseVersion?'latest':'outdated';}
 else if(status==='installed'){label='已安装 · 版本未知';kind='unknown';}
 else{label=a.sshm_checked_at?'无法确认':'尚未检查';kind='unknown';}
 const badge=node('span','client-version '+kind,label);badge.title=status==='missing'?'当前登录用户的 PATH 与常用安装目录中未找到 SSHM':(releaseVersion?'最新发布版本：'+releaseVersion:'最新版本信息暂不可用')+(a.sshm_checked_at?'；检查于 '+new Date(a.sshm_checked_at).toLocaleString():'');return badge;
}
latestRelease().then(version=>{releaseChecked=Date.now();releaseVersion=version;renderDevices();renderServers();}).catch(()=>{});

let deleteIDs=[],dispatchDraft={};
function openDelete(ids){if(!vault)return;deleteIDs=[...new Set(ids)].filter(id=>vault.data.entries[id]);if(!deleteIDs.length)return;$('#delete-description').textContent='将删除 '+deleteIDs.length+' 个云端连接。';$('#delete-names').replaceChildren(...deleteIDs.slice(0,12).map(id=>node('li','',vault.data.entries[id].aliases[0])));if(deleteIDs.length>12)$('#delete-names').append(node('li','muted','以及另外 '+(deleteIDs.length-12)+' 个连接'));$('#delete-error').textContent='';$('#delete-dialog').showModal();}
$('#server-bulk-delete').onclick=()=>openDelete([...selectedServers]);
$('#confirm-delete').onclick=async()=>{const button=$('#confirm-delete');button.disabled=true;try{if(!vault)throw Error('请重新解锁保险库。');const next=structuredClone(vault.data),count=deleteIDs.length;for(const id of deleteIDs){delete next.entries[id];delete next.conflicts[id];if(next.activity)delete next.activity[id];next.deleted[id]=true;}await saveVault(next);$('#delete-dialog').close();$('#server-dialog').close();selectedServers.clear();renderServers();flash('已删除 '+count+' 个连接，删除标记已加密同步。');}catch(e){$('#delete-error').textContent=e.message;}finally{button.disabled=false;}};
const actionNames={sync:'同步保险库',inspect:'检测服务器',update:'更新客户端'};
const jobStates={queued:'等待设备接收',running:'执行中',succeeded:'已完成',failed:'失败',restart_required:'已安装 · 待重启',expired:'已过期',cancelled:'已取消'};
const jobCodes={cancelled_by_user:'已取消，设备不会执行此任务',update_check_failed:'无法取得或验证签名发布，请检查设备网络',release_changed:'最新发布已改变，请重新确认更新版本',update_install_failed:'安装未完成，请检查写入权限、磁盘空间和更新日志',inspection_failed:'检测中断或超时，请在设备检查配置',local_config_unavailable:'设备本地配置无法读取',sync_failed:'加密同步未完成，本地数据保留，请重试',synced:'已合并并同步保险库',inspected:'已检测并同步状态',up_to_date:'已是指定版本',installed_restart_required:'新版已安装；代理重启并重新解锁后生效',operation_failed:'操作未完成，请检查设备网络、权限和本机配置后重试',interrupted:'执行中断，未自动重试',access_changed:'设备访问凭据已改变',not_received:'24 小时内未接收',receipt_missing:'未收到完成回执，请核对设备后重试'};
function updateJobHelp(){const action=$('#job-form').elements.action.value;$('#job-action-help').textContent=action==='sync'?'合并所选设备的本地连接到加密保险库，并拉取云端修改与删除标记。保留原本地配置；不覆盖 SSH 文件。':action==='inspect'?'各设备使用已有 SSH 认证检测自己的服务器列表，最多 4 路并发。无法连接会记录失败状态，不弹出密码输入。':'下载并验证签名发布'+(releaseVersion?' '+releaseVersion:'')+'，更新客户端和 SSHM 管理的 Skill。正在运行的代理需重启并重新解锁，任务会显示“待重启”。';}
function openJobs(id,action='sync'){if(!vault)return ensureVault('下发设备任务',()=>openJobs(id,action));dispatchDraft={};$('#job-form').reset();$('#job-form').elements.action.value=action;$('#job-error').textContent='';const list=$('#job-targets');list.replaceChildren();for(const d of devices.filter(d=>d.kind!=='browser')){const label=node('label','job-target'),box=document.createElement('input');box.type='checkbox';box.name='device';box.value=d.id;box.checked=d.id===id;label.append(box,systemIcon(d.platform),node('span','',d.label),node('span','sub',!d.job_seen?'尚未启动新版代理':Date.now()-d.job_seen<90_000?'可接收任务':'代理离线 · 等待上线'));list.append(label);}updateJobHelp();$('#job-dialog').showModal();}
$('#dispatch-jobs').onclick=()=>openJobs();$('#server-dispatch').onclick=()=>openJobs();$('#job-form').elements.action.onchange=updateJobHelp;$('#job-select-all').onclick=()=>{const boxes=$$('#job-targets input'),checked=!boxes.every(b=>b.checked);boxes.forEach(b=>b.checked=checked);};
$('#job-form').onsubmit=async event=>{event.preventDefault();const form=event.currentTarget,button=form.querySelector('button.primary');button.disabled=true;let sent=0;try{const current=vault;if(!current)throw Error('请先解锁保险库。');const ids=$$('#job-targets input:checked').map(b=>b.value),action=form.elements.action.value;if(!ids.length)throw Error('请选择接收设备。');const version=action==='update'?await latestRelease():'';if(version){releaseVersion=version;releaseChecked=Date.now();renderDevices();renderServers();}for(const device of ids){if(vault!==current)throw Error('保险库已锁定。');let j=dispatchDraft[device];if(!j||j.action!==action||j.version!==version){j={id:b64(crypto.getRandomValues(new Uint8Array(18))),device,action,version,expires:Date.now()+86400_000};j.signature=await signVault(current,'sshm-job-v1\n'+session.username+'\n'+j.id+'\n'+j.device+'\n'+j.action+'\n'+j.version+'\n'+j.expires);dispatchDraft[device]=j;}if(vault!==current)throw Error('保险库已锁定。');await api('jobs','POST',j);delete dispatchDraft[device];sent++;const box=$$('#job-targets input').find(b=>b.value===device);if(box)box.checked=false;}$('#job-dialog').close();navigate('devices');$('#job-history').open=true;await refreshJobs();flash('已下发 '+sent+' 个任务，完成后可在下发记录查看结果。');}catch(e){$('#job-error').textContent=(sent?'已确认下发 '+sent+' 个。':'')+e.message+' 请先查看下发记录；在此重试会复用未确认的任务编号。';}finally{button.disabled=false;}};
async function refreshJobs(){const {jobs}=await api('jobs'),rows=$('#job-rows');rows.replaceChildren();$('#job-summary').textContent=jobs.length?'· '+jobs.filter(j=>['queued','running'].includes(j.status)).length+' 项待完成':'· 暂无';for(const j of jobs){const tr=node('tr'),identity=node('td');identity.append(node('div','',devices.find(d=>d.id===j.device)?.label||'已撤销设备'),node('div','sub',actionNames[j.action]||j.action));const status=node('td');status.append(node('span','job-status '+j.status,jobStates[j.status]||'未知'));const result=node('td'),description=node('div','sub',jobCodes[j.code]||(j.status==='queued'?'等待已解锁的设备代理接收':j.status==='cancelled'?'已取消，设备不会执行此任务':'等待设备回执'));if(j.receipt){let verified=false;try{if(vault)verified=await verifyJobReceipt(vault,j);}catch{}description.append(node('div','sub',verified?'已验证回执签名'+(j.code==='inspected'?' · 成功识别 '+j.count+' 台':j.code==='synced'?' · '+j.count+' 个连接':''):vault?'回执签名无效':'解锁后验证回执签名'));}result.append(description);const when=node('td','sub',time(j.created));when.title=new Date(j.created).toLocaleString();const action=node('td','table-actions');if(j.status==='queued'){const cancel=node('button','','取消');cancel.onclick=async()=>{try{await api('jobs/'+j.id+'/cancel','POST');await refreshJobs();}catch(e){flash(e.message);}};action.append(cancel);}else if(['failed','expired'].includes(j.status)){const retry=node('button','','重新下发');retry.onclick=()=>openJobs(j.device,j.action);action.append(retry);}tr.append(identity,status,result,when,action);rows.append(tr);}}

installControls();

let serverTarget=null;
function supportsTarget(version){const m=/^0\.8\.0-cloud-preview\.(\d+)$/.exec(version||'');return m?Number(m[1])>=19:/^([1-9]\d*\.|0\.(?:9|[1-9]\d)\.)/.test(version||'');}
function openServerTerminal(entry){
 const clientId=deviceConnectionId(entry.server);if(clientId){const device=devices.find(d=>d.id===clientId),agent=agents.find(a=>a.device_id===clientId);if(!device||!agent){flash('设备尚未开启连接或已离线。请在目标设备运行 sshm cloud enable。');return;}startTerminal(device,agent);return;}
 if(!vault)return;serverTarget=entry.id;const form=$('#server-terminal-form'),select=form.elements.device;select.replaceChildren();
 const eligible=devices.filter(d=>online(d)&&supportsTarget(d.version)&&agents.some(a=>a.device_id===d.id&&a.ssh_targets));
 const sources=new Set(Object.values(entry.sources||{}).map(s=>s.device));eligible.sort((a,b)=>Number(sources.has(b.id))-Number(sources.has(a.id))||a.label.localeCompare(b.label));
 for(const d of eligible)select.add(new Option(d.label+(sources.has(d.id)?' · 保存原连接':' · 在线'),d.id));
 if(!eligible.length)select.add(new Option('暂无可用设备',''));
 const creds=form.elements.credential;creds.replaceChildren(new Option('自动选择 / 使用设备已有密钥',''));
 for(const id of entry.credentials||[]){const c=vault.data.credentials[id];if(c)creds.add(new Option((c.kind==='password'?'已保存密码':'SSH 私钥')+' · '+(c.fingerprint||id).slice(-16),id));}
 $('#server-terminal-target').textContent=entry.aliases[0]+' · '+entry.server.User+'@'+entry.server.Host+':'+entry.server.Port;
 $('#server-terminal-error').textContent=eligible.length?'':'需要一台已开启网页终端、在线且版本为 .19 或更新的设备。';form.querySelector('button.primary').disabled=!eligible.length;refreshControls();$('#server-terminal-dialog').showModal();
}
$('#server-terminal-form').onsubmit=async event=>{event.preventDefault();try{const current=vault,entry=current?.data.entries[serverTarget],form=event.currentTarget,device=devices.find(d=>d.id===form.elements.device.value),agent=agents.find(a=>a.device_id===device?.id);if(!current||!entry||current.data.deleted[entry.id]||current.data.conflicts[entry.id])throw Error('连接已改变或保险库已锁定，请重新选择。');if(!device||!agent?.ssh_targets||!online(device)||!supportsTarget(device.version))throw Error('所选设备已离线或需要更新，请刷新设备列表。');$('#server-terminal-dialog').close();await startTerminal(device,agent,{id:entry.id,label:entry.aliases[0],credential:form.elements.credential.value});}catch(e){$('#server-terminal-error').textContent=e.message;}};

async function addDeviceToVault(device){
 if(!vault)return ensureVault('将“'+device.label+'”加入保险库',()=>{const latest=devices.find(d=>d.id===device.id);if(!latest)throw Error('设备已不存在，请刷新后重试。');return addDeviceToVault(latest);});
 if(savingVault){flash('正在保存，请稍后再试。');return;}
 try{const current=vault,next=structuredClone(current.data);await addDeviceEntry(next,device);if(vault!==current)throw Error('保险库已锁定，请重试。');await saveVault(next);navigate('servers');flash('已加入服务器保险库；按设备 ID 去重。其他客户端运行 sshm cloud sync 后即可看到。'+(agents.some(a=>a.device_id===device.id)?'':'目标设备需运行 sshm cloud enable 才能接受连接。'));}catch(e){flash(e.message);}
}

function deviceMembership(device){
 const cell=node('td','vault-membership');
 if(!vault){const b=node('button','link-name','解锁查看');b.onclick=()=>ensureVault('查看设备是否已加入保险库',()=>renderDevices());cell.append(b);return cell;}
 const entry=Object.values(vault.data.entries).find(e=>deviceConnectionId(e.server)===device.id&&!vault.data.deleted[e.id]);
 if(entry){const badge=node('span','status'+(vault.data.conflicts[entry.id]?'':' online'),vault.data.conflicts[entry.id]?'有冲突':'已加入');cell.append(badge);}
 else{cell.append(node('div','sub','未加入'));const b=node('button','link-name','＋ 加入保险库');b.onclick=()=>addDeviceToVault(device);cell.append(b);}
 return cell;
}
