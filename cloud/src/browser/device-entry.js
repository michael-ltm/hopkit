// Device IDs, rather than names/IPs, identify client connections. Existing SSH
// records keep their own identity and credentials.
const prefix='sshm-device-',suffix='.invalid';
export function deviceConnectionId(server){
 if(server?.Auth!=='agent'||server?.User!=='sshm-client'||server?.Port!==22||!server?.Host?.startsWith(prefix)||!server.Host.endsWith(suffix))return '';
 const hex=server.Host.slice(prefix.length,-suffix.length);if(!/^(?:[0-9a-f]{2})+$/.test(hex))return '';
 const id=String.fromCharCode(...hex.match(/../g).map(x=>parseInt(x,16)));return /^[A-Za-z0-9_-]{8,100}$/.test(id)?id:'';
}
export async function addDeviceEntry(data,device){
 if(!/^[A-Za-z0-9_-]{8,100}$/.test(device.id)||device.kind==='browser')throw Error('请选择 SSHM 客户端设备。');
 const name=(device.label||device.id).trim();if(!name||name.length>100||/[\x00-\x1f\x7f]/.test(name))throw Error('设备名称无效，请先编辑名称。');
 const Host=prefix+[...new TextEncoder().encode(device.id)].map(x=>x.toString(16).padStart(2,'0')).join('')+suffix;
 const server={Host,Port:22,User:'sshm-client',Auth:'agent',Label:name,Description:device.note||'',Group:device.group||'',Tags:device.tags||[],KeyPath:''};
 const identity=JSON.stringify({Host,Port:22,User:server.User,Auth:'agent',Jump:'',Command:'',Proxy:'',Forwards:null});
 const id=[...new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(identity)))].map(x=>x.toString(16).padStart(2,'0')).join('');
 if(data.conflicts[id])throw Error('这台设备的连接存在冲突，请先处理。');
 const previous=data.entries[id],entry=previous||{id,aliases:[name],server,credentials:[],sources:{}};
 entry.aliases=[name];entry.server.Label=name;if(device.note||!previous)entry.server.Description=device.note||'';
 data.entries[id]=entry;delete data.deleted[id];data.activity||={};const a=data.activity[id]||{};
 data.activity[id]={...a,platform:device.platform==='darwin'?'macos':(['linux','windows','macos'].includes(device.platform)?device.platform:a.platform||''),last_seen:Math.max(a.last_seen||0,device.last_seen||0),sshm_status:'installed',sshm_version:device.version||'',sshm_checked_at:Math.max(a.sshm_checked_at||0,device.last_seen||0)};
 return entry;
}
