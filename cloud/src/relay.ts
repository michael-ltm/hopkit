// The relay handles ciphertext and authenticated routing metadata only.
import { createHash } from 'node:crypto';
type Device = {id:string;digest:string;expires:number;kind?:string};
type State = {root:string;devices:Device[]};
type Attachment = {runtime_version?:string;continuous?:boolean;ssh_targets?:boolean;role:'agent'|'browser';user:string;device:string;digest:string;root:string;epoch:string;session?:string;expires:number;count:number;window:number;last_seen?:number};
const id=/^[A-Za-z0-9_-]{8,100}$/;
const hash=(s:string)=>createHash('sha256').update(s).digest('hex');
export class Relay {
 constructor(private ctx:DurableObjectState,private state:()=>State|undefined){}
 private data(ws:WebSocket):Attachment{return ws.deserializeAttachment();}
 private sockets(){return this.ctx.getWebSockets().filter(ws=>ws.readyState===WebSocket.OPEN);}
 private valid(a:Attachment,s=this.state()):boolean{return !!s&&(a.last_seen===undefined||Date.now()-a.last_seen<90_000)&&a.expires>Date.now()&&a.root===s.root&&s.devices.some(d=>d.id===a.device&&d.digest===a.digest&&d.expires>Date.now());}
 private agent(device:string){return this.sockets().find(ws=>{const a=this.data(ws);return a.role==='agent'&&a.device===device&&this.valid(a);});}
 capabilities(){return this.sockets().filter(ws=>{const a=this.data(ws);return a.role==='agent'&&this.valid(a);}).map(ws=>({device_id:this.data(ws).device,epoch:this.data(ws).epoch,runtime_version:this.data(ws).runtime_version,...(this.data(ws).continuous?{continuous:true}:{}),...(this.data(ws).ssh_targets?{ssh_targets:true}:{})}));}
 prune(){for(const ws of this.sockets())if(!this.valid(this.data(ws))){this.closed(ws);ws.close(1008,'authorization ended');}}
 async upgrade(request:Request):Promise<Response>{
  const s=this.state(),token=request.headers.get('Authorization')?.replace(/^Bearer /,''),d=s?.devices.find(d=>d.digest===hash(token||'')&&d.expires>Date.now());
  if(!s||!d)return new Response('Unauthorized',{status:401});
  this.prune();
  const url=new URL(request.url),requestedRole=url.searchParams.get('role'),role=requestedRole==='client'?'browser':requestedRole,user=request.headers.get('X-SSHM-Account')||'';
  if(role!=='agent'&&role!=='browser')return new Response('Invalid role',{status:400});
  let epoch='',session='',expires=d.expires;
  if(role==='agent'){
   if(d.kind==='browser')return new Response('Forbidden',{status:403});
   epoch=url.searchParams.get('epoch')||'';if(!id.test(epoch))return new Response('Invalid epoch',{status:400});
   if(this.agent(d.id))return new Response('Agent already connected',{status:409});
  }else{
   if(requestedRole==='client'?d.kind==='browser':d.kind!=='browser')return new Response('Forbidden',{status:403});
   session=url.searchParams.get('session')||'';if(!id.test(session))return new Response('Invalid session',{status:400});
   if(this.sockets().filter(ws=>this.data(ws).role==='browser').length>=8||this.sockets().some(ws=>this.data(ws).session===session))return new Response('Session limit',{status:409});
   expires=Math.min(expires,Date.now()+30_000);
  }
  const runtimeVersion=url.searchParams.get('version')||'';
  if(runtimeVersion&&!/^[a-zA-Z0-9][a-zA-Z0-9._+ -]{0,79}$/.test(runtimeVersion))return new Response('Invalid version',{status:400});
  const pair=new WebSocketPair(),[client,server]=Object.values(pair);
  this.ctx.acceptWebSocket(server);
  server.serializeAttachment({...(role==='agent'&&runtimeVersion?{runtime_version:runtimeVersion}:{}),role,user,device:d.id,digest:d.digest,root:s.root,epoch,session,expires,count:0,window:0,last_seen:Date.now(),...(role==='agent'&&url.searchParams.get('protocol')==='3'?{continuous:true}:{}),...(role==='agent'&&url.searchParams.get('target')==='ssh'?{ssh_targets:true}:{})} satisfies Attachment);
  return new Response(null,{status:101,webSocket:client});
 }
 async message(ws:WebSocket,message:string|ArrayBuffer){
  const a=this.data(ws);if(!this.valid(a)||typeof message!=='string'||message.length>65536){this.closed(ws);ws.close(1008,'invalid session');return;}
  const window=Math.floor(Date.now()/1000);a.count=a.window===window?a.count+1:1;a.window=window;if(a.count>200){this.closed(ws);ws.close(1008,'rate limit');return;}
  try{
   const m=JSON.parse(message);a.last_seen=Date.now();if(m.type==='ping'){ws.send('{"type":"pong"}');ws.serializeAttachment(a);return;}
   if(a.role==='browser'&&m.type==='open'&&!a.epoch){
    const target=this.agent(m.device),remote=target&&this.data(target);
    if(!target||!remote||remote.epoch!==m.epoch||m.session!==a.session||!Number.isSafeInteger(m.expires)||m.expires<Date.now()||m.expires>Date.now()+15*60_000||typeof m.signature!=='string')throw Error();
    if(m.lifetime!==undefined&&m.lifetime!==''&&m.lifetime!=='connection')throw Error();
    if(m.lifetime==='connection'&&!remote.continuous)throw Error();
    if(m.mode!==undefined&&m.mode!==''&&m.mode!=='ssh')throw Error();
    const key=await crypto.subtle.importKey('raw',Buffer.from(a.root,'base64url'),{name:'Ed25519'},false,['verify']);
    if(!await crypto.subtle.verify('Ed25519',key,Buffer.from(m.signature,'base64url'),new TextEncoder().encode(m.lifetime==='connection'?`sshm-shell-v3\n${a.user}\n${m.device}\n${m.epoch}\n${m.session}\n${m.expires}\n${m.mode||''}\nconnection`:m.mode==='ssh'?`sshm-shell-v2\n${a.user}\n${m.device}\n${m.epoch}\n${m.session}\n${m.expires}\nssh`:`sshm-shell-v1\n${a.user}\n${m.device}\n${m.epoch}\n${m.session}\n${m.expires}`)))throw Error();
    // Recheck after crypto yield so revocation or disconnect wins.
    if(!this.valid(a)||this.agent(m.device)!==target)throw Error();
    a.epoch=remote.epoch;a.expires=m.lifetime==='connection'?safelyAuthorizedUntil(a,this.state()):Math.min(safelyAuthorizedUntil(a,this.state()),m.expires);ws.serializeAttachment(a);
    // Target mapping is kept separately from the browser's authorization identity.
    const attached={...a,target:m.device};ws.serializeAttachment(attached);target.send(JSON.stringify(m));return;
   }
   const target=(ws.deserializeAttachment() as Attachment&{target?:string}).target;
   if(a.role==='browser'){
    const agent=target&&this.agent(target);if(!agent||!a.epoch)throw Error();
    if(m.type==='frame'&&m.session===a.session&&validFrame(m))agent.send(JSON.stringify(m));
    else if(m.type==='close'){agent.send(JSON.stringify({type:'close',session:a.session}));ws.close(1000,'closed');}
    else throw Error();
   }else{
    const browser=this.sockets().find(w=>{const b=w.deserializeAttachment() as Attachment&{target?:string};return b.role==='browser'&&b.target===a.device&&b.epoch===a.epoch&&b.session===m.session&&this.valid(b);});
    if(!browser)return;
    if(m.type==='frame'&&validFrame(m))browser.send(JSON.stringify(m));
    else if(m.type==='close'){browser.send(JSON.stringify({type:'close'}));browser.close(1000,'terminal ended');}
    else throw Error();
   }
   ws.serializeAttachment({...ws.deserializeAttachment(),count:a.count,window:a.window,last_seen:a.last_seen});
  }catch{this.closed(ws);ws.close(1008,'invalid message');}
 }
 closed(ws:WebSocket){
  const a=this.data(ws);if(!a)return;
  if(a.role==='browser'){
   const target=ws.deserializeAttachment().target,agent=target&&this.agent(target);
   if(agent)try{agent.send(JSON.stringify({type:'close',session:a.session}));}catch{}
  }else for(const browser of this.sockets()){
   const b=browser.deserializeAttachment();if(b.role==='browser'&&b.target===a.device&&b.epoch===a.epoch)try{browser.close(1001,'device disconnected');}catch{}
  }
 }
}
function validFrame(m:any){return Number.isSafeInteger(m.seq)&&m.seq>=0&&m.seq<2**32&&typeof m.ciphertext==='string'&&/^[A-Za-z0-9_-]{22,60000}$/.test(m.ciphertext);}

function safelyAuthorizedUntil(a:Attachment,s:State|undefined):number{return s?.devices.find(d=>d.id===a.device&&d.digest===a.digest)?.expires||0;}
