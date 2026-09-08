import { env, SELF, runInDurableObject } from 'cloudflare:test';
import { describe, it, expect } from 'vitest';
import { randomBytes, generateKeyPairSync, sign } from 'node:crypto';
const rnd=(n:number)=>randomBytes(n).toString('base64url');
function fixture(user:string){
 const {privateKey,publicKey}=generateKeyPairSync('ed25519');
 const root=publicKey.export({format:'jwk'}).x!;
 const blob=JSON.stringify({version:1,account:user,vault_id:rnd(18),kdf:'argon2id-64m-t3-p4',salt:rnd(16),wrap_nonce:rnd(12),wrapped_key:rnd(48),recovery_nonce:rnd(12),recovery_key:rnd(48),nonce:rnd(12),ciphertext:rnd(64)});
 const update=(base:number,value=blob)=>{const op=rnd(18);return {base_revision:base,operation_id:op,blob:value,root_public:root,signature:sign(null,Buffer.from(`sshm-sync-v1\n${user}\n${base}\n${op}\n${value}`),privateKey).toString('base64url')}};
 return {update,blob,root,privateKey};
}
describe('account and vault boundaries',()=>{
 it('requires six characters across registration, password changes and recovery',async()=>{
  const user='six-'+rnd(9).toLowerCase(),f=fixture(user),stub=env.ACCOUNTS.getByName(user),recovery=rnd(32);
  const input={...f.update(0),label:'Test',device_id:'six_test_device',recovery_auth:recovery};
  for(const password of ['abcde','一二三四五','🔑🔑🔑🔑🔑']) expect((await stub.handle(user,'POST','/v1/register',{...input,password},'')).status).toBe(400);
  const registered=await stub.handle(user,'POST','/v1/register',{...input,password:'abcdef'},'');expect(registered.status).toBe(200);
  const token=(registered.body as {token:string}).token;
  expect((await stub.handle(user,'POST','/v1/login',{password:'abcdef',label:'Test',device_id:'six_login_device'},'')).status).toBe(200);
  expect((await stub.handle(user,'POST','/v1/password',{old_password:'abcdef',password:'abcde'},token)).status).toBe(401);
  expect((await stub.handle(user,'POST','/v1/password',{old_password:'abcdef',password:'一二三四五六'},token)).status).toBe(200);
  expect((await stub.handle(user,'POST','/v1/login',{password:'一二三四五六',label:'Test',device_id:'six_login_device'},'')).status).toBe(200);
  expect((await stub.handle(user,'POST','/v1/recover',{...input,password:'abcde'},'')).status).toBe(400);
  expect((await stub.handle(user,'POST','/v1/recover',{...input,password:'🔑🔑🔑🔑🔑🔑'},'')).status).toBe(200);
  expect((await stub.handle(user,'POST','/v1/login',{password:'🔑🔑🔑🔑🔑🔑',label:'Test',device_id:'six_login_device'},'')).status).toBe(200);
 });
 it('registers, logs in, enforces CAS, signatures and revocation',async()=>{
  const user='test-'+rnd(9).toLowerCase();const f=fixture(user);const stub=env.ACCOUNTS.getByName(user);
  const first=f.update(0);const recovery=rnd(32);
  const r=await stub.handle(user,'POST','/v1/register',{...first,password:'synthetic-account-password',label:'Mac',device_id:'device_mac_1',recovery_auth:recovery},'');
  expect(r.status).toBe(200);const token=(r.body as {token:string}).token;expect(token).toHaveLength(43);
  const badLogin=await stub.handle(user,'POST','/v1/login',{password:'wrong-password-long',label:'PC',device_id:'device_pc_1'},'');expect(badLogin.status).toBe(401);
  const logged=await stub.handle(user,'POST','/v1/login',{password:'synthetic-account-password',label:'PC',device_id:'device_pc_1'},'');expect(logged.status).toBe(200);const token2=(logged.body as {token:string}).token;
  const next=f.update(1);const results=await Promise.all([stub.handle(user,'PUT','/v1/vault',next,token),stub.handle(user,'PUT','/v1/vault',f.update(1),token2)]);expect(results.map(r=>r.status).sort()).toEqual([200,409]);
  const winning=results[0].status===200?next:undefined;
  if(winning){expect((await stub.handle(user,'PUT','/v1/vault',winning,token)).status).toBe(200);expect((await stub.handle(user,'PUT','/v1/vault',{...winning,blob:f.blob+' '},token)).status).toBe(409);}
  expect((await stub.handle(user,'PUT','/v1/vault',{...f.update(2),signature:rnd(64)},token)).status).toBe(403);
  expect((await stub.handle(user,'GET','/v1/vault',{},'wrong-token')).status).toBe(401);
  expect((await stub.handle(user,'DELETE','/v1/devices/device_pc_1',{},token)).status).toBe(200);
  expect((await stub.handle(user,'GET','/v1/vault',{},token2)).status).toBe(401);
  const listing=await stub.handle(user,'GET','/v1/devices',{},token);expect(JSON.stringify(listing)).not.toContain(token);expect(JSON.stringify(listing)).not.toContain('digest');
  expect((await stub.handle(user,'POST','/v1/recover',{recovery_auth:rnd(32),password:'new-password-value',label:'recovery',device_id:'recover_device'},'')).status).toBe(401);
  const recovered=await stub.handle(user,'POST','/v1/recover',{recovery_auth:recovery,password:'new-password-value',label:'recovery',device_id:'recover_device'},'');expect(recovered.status).toBe(200);expect((await stub.handle(user,'GET','/v1/vault',{},token)).status).toBe(401);
 });
 it('isolates accounts, rejects cross origin and limits login attempts',async()=>{
  const one=env.ACCOUNTS.getByName('isolated-one');expect((await one.handle('isolated-one','GET','/v1/vault',{},rnd(32))).status).toBe(401);
  const csrf=await SELF.fetch('https://example.com/v1/login',{method:'POST',headers:{Origin:'https://other.example','X-SSHM-Account':'isolated-one','Content-Type':'application/json'},body:'{}'});expect(csrf.status).toBe(403);
  const limiter=env.LIMITER.getByName(rnd(18));expect(await limiter.consume(2)).toBe(true);expect(await limiter.consume(2)).toBe(true);expect(await limiter.consume(2)).toBe(false);
 });
});

describe('device console',()=>{
 it('keeps installation observations independent of legacy process heartbeats and supports downgrades',async()=>{
  const user='versions-'+rnd(8).toLowerCase(),f=fixture(user),stub=env.ACCOUNTS.getByName(user);
  const r=await stub.handle(user,'POST','/v1/register',{...f.update(0),password:'version-test-password',label:'Mac',device_id:'version_test_device',recovery_auth:rnd(32)},'');
  const token=(r.body as any).token;
  expect((await stub.handle(user,'POST','/v1/client-version',{installed_version:'new'},token)).status).toBe(200);
  let d=(await stub.handle(user,'GET','/v1/devices',{},token)).body as any;
  expect(d.devices[0].last_seen).toBeUndefined(); // reporting a file does not imply an online agent
  expect((await stub.handle(user,'POST','/v1/heartbeat',{platform:'darwin',version:'old'},token)).status).toBe(200);
  d=(await stub.handle(user,'GET','/v1/devices',{},token)).body as any;
  expect(d.devices[0].installed_version).toBe('new');expect(d.devices[0].version).toBe('old');expect(d.devices[0].installed_checked_at).toBeGreaterThan(0);
  await Promise.all([
   stub.handle(user,'POST','/v1/client-version',{installed_version:'concurrent-new'},token),
   stub.handle(user,'POST','/v1/heartbeat',{platform:'darwin',version:'concurrent-old'},token)
  ]);
  d=(await stub.handle(user,'GET','/v1/devices',{},token)).body as any;
  expect(d.devices[0].installed_version).toBe('concurrent-new');expect(d.devices[0].version).toBe('concurrent-old');
  expect((await stub.handle(user,'POST','/v1/client-version',{installed_version:'older'},token)).status).toBe(200);
  expect((await stub.handle(user,'POST','/v1/client-version',{installed_version:'bad\nvalue'},token)).status).toBe(400);
  expect((await stub.handle(user,'POST','/v1/client-version',{installed_version:'new'},'wrong')).status).toBe(401);
  d=(await stub.handle(user,'GET','/v1/devices',{},token)).body as any;expect(d.devices[0].installed_version).toBe('older');
  const login=await stub.handle(user,'POST','/v1/login',{password:'version-test-password',label:'Browser',device_id:'browser_version_test',_browser:true},'');
  expect((await stub.handle(user,'POST','/v1/client-version',{installed_version:'fake'},(login.body as any).token)).status).toBe(403);
 });
 it('uses HttpOnly browser sessions, real heartbeat metadata and account-scoped edits',async()=>{
  const user='console-'+rnd(8).toLowerCase(),f=fixture(user),password='synthetic-console-password';
  const stub=env.ACCOUNTS.getByName(user);
  const registered=await stub.handle(user,'POST','/v1/register',{...f.update(0),password,label:'Linux',device_id:'console_device',recovery_auth:rnd(32)},'');
  const token=(registered.body as {token:string}).token;
  const before=await stub.handle(user,'GET','/v1/devices',{},token);
  expect((before.body as any).devices[0].last_seen).toBeUndefined();
  expect((await stub.handle(user,'POST','/v1/heartbeat',{platform:'linux',version:'0.8.0-cloud-preview.1',hardware:{status:'ok',checked_at:Date.now(),cpu:'public-resource-test',memory_total:1024,disks:[{id:'disk1',kind:'disk',total:100,free:20,mounts:['/private-mount']}]}},token)).status).toBe(200);
  const login=await SELF.fetch('https://sshm.example/v1/web/login',{method:'POST',headers:{Origin:'https://sshm.example','Content-Type':'application/json','X-SSHM-Account':user},body:JSON.stringify({password,label:'Browser',device_id:'console_browser'})});
  expect(login.status).toBe(200);const body=await login.json() as any;expect(body.token).toBeUndefined();expect(body.snapshot).toBeUndefined();
  const cookie=login.headers.get('Set-Cookie')!;expect(cookie).toContain('HttpOnly');expect(cookie).toContain('Secure');expect(cookie).toContain('SameSite=Strict');
  const headers={Cookie:cookie.split(';')[0],'Content-Type':'application/json',Origin:'https://sshm.example'};
  const me=await SELF.fetch('https://sshm.example/v1/web/me',{headers});expect(me.status).toBe(200);
  const edited=await SELF.fetch('https://sshm.example/v1/devices/console_device',{method:'POST',headers,body:JSON.stringify({label:'Build server',group:'Development',tags:['linux','build'],note:'Synthetic test'})});expect(edited.status).toBe(200);
  const list=await SELF.fetch('https://sshm.example/v1/devices',{headers});const items=(await list.json() as any).devices;
  const device=items.find((d:any)=>d.id==='console_device');expect(device.group).toBe('Development');expect(device.tags).toEqual(['linux','build']);expect(device.last_seen).toBeGreaterThan(0);expect(device.platform).toBe('linux');expect(device.hardware.cpu).toBe('public-resource-test');expect(device.hardware.disks[0].free).toBe(20);expect(device.hardware.disks[0].mounts).toBeUndefined();
  const csrf=await SELF.fetch('https://sshm.example/v1/devices/console_device',{method:'DELETE',headers:{...headers,Origin:'https://evil.example'},body:'{}'});expect(csrf.status).toBe(403);
  const logout=await SELF.fetch('https://sshm.example/v1/web/logout',{method:'POST',headers,body:'{}'});expect(logout.status).toBe(200);expect(logout.headers.get('Set-Cookie')).toContain('Max-Age=0');
  expect((await SELF.fetch('https://sshm.example/v1/web/me',{headers})).status).toBe(401);
  expect((await stub.handle(user,'GET','/v1/vault',{},token)).status).toBe(200);
 });
});

it('approves link requests only with browser auth and pinned root signature; revocation invalidates delivery',async()=>{
 const user='link-'+rnd(8).toLowerCase(),f=fixture(user),stub=env.ACCOUNTS.getByName(user);
 const initial=await stub.handle(user,'POST','/v1/register',{...f.update(0),password:'test-password',label:'Owner',device_id:'owner_device',recovery_auth:rnd(32),_browser:true},'');
 const owner=(initial.body as any).token,secret=rnd(32),request={id:rnd(18),device_id:'new_link_device',public_key:rnd(65),secret,label:'New device',platform:'linux',allow_shell:true};
 const begun=await stub.handle(user,'POST','/v1/link/start',request,'');expect(begun.status).toBe(200);const expires=(begun.body as any).expires;
 expect((await stub.handle(user,'POST','/v1/link/poll',{id:request.id,secret:rnd(32)},'')).status).toBe(401);
 const list=await stub.handle(user,'GET','/v1/links',{},owner);expect(JSON.stringify(list)).not.toContain(secret);expect(JSON.stringify(list)).not.toContain('secret_hash');
 const grant=JSON.stringify({version:1,public_key:rnd(65),nonce:rnd(12),ciphertext:rnd(48)}),signature=sign(null,Buffer.from(`sshm-link-v1\n${user}\n${request.id}\n${request.public_key}\n${expires}\n${grant}`),f.privateKey).toString('base64url');
 expect((await stub.handle(user,'POST','/v1/link/'+request.id,{grant,signature:rnd(64)},owner)).status).toBe(403);
 expect((await stub.handle(user,'POST','/v1/link/'+request.id,{grant,signature},'')).status).toBe(401);
 expect((await stub.handle(user,'POST','/v1/link/'+request.id,{grant,signature},owner)).status).toBe(200);
 expect((await stub.handle(user,'POST','/v1/link/'+request.id,{grant,signature},owner)).status).toBe(409);
 const poll=await stub.handle(user,'POST','/v1/link/poll',{id:request.id,secret},'');expect(poll.status).toBe(200);expect((poll.body as any).grant).toBe(grant);
 expect((await stub.handle(user,'POST','/v1/link/poll',{id:request.id,secret},'')).body).toEqual(poll.body);
 await stub.handle(user,'DELETE','/v1/devices/new_link_device',{},owner);
 expect((await stub.handle(user,'POST','/v1/link/poll',{id:request.id,secret},'')).status).toBe(410);
});
it.each([{mode:'',native:false,continuous:false},{mode:'ssh',native:false,continuous:false},{mode:'',native:true,continuous:false},{mode:'',native:false,continuous:true},{mode:'ssh',native:false,continuous:true},{mode:'',native:true,continuous:true}])('routes encrypted terminal frames after signed authorization (%j) and closes on revocation',async({mode,native,continuous})=>{
 const user='relay-'+rnd(8).toLowerCase(),f=fixture(user),stub=env.ACCOUNTS.getByName(user);
 const reg=await stub.handle(user,'POST','/v1/register',{...f.update(0),password:'test-password',label:'Agent',device_id:'relay_device',recovery_auth:rnd(32)},'');const token=(reg.body as any).token;
 const login=await SELF.fetch('https://sshm.example/v1/web/login',{method:'POST',headers:{Origin:'https://sshm.example','Content-Type':'application/json','X-SSHM-Account':user},body:JSON.stringify({password:'test-password',label:'Browser',device_id:'relay_browser'})});const cookie=login.headers.get('Set-Cookie')!.split(';')[0];
 const epoch=rnd(18),session=rnd(18);
 const agentRes=await SELF.fetch('https://sshm.example/v1/relay?role=agent&epoch='+epoch+(continuous?'&protocol=3&version=0.8.0-test':''),{headers:{Upgrade:'websocket',Authorization:'Bearer '+token,'X-SSHM-Account':user}});expect(agentRes.status).toBe(101);const agent=agentRes.webSocket!;agent.accept();
 const caps=await stub.handle(user,'GET','/v1/agents',{},token);expect((caps.body as any).agents).toEqual([{device_id:'relay_device',epoch,...(continuous?{continuous:true,runtime_version:'0.8.0-test'}:{})}]);
 const denied=await SELF.fetch('https://sshm.example/v1/relay?role=browser&session='+session,{headers:{Upgrade:'websocket',Cookie:cookie,Origin:'https://evil.example'}});expect(denied.status).toBe(403);
 const nativeLogin=await stub.handle(user,'POST','/v1/login',{password:'test-password',label:'Native client',device_id:'native_client'},'');const clientToken=(nativeLogin.body as any).token;
 const wrongKind=await SELF.fetch('https://sshm.example/v1/relay?role=client&session='+rnd(18),{headers:{Upgrade:'websocket',Cookie:cookie,Origin:'https://sshm.example'}});expect(wrongKind.status).toBe(403);
 const webRes=await SELF.fetch('https://sshm.example/v1/relay?role='+(native?'client':'browser')+'&session='+session,{headers:native?{Upgrade:'websocket',Authorization:'Bearer '+clientToken,'X-SSHM-Account':user}:{Upgrade:'websocket',Cookie:cookie,Origin:'https://sshm.example'}});expect(webRes.status).toBe(101);const web=webRes.webSocket!;web.accept();
 const next=(ws:WebSocket)=>new Promise<any>(resolve=>ws.addEventListener('message',e=>resolve(JSON.parse(String(e.data))),{once:true}));
 const request={...(continuous?{lifetime:'connection'}:{}),mode,type:'open',device:'relay_device',epoch,session,expires:Date.now()+60000,signature:''};request.signature=sign(null,Buffer.from(continuous?`sshm-shell-v3\n${user}\n${request.device}\n${epoch}\n${session}\n${request.expires}\n${mode}\nconnection`:mode==='ssh'?`sshm-shell-v2\n${user}\n${request.device}\n${epoch}\n${session}\n${request.expires}\nssh`:`sshm-shell-v1\n${user}\n${request.device}\n${epoch}\n${session}\n${request.expires}`),f.privateKey).toString('base64url');
 let received=next(agent);web.send(JSON.stringify(request));expect(await received).toEqual(request);
 const frame={type:'frame',session,seq:0,ciphertext:rnd(40)};received=next(web);agent.send(JSON.stringify(frame));expect(await received).toEqual(frame);
 received=next(agent);web.send(JSON.stringify(frame));expect(await received).toEqual(frame);
 if(continuous){
  // Exercise the real Durable Object routing clock past BOTH old deadlines.
  received=next(agent);
  await runInDurableObject(stub,async(instance,state)=>{
   const now=Date.now()+61*60_000,realNow=Date.now;
   const sockets=state.getWebSockets();
   for(const ws of sockets){const a=ws.deserializeAttachment();expect(a.expires).toBeGreaterThan(now);ws.serializeAttachment({...a,last_seen:now});}
   const client=sockets.find(ws=>ws.deserializeAttachment().session===session)!;
   Date.now=()=>now;
   try {await instance.webSocketMessage(client,JSON.stringify(frame));} finally {Date.now=realNow;}
  });
  expect(await received).toEqual(frame);
 }

 const closed=new Promise<void>(resolve=>web.addEventListener('close',()=>resolve(),{once:true}));await stub.handle(user,'DELETE','/v1/devices/relay_device',{},token);await closed;agent.close();web.close();
 expect((await stub.handle(user,'GET','/v1/agents',{},token)).status).toBe(401);
});

it('queues signed device jobs, isolates claims, verifies receipts and cancels revoked work',async()=>{
 const {jobMessage,receiptMessage}=await import('../src/jobs');
 const user='jobs-'+rnd(8).toLowerCase(),f=fixture(user),stub=env.ACCOUNTS.getByName(user),password='test-password';
 const registered=await stub.handle(user,'POST','/v1/register',{...f.update(0),password,label:'Browser',device_id:'jobs_browser',recovery_auth:rnd(32),_browser:true},'');
 const owner=(registered.body as any).token;
 const login=async(id:string)=>(await stub.handle(user,'POST','/v1/login',{password,label:id,device_id:id},'')).body as any;
 const a=await login('jobs_device_a'),b=await login('jobs_device_b');
 const make=(device=a.device_id,action='sync')=>{const j={id:rnd(18),device,action,version:action==='update'?'0.8.0-cloud-preview.15':'',expires:Date.now()+3600_000,signature:''};j.signature=sign(null,Buffer.from(jobMessage(user,j)),f.privateKey).toString('base64url');return j;};
 const j=make();
 expect((await stub.handle(user,'POST','/v1/jobs',{...j,signature:rnd(64)},owner)).status).toBe(403);
 expect((await stub.handle(user,'POST','/v1/jobs',j,a.token)).status).toBe(403);
 expect((await stub.handle(user,'POST','/v1/jobs',make(a.device_id,'shell'),owner)).status).toBe(400);
 expect((await stub.handle(user,'POST','/v1/jobs',j,owner)).status).toBe(200);
 expect((await stub.handle(user,'POST','/v1/jobs',j,owner)).status).toBe(200);
 expect((await stub.handle(user,'POST','/v1/jobs/poll',{},b.token)).body).toEqual({jobs:[]});
 const poll=await stub.handle(user,'POST','/v1/jobs/poll',{},a.token);expect((poll.body as any).jobs[0].status).toBe('queued');expect(JSON.stringify(poll)).not.toContain('digest');
 const claim=rnd(18),route='/v1/jobs/'+j.id;
 expect((await stub.handle(user,'POST',route+'/claim',{claim},b.token)).status).toBe(403);
 expect((await stub.handle(user,'POST',route+'/claim',{claim},a.token)).status).toBe(200);
 expect((await stub.handle(user,'POST',route+'/claim',{claim},a.token)).status).toBe(200);
 expect((await stub.handle(user,'POST',route+'/claim',{claim:rnd(18)},a.token)).status).toBe(409);
 expect((await stub.handle(user,'POST',route+'/cancel',{},owner)).status).toBe(409);
 const result={claim,status:'succeeded',code:'synced',count:3,receipt:''};result.receipt=sign(null,Buffer.from(receiptMessage(user,j,result.status,result.code,result.count)),f.privateKey).toString('base64url');
 expect((await stub.handle(user,'POST',route+'/result',{...result,count:4},a.token)).status).toBe(403);
 expect((await stub.handle(user,'POST',route+'/result',result,b.token)).status).toBe(403);
 expect((await stub.handle(user,'POST',route+'/result',result,a.token)).status).toBe(200);
 expect((await stub.handle(user,'POST',route+'/result',result,a.token)).status).toBe(200);
 expect((await stub.handle(user,'POST',route+'/claim',{claim},a.token)).status).toBe(409);
 const cancelled=make();await stub.handle(user,'POST','/v1/jobs',cancelled,owner);
 expect((await stub.handle(user,'POST','/v1/jobs/'+cancelled.id+'/cancel',{},owner)).status).toBe(200);
 expect((await stub.handle(user,'POST','/v1/jobs/'+cancelled.id+'/claim',{claim},a.token)).status).toBe(409);
 const revoked=make();await stub.handle(user,'POST','/v1/jobs',revoked,owner);await stub.handle(user,'DELETE','/v1/devices/'+a.device_id,{},owner);
 const list=(await stub.handle(user,'GET','/v1/jobs',{},owner)).body as any;expect(list.jobs.find((j:any)=>j.id===revoked.id).status).toBe('cancelled');
});

it('rejects a live duplicate relay but lets the same device replace a stale socket',async()=>{
 const user='stale-'+rnd(8).toLowerCase(),f=fixture(user),stub=env.ACCOUNTS.getByName(user);
 const r=await stub.handle(user,'POST','/v1/register',{...f.update(0),password:'test-password',label:'Device',device_id:'stale_device',recovery_auth:rnd(32)},'');
 const token=(r.body as any).token;
 const dial=()=>SELF.fetch('https://sshm.example/v1/relay?role=agent&epoch='+rnd(18),{headers:{Upgrade:'websocket',Authorization:'Bearer '+token,'X-SSHM-Account':user}});
 const first=await dial();expect(first.status).toBe(101);const old=first.webSocket!;old.accept();
 expect((await dial()).status).toBe(409);
 await runInDurableObject(stub,(_instance,state)=>{for(const ws of state.getWebSockets()){const a=ws.deserializeAttachment();if(a.role==='agent')ws.serializeAttachment({...a,last_seen:Date.now()-91_000});}});
 expect(((await stub.handle(user,'GET','/v1/agents',{},token)).body as any).agents).toEqual([]);
 const replacement=await dial();expect(replacement.status).toBe(101);replacement.webSocket!.accept();
 expect(((await stub.handle(user,'GET','/v1/agents',{},token)).body as any).agents).toHaveLength(1);
 old.close();replacement.webSocket!.close();
});
