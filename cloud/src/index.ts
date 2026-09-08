import {installSh,installPs1} from './installers-generated';
import { DurableObject } from 'cloudflare:workers';
import { randomBytes, scryptSync, timingSafeEqual, createHash } from 'node:crypto';
import { page } from './page';
import { Relay } from './relay';
import { Jobs } from './jobs';
import { resources, type Resources } from './resources';
import { accountScript } from './account-bundle';

type Result = { status: number; body: unknown };
type Input = Record<string, unknown>;
type Snapshot = { revision: number; base_revision: number; operation_id: string; blob: string; signature: string; root_public: string };
type Device = {installed_version?:string; installed_checked_at?:number; hardware?:Resources; id: string; label: string; digest: string; expires: number; created: number; kind?: string; platform?: string; version?: string; last_seen?: number; job_seen?: number; group?: string; tags?: string[]; note?: string };
type State = { salt: string; verifier: string; recovery: string; root: string; snapshot: Snapshot; devices: Device[] };
const MAX_BODY = 3 * 1024 * 1024;
const MAX_BLOB = 2 * 1024 * 1024;
const SESSION_MS = 30 * 86400_000;
const ID = /^[a-zA-Z0-9_-]{8,100}$/;
const ACCOUNT = /^[a-z0-9][a-z0-9._-]{2,63}$/;
function reply(status: number, body: unknown): Result { return { status, body }; }
function err(status: number, error: string): Result { return reply(status, { error }); }
function str(b: Input, k: string): string { return typeof b[k] === 'string' ? b[k] : ''; }
function hash(s: string): string { return createHash('sha256').update(s).digest('hex'); }
function equal(a: string, b: string): boolean { return timingSafeEqual(Buffer.from(hash(a)), Buffer.from(hash(b))); }
function validPass(p: string): boolean { const n = [...p].length; return n >= 6 && n <= 256; }
function passwordHash(p: string, salt: string): string {
  // OWASP scrypt alternative: N=2^15, r=8, p=3. Never reduce on free plans.
  return scryptSync(p, Buffer.from(salt, 'base64url'), 32, { N: 32768, r: 8, p: 3, maxmem: 64 * 1024 * 1024 }).toString('base64url');
}
function b64(s: string, length: number): boolean { return /^[A-Za-z0-9_-]+$/.test(s) && Buffer.from(s, 'base64url').length === length; }
async function verify(root: string, signature: string, message: string): Promise<boolean> {
  if (!b64(root, 32) || !b64(signature, 64)) return false;
  try {
    const key = await crypto.subtle.importKey('raw', Buffer.from(root, 'base64url'), {name:'Ed25519'}, false, ['verify']);
    return await crypto.subtle.verify('Ed25519', key, Buffer.from(signature, 'base64url'), new TextEncoder().encode(message));
  } catch { return false; }
}
function message(username: string, base: number, operation: string, blob: string): string {
  return `sshm-sync-v1\n${username}\n${base}\n${operation}\n${blob}`;
}
function validBlob(blob: string, username: string): boolean {
  if (blob.length > MAX_BLOB) return false;
  try {
    const e = JSON.parse(blob);
    return e.version === 1 && e.account === username && typeof e.vault_id === 'string' && ID.test(e.vault_id)
      && e.kdf === 'argon2id-64m-t3-p4' && b64(e.salt,16) && b64(e.wrap_nonce,12)
      && b64(e.wrapped_key,48) && b64(e.recovery_nonce,12) && b64(e.recovery_key,48)
      && b64(e.nonce,12) && typeof e.ciphertext === 'string' && /^[A-Za-z0-9_-]{22,}$/.test(e.ciphertext);
  } catch { return false; }
}
export class Limiter extends DurableObject<Env> {
  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.ctx.storage.sql.exec('CREATE TABLE IF NOT EXISTS bucket (id INTEGER PRIMARY KEY, window INTEGER NOT NULL, count INTEGER NOT NULL)');
  }
  consume(limit: number): boolean {
    const window = Math.floor(Date.now() / 60_000);
    const row = this.ctx.storage.sql.exec<{window:number;count:number}>('SELECT window,count FROM bucket WHERE id=1').toArray()[0];
    const count = row?.window === window ? row.count + 1 : 1;
    this.ctx.storage.sql.exec('INSERT OR REPLACE INTO bucket VALUES (1,?,?)',window,count);
    return count <= limit;
  }
}
export class Account extends DurableObject<Env> {
  private relay: Relay;
  private jobs: Jobs;
  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.ctx.storage.sql.exec('CREATE TABLE IF NOT EXISTS account (id INTEGER PRIMARY KEY, value TEXT NOT NULL)');
    this.ctx.storage.sql.exec('CREATE TABLE IF NOT EXISTS history (revision INTEGER PRIMARY KEY, value TEXT NOT NULL)');
    this.ctx.storage.sql.exec('CREATE TABLE IF NOT EXISTS links (id TEXT PRIMARY KEY, expires INTEGER NOT NULL, value TEXT NOT NULL)');
    this.relay=new Relay(ctx,()=>this.get());
    this.jobs=new Jobs(ctx,()=>this.get(),verify);
  }
  fetch(request:Request){return this.relay.upgrade(request);}
  webSocketMessage(ws:WebSocket,message:string|ArrayBuffer){return this.relay.message(ws,message);}
  webSocketClose(ws:WebSocket){this.relay.closed(ws);ws.close(1000,'closed');}
  webSocketError(ws:WebSocket){this.relay.closed(ws);ws.close(1011,'transport error');}
  private get(): State | undefined {
    const row = this.ctx.storage.sql.exec<{value:string}>('SELECT value FROM account WHERE id=1').toArray()[0];
    return row ? JSON.parse(row.value) : undefined;
  }
  private save(s: State): void { this.ctx.storage.sql.exec('INSERT OR REPLACE INTO account VALUES (1,?)',JSON.stringify(s)); this.relay?.prune(); }
  private device(s: State, token: string): Device | undefined { return s.devices.find(d => d.expires > Date.now() && equal(d.digest,hash(token))); }
  private login(s: State, b: Input): Result {
    const id = str(b,'device_id'); const label = str(b,'label');
    if (!ID.test(id) || !label || label.length > 80 || /[\x00-\x1f\x7f]/.test(label)) return err(400,'invalid_device');
    const previous=s.devices.find(d=>d.id===id);
    s.devices = s.devices.filter(d => d.expires > Date.now() && d.id !== id);
    if(s.devices.length >= 32) return err(409,'device_limit');
    const token = randomBytes(32).toString('base64url');
    s.devices.push({ ...previous,id,label:previous?.label??label,digest:hash(token),expires:Date.now()+SESSION_MS,created:previous?.created??Date.now(),kind:b._browser?'browser':'cli' });
    this.save(s);
    return reply(200,{token,device_id:id,expires:Date.now()+SESSION_MS,snapshot:s.snapshot});
  }
  private linkValue(id:string): any {
    const row=this.ctx.storage.sql.exec<{value:string}>('SELECT value FROM links WHERE id=?',id).toArray()[0];
    return row?JSON.parse(row.value):undefined;
  }
  private saveLink(v:any):void { this.ctx.storage.sql.exec('INSERT OR REPLACE INTO links VALUES (?,?,?)',v.id,v.expires,JSON.stringify(v)); }
  private async links(username:string,method:string,path:string,b:Input,token:string):Promise<Result|undefined>{
    if(!path.startsWith('/v1/link'))return;
    this.ctx.storage.sql.exec('DELETE FROM links WHERE expires < ?',Date.now());
    let s=this.get();if(!s)return err(401,'unauthorized');
    if(path==='/v1/link/start' && method==='POST'){
      const id=str(b,'id'),publicKey=str(b,'public_key'),secret=str(b,'secret'),deviceID=str(b,'device_id'),label=str(b,'label'),platform=str(b,'platform');
      if(!ID.test(id)||!ID.test(deviceID)||!b64(secret,32)||!b64(publicKey,65)||!label||label.length>80||/[\x00-\x1f\x7f]/.test(label)||!/^(darwin|linux|windows)$/.test(platform))return err(400,'invalid_link');
      if(this.linkValue(id))return err(409,'link_exists');
      const count=this.ctx.storage.sql.exec<{n:number}>('SELECT count(*) AS n FROM links').toArray()[0].n;if(count>=12)return err(429,'link_limit');
      const v={id,public_key:publicKey,secret_hash:hash(secret),device_id:deviceID,label,platform,allow_shell:b.allow_shell===true,expires:Date.now()+600_000,status:'pending'};
      this.saveLink(v);return reply(200,{id,expires:v.expires});
    }
    if(path==='/v1/link/poll' && method==='POST'){
      const v=this.linkValue(str(b,'id'));if(!v||!equal(v.secret_hash,hash(str(b,'secret'))))return err(401,'invalid_link');
      if(v.status==='approved'){
        if(v.root!==s.root || !this.device(s,v.delivery.token))return err(410,'link_revoked');
        return reply(200,{status:'approved',...v.delivery,snapshot:s.snapshot});
      }
      return reply(200,{status:'pending',expires:v.expires});
    }
    const actor=this.device(s,token);if(!actor)return err(401,'unauthorized');
    if(path==='/v1/links'&&method==='GET')return reply(200,{requests:this.ctx.storage.sql.exec<{value:string}>('SELECT value FROM links ORDER BY expires').toArray().map(r=>JSON.parse(r.value)).filter(v=>v.status==='pending').map(({secret_hash,delivery,root,...v})=>v)});
    const id=path.slice('/v1/link/'.length),v=this.linkValue(id);
    if(!v)return err(404,'not_found');
    if(method==='DELETE'){if(actor.id!==v.device_id && actor.kind!=='browser')return err(403,'not_allowed');this.ctx.storage.sql.exec('DELETE FROM links WHERE id=?',id);return reply(200,{ok:true});}
    if(method!=='POST'||actor.kind!=='browser')return err(403,'not_allowed');
    if(v.status!=='pending')return err(409,'link_already_approved');
    const grant=str(b,'grant'),signature=str(b,'signature');
    if(grant.length>4096)return err(400,'invalid_grant');
    try{const g=JSON.parse(grant);if(g.version!==1||!b64(g.public_key,65)||!b64(g.nonce,12)||!b64(g.ciphertext,48))return err(400,'invalid_grant');}catch{return err(400,'invalid_grant');}
    const root=s.root;
    if(!await verify(root,signature,`sshm-link-v1\n${username}\n${v.id}\n${v.public_key}\n${v.expires}\n${grant}`))return err(403,'invalid_signature');
    return this.ctx.storage.transactionSync(()=>{
      s=this.get();const current=this.linkValue(id);if(!s||s.root!==root||!this.device(s,token)||!current||current.status!=='pending'||current.expires<Date.now())return err(409,'link_changed');
      const login=this.login(s,{device_id:current.device_id,label:current.label});if(login.status!==200)return login;
      const delivery=login.body as any;delete delivery.snapshot;
      current.status='approved';current.root=root;current.delivery={...delivery,grant,signature,request_expires:current.expires};this.saveLink(current);
      return reply(200,{ok:true,device_id:current.device_id});
    });
  }
  async handle(username: string, method: string, path: string, b: Input, token: string): Promise<Result> {
    const link=await this.links(username,method,path,b,token);if(link)return link;
    let s = this.get();
    if(path === '/v1/register' && method === 'POST') {
      if(this.env.REGISTRATION !== 'open') return err(403,'registration_closed');
      if(s) return err(409,'account_unavailable');
      const password = str(b,'password'), salt = randomBytes(16).toString('base64url');
      const root = str(b,'root_public'), blob = str(b,'blob'), signature = str(b,'signature'), op = str(b,'operation_id');
      if(!validPass(password) || !b64(str(b,'recovery_auth'),32) || !ID.test(op) || !validBlob(blob,username)) return err(400,'invalid_registration');
      if(!await verify(root,signature,message(username,0,op,blob))) return err(400,'invalid_signature');
      const verifier = passwordHash(password,salt);
      return this.ctx.storage.transactionSync(() => {
        if(this.get()) return err(409,'account_unavailable');
        const state: State = {salt,verifier,recovery:hash(str(b,'recovery_auth')),root,devices:[],snapshot:{revision:1,base_revision:0,operation_id:op,blob,signature,root_public:root}};
        return this.login(state,b);
      });
    }
    if(path === '/v1/login' && method === 'POST') {
      // Same KDF for unknown accounts; rate limiting precedes all KDF work.
      const p = str(b,'password'); if(!validPass(p)) return err(401,'invalid_login');
      const salt = s?.salt ?? 'AAAAAAAAAAAAAAAAAAAAAA';
      const candidate = passwordHash(p,salt);
      if(!s || !equal(candidate,s.verifier)) return err(401,'invalid_login');
      return this.login(s,b);
    }
    if(path === '/v1/recover' && method === 'POST') {
      if(!s || !b64(str(b,'recovery_auth'),32) || !equal(hash(str(b,'recovery_auth')),s.recovery)) return err(401,'invalid_recovery');
      if(!validPass(str(b,'password'))) return err(400,'invalid_password');
      s.salt=randomBytes(16).toString('base64url');s.verifier=passwordHash(str(b,'password'),s.salt);s.devices=[];
      return this.login(s,b);
    }
    if(!s || !token || !this.device(s,token)) return err(401,'unauthorized');
    if(path==='/v1/jobs/poll'&&method==='POST'&&this.device(s,token)!.kind!=='browser'){this.device(s,token)!.job_seen=Date.now();this.save(s);}
    const job=await this.jobs.handle(username,method,path,b,this.device(s,token)!);if(job)return job;
    // Re-read after yielding: another heartbeat, installation report or revoke
    // may have committed while the job router was awaiting. Never save a stale
    // account snapshot over that observation or restore a revoked credential.
    s=this.get();if(!s||!this.device(s,token))return err(401,'unauthorized');
    if(path === '/v1/agents' && method === 'GET')return reply(200,{agents:this.relay.capabilities()});
    if(path === '/v1/vault' && method === 'GET') return reply(200,s.snapshot);
    if(path === '/v1/me' && method === 'GET') { const {digest,...device}=this.device(s,token)!; return reply(200,{username,device}); }
    // Installation observations are separate from process heartbeats. Legacy
    // agents must never overwrite a verified-on-device installation report.
    if(path === '/v1/client-version' && method === 'POST') {
      const device=this.device(s,token)!,version=str(b,'installed_version');
      if(device.kind==='browser')return err(403,'client_required');
      if(!/^[a-zA-Z0-9][a-zA-Z0-9._+ -]{0,79}$/.test(version))return err(400,'invalid_device');
      device.installed_version=version;device.installed_checked_at=Date.now();this.save(s);
      return reply(200,{ok:true});
    }
    if(path === '/v1/heartbeat' && method === 'POST') {
      const device=this.device(s,token)!;
      const platform=str(b,'platform'),version=str(b,'version');
      if(!/^(darwin|windows|linux|freebsd|browser|unknown)$/.test(platform) || version.length>80 || /[^a-zA-Z0-9._+ -]/.test(version))return err(400,'invalid_device');
      if(b.hardware!==undefined){if(device.kind==='browser')return err(403,'client_required');try{const h=resources(b.hardware);if(Number(h.checked_at)>=Math.max(Number(device.hardware?.checked_at||0),Number(device.hardware?.attempted_at||0)))device.hardware=h.status==='unavailable'&&device.hardware&&device.hardware.status!=='unavailable'?{...device.hardware,attempted_at:h.checked_at,refresh_failed:true}:h;}catch{return err(400,'invalid_resources');}}
      device.platform=platform;device.version=version;device.last_seen=Date.now();this.save(s);
      return reply(200,{ok:true,last_seen:device.last_seen});
    }
    if(path === '/v1/devices' && method === 'GET') return reply(200,{devices:s.devices.filter(d=>d.expires>Date.now()).map(({digest,...d})=>d)});
    if(path.startsWith('/v1/devices/') && method === 'POST') {
      const id=path.slice('/v1/devices/'.length),device=s.devices.find(d=>d.id===id);
      if(!device)return err(404,'not_found');
      const label=str(b,'label'),group=str(b,'group'),note=str(b,'note'),tags=b.tags;
      if(!label || label.length>80 || group.length>100 || note.length>500 || /[\x00-\x1f\x7f]/.test(label+group+note) || !Array.isArray(tags) || tags.length>32 || tags.some(t=>typeof t!=='string' || !t || t.length>50 || /[\x00-\x1f\x7f]/.test(t)))return err(400,'invalid_device');
      Object.assign(device,{label,group,note,tags:[...new Set(tags)]});this.save(s);
      return reply(200,{ok:true});
    }
    if(path.startsWith('/v1/devices/') && method === 'DELETE') {
      const id=path.slice('/v1/devices/'.length);s.devices=s.devices.filter(d=>d.id!==id);this.save(s);return reply(200,{ok:true});
    }
    if(path === '/v1/password' && method === 'POST') {
      if(!validPass(str(b,'old_password')) || !validPass(str(b,'password')) || !equal(passwordHash(str(b,'old_password'),s.salt),s.verifier)) return err(401,'invalid_login');
      const current=this.device(s,token)!;s.salt=randomBytes(16).toString('base64url');s.verifier=passwordHash(str(b,'password'),s.salt);s.devices=[current];this.save(s);return reply(200,{ok:true});
    }
    if(path === '/v1/account' && method === 'DELETE') {
      if(!validPass(str(b,'password')) || !equal(passwordHash(str(b,'password'),s.salt),s.verifier)) return err(401,'invalid_login');
      this.ctx.storage.transactionSync(()=>{this.ctx.storage.sql.exec('DELETE FROM account');this.ctx.storage.sql.exec('DELETE FROM history');this.ctx.storage.sql.exec('DELETE FROM links');this.ctx.storage.sql.exec('DELETE FROM jobs');});
      this.relay.prune();return reply(200,{ok:true});
    }
    if((path === '/v1/vault' || path === '/v1/rotate') && method === 'PUT') {
      const base=b.base_revision,op=str(b,'operation_id'),blob=str(b,'blob'),signature=str(b,'signature');
      if(!Number.isSafeInteger(base) || Number(base)<0 || !ID.test(op) || !validBlob(blob,username)) return err(400,'invalid_update');
      // Replay must be the exact same logical operation, not merely an ID collision.
      if(s.snapshot.operation_id===op) return s.snapshot.blob===blob && s.snapshot.signature===signature && s.snapshot.base_revision===base ? reply(200,s.snapshot) : err(409,'operation_mismatch');
      if(base!==s.snapshot.revision) return err(409,'revision_conflict');
      const oldRoot=s.root;
      const root=path==='/v1/rotate'?str(b,'root_public'):oldRoot;
      if(!await verify(root,signature,message(username,Number(base),op,blob))) return err(403,'invalid_signature');
      if(path==='/v1/rotate' && (!b64(str(b,'recovery_auth'),32) || !await verify(oldRoot,str(b,'authorization'),`sshm-rotate-v1\n${username}\n${base}\n${root}\n${blob}\n${str(b,'recovery_auth')}`))) return err(403,'invalid_rotation');
      // Re-read after asynchronous signature verification: revocation and concurrent writes must win.
      return this.ctx.storage.transactionSync(()=>{
        s=this.get();if(!s || !this.device(s,token))return err(401,'unauthorized');
        if(s.snapshot.revision!==base || s.root!==oldRoot)return err(409,'revision_conflict');
        this.ctx.storage.sql.exec('INSERT OR REPLACE INTO history VALUES (?,?)',s.snapshot.revision,JSON.stringify(s.snapshot));
        if(path==='/v1/rotate'){s.root=root;s.recovery=hash(str(b,'recovery_auth'));s.devices=[this.device(s,token)!];}
        s.snapshot={revision:Number(base)+1,base_revision:Number(base),operation_id:op,blob,signature,root_public:root};
        this.save(s);this.ctx.storage.sql.exec('DELETE FROM history WHERE revision < ?',Number(base)-19);
        return reply(200,s.snapshot);
      });
    }
    return err(404,'not_found');
  }
}
async function body(request: Request): Promise<Input> {
  const reader=request.body?.getReader();if(!reader)return {};
  const chunks:Uint8Array[]=[];let total=0;
  while(true){const {value,done}=await reader.read();if(done)break;total+=value.length;if(total>MAX_BODY){await reader.cancel();throw new Error('body_limit');}chunks.push(value);}
  const buffer=new Uint8Array(total);let offset=0;for(const c of chunks){buffer.set(c,offset);offset+=c.length;}
  const parsed=JSON.parse(new TextDecoder().decode(buffer));
  if(!parsed || Array.isArray(parsed) || typeof parsed!=='object')throw new Error('invalid_body');
  return parsed;
}
function response(result: Result): Response { return Response.json(result.body,{status:result.status,headers:{'Cache-Control':'no-store','X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer'}}); }
export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url=new URL(request.url);
    if(['/install.sh','/install.ps1'].includes(url.pathname) && ['GET','HEAD'].includes(request.method)) {
      return new Response(request.method==='HEAD'?null:(url.pathname.endsWith('.ps1')?installPs1:installSh),{headers:{'Content-Type':'text/plain; charset=utf-8','Cache-Control':'no-store','X-Content-Type-Options':'nosniff'}});
    }
    if(url.pathname.startsWith('/downloads/') && ['GET','HEAD'].includes(request.method)) {
      const asset=await env.ASSETS.fetch(request);
      const r=new Response(request.method==='HEAD'?null:asset.body,asset);r.headers.set('X-Content-Type-Options','nosniff');
      const filename=url.pathname.slice('/downloads/'.length);
      if((asset.status===200||asset.status===206) && /^sshm-(darwin|linux|windows)-(amd64|arm64)(\.exe)?$/.test(filename)) {
        r.headers.set('Content-Type','application/octet-stream');
        r.headers.set('Content-Disposition','attachment; filename="'+filename+'"');
      }
      return r;
    }
    if(url.pathname==='/health' && request.method==='GET')return response(reply(200,{service:'sshm-cloud',protocol:1,status:'ok'}));
    if(['/', '/devices','/servers','/settings','/login'].includes(url.pathname) && request.method==='GET')return new Response(page,{headers:{'Content-Type':'text/html; charset=utf-8','Content-Security-Policy':"default-src 'none'; style-src 'unsafe-inline'; script-src 'self'; connect-src 'self'; form-action 'none'; frame-ancestors 'none'; base-uri 'none'",'Cache-Control':'no-store'}});
    if(url.pathname==='/account.js' && request.method==='GET')return new Response(accountScript,{headers:{'Content-Type':'application/javascript; charset=utf-8','Cache-Control':'no-store','X-Content-Type-Options':'nosniff'}});
    if(!url.pathname.startsWith('/v1/'))return response(err(404,'not_found'));
    if(request.headers.has('Origin') && request.headers.get('Origin')!==url.origin)return response(err(403,'origin_denied'));
    const cookie=request.headers.get('Cookie')?.match(/(?:^|;\s*)__Host-sshm_session=([a-z0-9._-]+):([A-Za-z0-9_-]{43})(?:;|$)/);
    const web=url.pathname.startsWith('/v1/web/');
    const path=web?url.pathname.replace('/v1/web/','/v1/'):url.pathname;
    const username=(request.headers.get('X-SSHM-Account')??cookie?.[1]??'').trim().toLowerCase();
    if(!ACCOUNT.test(username))return response(err(400,'invalid_account'));
    const credentialRoute=['/v1/register','/v1/login','/v1/recover','/v1/password','/v1/account','/v1/link/start'].includes(path);
    const ip=request.headers.get('CF-Connecting-IP')??'local';
    if(path==='/v1/link/poll'&&!await env.LIMITER.getByName(`poll:${hash(ip+username)}`).consume(360))return response(err(429,'rate_limited'));
    if(credentialRoute){
      const ipOK=await env.LIMITER.getByName(`ip:${hash(ip)}`).consume(30);
      const userOK=await env.LIMITER.getByName(`user:${hash(username)}`).consume(10);
      if(!ipOK || !userOK)return response(err(429,'rate_limited'));
    }
    try {
      if(!['GET','POST','PUT','DELETE'].includes(request.method))return response(err(405,'method_not_allowed'));
      if(request.method!=='GET' && !request.headers.get('Content-Type')?.startsWith('application/json'))return response(err(415,'json_required'));
      const b=request.method==='GET'?{}:await body(request);
      delete b._browser;
      if(web && path==='/v1/login')b._browser=true;
      const token=request.headers.get('Authorization')?.match(/^Bearer ([A-Za-z0-9_-]{43})$/)?.[1]??cookie?.[2]??'';
      if(cookie && !request.headers.has('Authorization') && request.method!=='GET' && request.headers.get('Origin')!==url.origin)return response(err(403,'origin_denied'));
      const account=env.ACCOUNTS.getByName(username);
      if(path==='/v1/relay'&&request.headers.get('Upgrade')?.toLowerCase()==='websocket'){
        if(cookie&&!request.headers.has('Authorization')&&request.headers.get('Origin')!==url.origin)return response(err(403,'origin_denied'));
        if(!await env.LIMITER.getByName(`relay:${hash(ip+username)}`).consume(30))return response(err(429,'rate_limited'));
        const headers=new Headers(request.headers);headers.set('Authorization','Bearer '+token);headers.set('X-SSHM-Account',username);return account.fetch(new Request(request,{headers}));
      }
      if(web && path==='/v1/logout') {
        const me=await account.handle(username,'GET','/v1/me',{},token) as Result;
        if(me.status===200)await account.handle(username,'DELETE','/v1/devices/'+(me.body as {device:Device}).device.id,{},token);
        const r=response(reply(200,{ok:true}));r.headers.set('Set-Cookie','__Host-sshm_session=; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=0');return r;
      }
      const result=await account.handle(username,request.method,path,b,token) as Result;
      if(web && path==='/v1/login' && result.status===200) {
        const d=result.body as {token:string;device_id:string};
        const r=response(reply(200,{username,device_id:d.device_id}));r.headers.set('Set-Cookie',`__Host-sshm_session=${username}:${d.token}; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=86400`);return r;
      }
      return response(result);
    } catch {
      // Never log request bodies, tokens, passwords, or arbitrary exception text.
      return response(err(400,'request_failed'));
    }
  }
} satisfies ExportedHandler<Env>;
