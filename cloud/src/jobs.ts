type Device = { id:string; digest:string; expires:number; kind?:string };
type State = { root:string; devices:Device[] };
type Result = { status:number; body:unknown };
type Input = Record<string,unknown>;
type Job = { id:string; device:string; action:string; version:string; expires:number; signature:string; root:string; digest:string; created:number; updated:number; status:string; claim?:string; code?:string; count?:number; receipt?:string };
const ID=/^[A-Za-z0-9_-]{8,100}$/;
const terminal=['succeeded','failed','restart_required'];
const codes=['synced','inspected','up_to_date','installed_restart_required','operation_failed','interrupted','update_check_failed','release_changed','update_install_failed','inspection_failed','local_config_unavailable','sync_failed'];
export const jobMessage=(user:string,j:Pick<Job,'id'|'device'|'action'|'version'|'expires'>)=>`sshm-job-v1\n${user}\n${j.id}\n${j.device}\n${j.action}\n${j.version}\n${j.expires}`;
export const receiptMessage=(user:string,j:Pick<Job,'id'|'device'>,status:string,code:string,count:number)=>`sshm-job-result-v1\n${user}\n${j.id}\n${j.device}\n${status}\n${code}\n${count}`;
export class Jobs {
 constructor(private ctx:DurableObjectState,private state:()=>State|undefined,private verify:(root:string,sig:string,message:string)=>Promise<boolean>){ctx.storage.sql.exec('CREATE TABLE IF NOT EXISTS jobs (id TEXT PRIMARY KEY, value TEXT NOT NULL)');}
 private all():Job[]{return this.ctx.storage.sql.exec<{value:string}>('SELECT value FROM jobs').toArray().map(r=>JSON.parse(r.value));}
 private save(j:Job){this.ctx.storage.sql.exec('INSERT OR REPLACE INTO jobs VALUES (?,?)',j.id,JSON.stringify(j));}
 private get(id:string){return this.all().find(j=>j.id===id);}
 private public(j:Job){const {root,digest,claim,...out}=j;return out;}
 private prune(){const s=this.state(),now=Date.now();for(const j of this.all()){
  if(j.created<now-7*86400_000){this.ctx.storage.sql.exec('DELETE FROM jobs WHERE id=?',j.id);continue;}
  if(!['queued','running'].includes(j.status))continue;
  const d=s?.devices.find(d=>d.id===j.device&&d.expires>now);
  if(!s||s.root!==j.root||d?.digest!==j.digest){j.status='cancelled';j.code='access_changed';}
  else if(j.status==='queued'&&j.expires<=now){j.status='expired';j.code='not_received';}
  else if(j.status==='running'&&j.updated<now-10*60_000){j.status='failed';j.code='receipt_missing';}
  else continue;
  j.updated=now;this.save(j);
 }}
 async handle(user:string,method:string,path:string,b:Input,actor:Device):Promise<Result|undefined>{
  if(!path.startsWith('/v1/jobs'))return;
  this.prune();const reply=(status:number,body:unknown)=>({status,body}),fail=(status:number,error:string)=>reply(status,{error});
  if(path==='/v1/jobs'&&method==='GET')return reply(200,{jobs:this.all().sort((a,b)=>b.created-a.created).map(j=>this.public(j))});
  if(path==='/v1/jobs/poll'&&method==='POST'){
   if(actor.kind==='browser')return fail(403,'agent_only');
   return reply(200,{jobs:this.all().filter(j=>j.device===actor.id&&j.digest===actor.digest&&['queued','running'].includes(j.status)).sort((a,b)=>a.created-b.created).map(j=>this.public(j))});
  }
  if(path==='/v1/jobs'&&method==='POST'){
   if(actor.kind!=='browser')return fail(403,'browser_only');
   const {id,device,action,version,expires,signature}=b;
   if(typeof id!=='string'||!ID.test(id)||typeof device!=='string'||!ID.test(device)||!['sync','inspect','update'].includes(String(action))||typeof version!=='string'||(action==='update'?!/^[a-zA-Z0-9.+_-]{1,80}$/.test(version):version!=='')||!Number.isSafeInteger(expires)||Number(expires)<=Date.now()||Number(expires)>Date.now()+86400_000||typeof signature!=='string')return fail(400,'invalid_job');
   const s=this.state()!,d=s.devices.find(d=>d.id===device&&d.expires>Date.now()&&d.kind!=='browser');if(!d)return fail(404,'device_not_found');
   const j:Job={id,device,action:String(action),version,expires:Number(expires),signature,root:s.root,digest:d.digest,created:Date.now(),updated:Date.now(),status:'queued'};
   if(!await this.verify(s.root,signature,jobMessage(user,j)))return fail(403,'invalid_signature');
   return this.ctx.storage.transactionSync(()=>{
    const current=this.state();if(!current||current.root!==s.root||!current.devices.some(a=>a.id===actor.id&&a.digest===actor.digest&&a.expires>Date.now())||!current.devices.some(a=>a.id===d.id&&a.digest===d.digest&&a.expires>Date.now()))return fail(409,'access_changed');
    const old=this.get(id);if(old)return old.signature===signature?reply(200,this.public(old)):fail(409,'job_exists');
    const jobs=this.all();if(jobs.filter(j=>j.device===device&&['queued','running'].includes(j.status)).length>=4)return fail(429,'device_queue_full');
    if(jobs.length>=200){const oldest=jobs.filter(j=>!['queued','running'].includes(j.status)).sort((a,b)=>a.created-b.created)[0];if(!oldest)return fail(429,'queue_full');this.ctx.storage.sql.exec('DELETE FROM jobs WHERE id=?',oldest.id);}
    this.save(j);return reply(200,this.public(j));
   });
  }
  const match=path.match(/^\/v1\/jobs\/([A-Za-z0-9_-]{8,100})\/(claim|result|cancel)$/);if(!match||method!=='POST')return fail(404,'not_found');
  const j=this.get(match[1]);if(!j)return fail(404,'not_found');
  if(match[2]==='cancel'){if(actor.kind!=='browser')return fail(403,'browser_only');if(j.status!=='queued')return fail(409,'already_started');j.status='cancelled';j.updated=Date.now();this.save(j);return reply(200,this.public(j));}
  if(actor.kind==='browser'||actor.id!==j.device||actor.digest!==j.digest)return fail(403,'wrong_device');
  if(typeof b.claim!=='string'||!ID.test(b.claim))return fail(400,'invalid_claim');
  if(match[2]==='claim'){
   if(j.status==='running'&&j.claim===b.claim)return reply(200,this.public(j));
   if(j.status!=='queued')return fail(409,'already_started');
   j.status='running';j.claim=b.claim;j.updated=Date.now();this.save(j);return reply(200,this.public(j));
  }
  if(j.claim!==b.claim)return fail(409,'claim_changed');
  const {status,code,count,receipt}=b;
  if(typeof status!=='string'||!terminal.includes(status)||typeof code!=='string'||!codes.includes(code)||!Number.isSafeInteger(count)||Number(count)<0||Number(count)>100000||typeof receipt!=='string')return fail(400,'invalid_result');
  if(!await this.verify(j.root,receipt,receiptMessage(user,j,status,code,Number(count))))return fail(403,'invalid_receipt');
  const s=this.state(),current=this.get(j.id);if(!s||s.root!==j.root||!s.devices.some(d=>d.id===actor.id&&d.digest===actor.digest&&d.expires>Date.now())||!current)return fail(409,'access_changed');
  if(current.receipt===receipt)return reply(200,this.public(current));
  if(current.status!=='running')return fail(409,'job_finished');
  Object.assign(current,{status,code,count,receipt,updated:Date.now()});this.save(current);return reply(200,this.public(current));
 }
}
