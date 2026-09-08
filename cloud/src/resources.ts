// Resource metadata is authenticated account data. Do not retain arbitrary
// heartbeat fields, credentials, volume UUIDs or filesystem mount paths.
export type Resources = Record<string,unknown>;
export function resources(value:unknown):Resources{
 if(!value||typeof value!=='object'||Array.isArray(value)||JSON.stringify(value).length>65536)throw Error('invalid resources');
 const v=value as Record<string,unknown>,out:Resources={};
 const text=(key:string,max:number)=>{if(v[key]===undefined)return;if(typeof v[key]!=='string'||(v[key] as string).length>max||/[\x00-\x1f\x7f]/.test(v[key] as string))throw Error();out[key]=v[key];};
 for(const k of ['os','cpu'])text(k,512);for(const k of ['platform','arch','status'])text(k,64);
 if(!['ok','partial','unavailable'].includes(String(out.status)))throw Error();
 for(const k of ['checked_at','attempted_at','cores','threads','memory_total','memory_available']){if(v[k]===undefined)continue;if(!Number.isSafeInteger(v[k])||Number(v[k])<0)throw Error();out[k]=v[k];}
 if(!out.checked_at||Number(out.checked_at)>Date.now()+86400_000)throw Error();if(typeof v.refresh_failed==='boolean')out.refresh_failed=v.refresh_failed;
 if(v.disks!==undefined){if(!Array.isArray(v.disks)||v.disks.length>256)throw Error();out.disks=v.disks.map((disk,i)=>{
  if(!disk||typeof disk!=='object')throw Error();const d=disk as Record<string,unknown>,result:Resources={};
  for(const k of ['id','parent','kind','model','filesystem']){if(d[k]===undefined)continue;if(typeof d[k]!=='string'||(d[k] as string).length>512||/[\x00-\x1f\x7f]/.test(d[k] as string))throw Error();result[k]=d[k];}
  if(!result.id||!result.kind)throw Error();if(String(result.id).includes('Volume{'))result.id='volume-'+i;
  for(const k of ['total','free']){if(d[k]===undefined)continue;if(!Number.isSafeInteger(d[k])||Number(d[k])<0)throw Error();result[k]=d[k];}return result;
 });}return out;
}
