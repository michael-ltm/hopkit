import {SELF} from 'cloudflare:test';
import {describe,it,expect} from 'vitest';
describe('public installation and download routes',()=>{
 it('serves executable names and binary MIME on every platform without login',async()=>{
  for(const os of ['darwin','linux','windows'])for(const arch of ['amd64','arm64']){
   const name=`sshm-${os}-${arch}${os==='windows'?'.exe':''}`;
   const r=await SELF.fetch('https://sshm.test/downloads/'+name,{method:'HEAD'});
   expect(r.status).toBe(200);expect(r.headers.get('Content-Type')).toBe('application/octet-stream');
   expect(r.headers.get('Content-Disposition')).toBe(`attachment; filename="${name}"`);
   expect(await r.text()).toBe('');
  }
 });
 it('serves complete pinned installers, with no account or shell credentials',async()=>{
  for(const path of ['/install.sh','/install.ps1']){
   const r=await SELF.fetch('https://sshm.test'+path);expect(r.status).toBe(200);
   expect(r.headers.get('Cache-Control')).toBe('no-store');const script=await r.text();
   expect(script).not.toContain('@@');expect(script).toContain('SHA-256 mismatch');
   expect(script).toContain('sshm.yunmini.net/downloads/');
  }
 });
});
