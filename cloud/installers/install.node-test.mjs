import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,writeFileSync,readFileSync,mkdirSync,rmSync,readdirSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {spawnSync} from 'node:child_process';
import {createHash} from 'node:crypto';
const template=readFileSync(new URL('./install.sh',import.meta.url),'utf8');
function fixture(){
 const root=mkdtempSync(join(tmpdir(),'sshm-install-test-')),bin=join(root,'tools'),home=join(root,'home'),dir=join(home,'.local/bin');mkdirSync(bin);mkdirSync(home);mkdirSync(dir,{recursive:true});
 const payload='#!/bin/sh\nprintf "test-version\\n"\n',hash=createHash('sha256').update(payload).digest('hex');writeFileSync(join(root,'payload'),payload);
 const script=template.replace('@@VERSION@@','test-version').replace('@@POSIX_ASSETS@@',['linux-amd64','linux-arm64','darwin-amd64','darwin-arm64'].map(t=>`${t}) expected='${hash}' ;;`).join('\n'));writeFileSync(join(root,'install.sh'),script);
 const tool=(name,text)=>writeFileSync(join(bin,name),'#!/bin/sh\n'+text,{mode:0o700});
 tool('uname','case "$1" in -s) echo "${QA_OS:-Linux}";; -m) echo "${QA_ARCH:-x86_64}";; esac\n');tool('sysctl','echo "${QA_APPLE_ARM:-0}"\n');tool('getconf','echo 64\n');
 tool('curl','while [ "$#" -gt 0 ]; do case "$1" in --output) shift; dst=$1;; https:*) printf "%s" "$1" > "$QA_ROOT/url";; esac; shift; done\nif [ "${QA_BAD:-0}" = 1 ]; then echo broken > "$dst"; else cp "$QA_ROOT/payload" "$dst"; fi\n');
 const run=(more={})=>spawnSync('/bin/sh',[join(root,'install.sh')],{encoding:'utf8',env:{...process.env,HOME:home,SHELL:'/bin/bash',PATH:bin+':'+process.env.PATH,QA_ROOT:root,...more}});
 return {root,home,dir,run,close:()=>rmSync(root,{recursive:true,force:true})};
}
test('automatic OS/architecture routes, Rosetta native ARM and unsupported CPUs',()=>{const f=fixture();try{
 for(const [os,arch,arm,target] of [['Linux','x86_64','0','linux-amd64'],['Linux','aarch64','0','linux-arm64'],['Darwin','x86_64','0','darwin-amd64'],['Darwin','x86_64','1','darwin-arm64']]){
  const r=f.run({QA_OS:os,QA_ARCH:arch,QA_APPLE_ARM:arm});assert.equal(r.status,0,r.stderr);assert.ok(readFileSync(join(f.root,'url'),'utf8').endsWith(target));
 }
 const old=readFileSync(join(f.dir,'sshm'));const r=f.run({QA_ARCH:'mips'});assert.notEqual(r.status,0);assert.deepEqual(readFileSync(join(f.dir,'sshm')),old);
}finally{f.close();}});
test('bad checksum retains existing client, cleans staging, PATH setup is idempotent',()=>{const f=fixture();try{
 assert.equal(f.run().status,0);assert.equal(f.run().status,0);const before=readFileSync(join(f.dir,'sshm'));
 const bad=f.run({QA_BAD:'1'});assert.notEqual(bad.status,0);assert.match(bad.stderr,/SHA-256 mismatch/);assert.deepEqual(readFileSync(join(f.dir,'sshm')),before);
 assert.equal(readdirSync(f.dir).filter(n=>n.startsWith('.sshm-install.')).length,0);
 assert.equal(readFileSync(join(f.home,'.bashrc'),'utf8').split('export PATH=').length-1,1);
}finally{f.close();}});
