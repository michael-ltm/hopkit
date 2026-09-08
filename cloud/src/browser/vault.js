import { argon2idAsync } from '@noble/hashes/argon2.js';
const enc=new TextEncoder(),dec=new TextDecoder();
export const b64=b=>{let s='';for(let i=0;i<b.length;i+=8192)s+=String.fromCharCode(...b.subarray(i,i+8192));return btoa(s).replaceAll('+','-').replaceAll('/','_').replaceAll('=','');};
const bytes=s=>Uint8Array.from(atob(s.replaceAll('-','+').replaceAll('_','/')),c=>c.charCodeAt(0));
const random=n=>crypto.getRandomValues(new Uint8Array(n));
async function derive(master,label){const key=await crypto.subtle.importKey('raw',master,'HKDF',false,['deriveBits']);return new Uint8Array(await crypto.subtle.deriveBits({name:'HKDF',hash:'SHA-256',salt:new Uint8Array(),info:enc.encode('sshm-v1/'+label)},key,256));}
const aad=(e,p)=>enc.encode('sshm-v1\n'+e.account+'\n'+e.vault_id+'\n'+p);
async function decrypt(key,nonce,ciphertext,data){const k=await crypto.subtle.importKey('raw',key,'AES-GCM',false,['decrypt']);return new Uint8Array(await crypto.subtle.decrypt({name:'AES-GCM',iv:bytes(nonce),additionalData:data},k,bytes(ciphertext)));}
async function signing(master){const seed=await derive(master,'signature'),der=new Uint8Array(48);der.set([48,46,2,1,0,48,5,6,3,43,101,112,4,34,4,32]);der.set(seed,16);seed.fill(0);try{return await crypto.subtle.importKey('pkcs8',der,{name:'Ed25519'},true,['sign']);}finally{der.fill(0);}}
const message=(user,base,op,blob)=>enc.encode('sshm-sync-v1\n'+user+'\n'+base+'\n'+op+'\n'+blob);
function envelope(user,snapshot){const e=JSON.parse(snapshot.blob);if(snapshot.blob.length>2*1024*1024 || e.version!==1 || e.account!==user || e.kdf!=='argon2id-64m-t3-p4' || bytes(e.salt).length!==16 || !Number.isSafeInteger(snapshot.revision) || snapshot.revision<1 || snapshot.revision!==snapshot.base_revision+1)throw Error('保险库格式或版本不受支持。');return e;}
export async function unlockVault(user,snapshot,phrase,onProgress){let master;try{const e=envelope(user,snapshot);const kek=await argon2idAsync(enc.encode(phrase),bytes(e.salt),{t:3,m:65536,p:4,dkLen:32,maxmem:80*1024*1024,onProgress});try{master=await decrypt(kek,e.wrap_nonce,e.wrapped_key,aad(e,'wrap'));}finally{kek.fill(0);}const signingKey=await signing(master),jwk=await crypto.subtle.exportKey('jwk',signingKey);if(jwk.x!==snapshot.root_public)throw Error();const pub=await crypto.subtle.importKey('raw',bytes(jwk.x),{name:'Ed25519'},false,['verify']);if(!await crypto.subtle.verify('Ed25519',pub,bytes(snapshot.signature),message(user,snapshot.base_revision,snapshot.operation_id,snapshot.blob)))throw Error();const key=await derive(master,'data');let plain;try{plain=await decrypt(key,e.nonce,e.ciphertext,aad(e,'data'));const data=JSON.parse(dec.decode(plain));if(data.version!==1 || !data.entries || !data.credentials || !data.deleted || !data.conflicts)throw Error();return {user,snapshot,envelope:e,master,data,close(){master.fill(0);this.data=null;this.master=null;}};}finally{key.fill(0);plain?.fill(0);}}catch{master?.fill(0);throw Error('无法解锁或验证保险库，请检查口令。');}}
export async function encryptVault(v){const key=await derive(v.master,'data'),nonce=random(12),plain=enc.encode(JSON.stringify(v.data));let ciphertext;try{const k=await crypto.subtle.importKey('raw',key,'AES-GCM',false,['encrypt']);ciphertext=new Uint8Array(await crypto.subtle.encrypt({name:'AES-GCM',iv:nonce,additionalData:aad(v.envelope,'data')},k,plain));}finally{key.fill(0);plain.fill(0);}const e={...v.envelope,nonce:b64(nonce),ciphertext:b64(ciphertext)},blob=JSON.stringify(e);if(blob.length>2*1024*1024)throw Error('保险库超过容量限制。');const operation_id=b64(random(18)),base_revision=v.snapshot.revision;const signature=b64(new Uint8Array(await crypto.subtle.sign('Ed25519',await signing(v.master),message(v.user,base_revision,operation_id,blob))));return {base_revision,operation_id,blob,signature,root_public:v.snapshot.root_public};}

// Only exported operations see the unlocked master; UI automation never reads it.
export async function signVault(v,messageText){return b64(new Uint8Array(await crypto.subtle.sign('Ed25519',await signing(v.master),enc.encode(messageText))));}
export async function linkCode(publicKey){const hash=new Uint8Array(await crypto.subtle.digest('SHA-256',bytes(publicKey)));const s=[...hash.slice(0,6)].map(b=>b.toString(16).padStart(2,'0')).join('').toUpperCase();return s.match(/.{4}/g).join('-');}
export async function createLinkGrant(v,request){
 if(request.expires<Date.now()||request.expires>Date.now()+610000)throw Error('设备请求已过期。');
 const remote=await crypto.subtle.importKey('raw',bytes(request.public_key),{name:'ECDH',namedCurve:'P-256'},false,[]);
 const pair=await crypto.subtle.generateKey({name:'ECDH',namedCurve:'P-256'},true,['deriveBits']);
 const shared=new Uint8Array(await crypto.subtle.deriveBits({name:'ECDH',public:remote},pair.privateKey,256));
 const base=await crypto.subtle.importKey('raw',shared,'HKDF',false,['deriveKey']);shared.fill(0);
 const key=await crypto.subtle.deriveKey({name:'HKDF',hash:'SHA-256',salt:new Uint8Array(),info:enc.encode('sshm-link-v1/'+v.user+'/'+request.id)},base,{name:'AES-GCM',length:256},false,['encrypt']);
 const nonce=random(12),ciphertext=await crypto.subtle.encrypt({name:'AES-GCM',iv:nonce,additionalData:enc.encode('sshm-link-v1\n'+v.user+'\n'+request.id+'\n'+request.public_key)},key,v.master);
 const grant=JSON.stringify({version:1,public_key:b64(new Uint8Array(await crypto.subtle.exportKey('raw',pair.publicKey))),nonce:b64(nonce),ciphertext:b64(new Uint8Array(ciphertext))});
 const signature=await signVault(v,'sshm-link-v1\n'+v.user+'\n'+request.id+'\n'+request.public_key+'\n'+request.expires+'\n'+grant);
 return {grant,signature};
}
export async function shellCipher(v,r,direction){
 const raw=await derive(v.master,'shell/'+v.user+'/'+r.device+'/'+r.epoch+'/'+r.session+'/'+direction);let key=await crypto.subtle.importKey('raw',raw,'AES-GCM',false,['encrypt','decrypt']);raw.fill(0);let seq=0;
 const params=()=>{if(!key||seq>=2**32)throw Error('终端会话已结束。');const iv=new Uint8Array(12);new DataView(iv.buffer).setUint32(8,seq);return {name:'AES-GCM',iv,additionalData:enc.encode('sshm-shell-frame-v1\n'+r.session+'\n'+direction+'\n'+seq)};};
 return {async seal(payload){const plaintext=enc.encode(JSON.stringify(payload));if(plaintext.length>32768)throw Error('终端输入过长。');try{const ciphertext=await crypto.subtle.encrypt(params(),key,plaintext);return {type:'frame',session:r.session,seq:seq++,ciphertext:b64(new Uint8Array(ciphertext))};}finally{plaintext.fill(0);}},async open(frame){if(frame.type!=='frame'||frame.session!==r.session||frame.seq!==seq||typeof frame.ciphertext!=='string'||frame.ciphertext.length>60000)throw Error('终端序列无效。');const plaintext=new Uint8Array(await crypto.subtle.decrypt(params(),key,bytes(frame.ciphertext)));try{if(plaintext.length>32768)throw Error();const p=JSON.parse(dec.decode(plaintext));seq++;return p;}finally{plaintext.fill(0);}},close(){key=null;}};
}

// Refresh ciphertext with the already unlocked key; no unlock material leaves this module.
export async function refreshVault(v,snapshot){
 const e=envelope(v.user,snapshot);
 if(snapshot.revision<=v.snapshot.revision||snapshot.root_public!==v.snapshot.root_public||e.vault_id!==v.envelope.vault_id)throw Error('保险库身份或版本发生变化，请重新解锁。');
 const pub=await crypto.subtle.importKey('raw',bytes(snapshot.root_public),{name:'Ed25519'},false,['verify']);
 if(!await crypto.subtle.verify('Ed25519',pub,bytes(snapshot.signature),message(v.user,snapshot.base_revision,snapshot.operation_id,snapshot.blob)))throw Error('保险库签名验证失败。');
 const key=await derive(v.master,'data');let plain;
 try{plain=await decrypt(key,e.nonce,e.ciphertext,aad(e,'data'));const data=JSON.parse(dec.decode(plain));if(data.version!==1||!data.entries||!data.credentials||!data.deleted||!data.conflicts)throw Error('保险库格式错误。');return {data,envelope:e};}finally{key.fill(0);plain?.fill(0);}
}

export async function latestRelease(){
 const response=await fetch('/downloads/release.json',{cache:'no-store'});if(!response.ok)throw Error('版本信息暂不可用');
 const signed=await response.json();if(typeof signed.payload!=='string'||signed.payload.length>20000)throw Error('版本信息格式错误');
 const key=await crypto.subtle.importKey('raw',bytes('ihdgSJDRX-pBIH6ORAanzGs4-JwAFNcmYreMXR2R8wU'),{name:'Ed25519'},false,['verify']);
 if(!await crypto.subtle.verify('Ed25519',key,bytes(signed.signature),enc.encode(signed.payload)))throw Error('发布签名验证失败');
 const release=JSON.parse(signed.payload);if(release.protocol!==1||release.expires*1000<Date.now()||typeof release.version!=='string')throw Error('版本信息已过期');return release.version;
}
export async function verifyJobReceipt(v,j){
 if(!j.receipt)return false;
 const pub=await crypto.subtle.importKey('raw',bytes(v.snapshot.root_public),{name:'Ed25519'},false,['verify']);
 return crypto.subtle.verify('Ed25519',pub,bytes(j.receipt),enc.encode('sshm-job-result-v1\n'+v.user+'\n'+j.id+'\n'+j.device+'\n'+j.status+'\n'+j.code+'\n'+j.count));
}
