import {test} from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,createPrivateKey} from 'node:crypto';
import {exportKey,exportableKeys} from './key-export.js';
const pem=generateKeyPairSync('ed25519').privateKey.export({format:'pem',type:'pkcs8',cipher:'aes-256-cbc',passphrase:'synthetic-only'});
function fixture(){return {entries:{target:{aliases:['prod-7w'],credentials:['password','key']},other:{aliases:['other'],credentials:['other-key']}},credentials:{password:{kind:'password',password:'unused'},key:{kind:'key',key:Buffer.from(pem).toString('base64'),fingerprint:'SHA256:synthetic'},'other-key':{kind:'key',key:Buffer.from(pem).toString('base64')}},deleted:{},conflicts:{}};}
test('downloads the selected original encrypted private key, preserving its password',()=>{
 const data=fixture(),before=JSON.stringify(data),result=exportKey(data,'target','key');
 assert.deepEqual(Buffer.from(result.bytes),Buffer.from(pem));
 assert.equal(result.filename,'prod-7w.key');
 assert.equal(createPrivateKey({key:Buffer.from(result.bytes),passphrase:'synthetic-only'}).asymmetricKeyType,'ed25519');
 assert.equal(JSON.stringify(data),before);
 assert.deepEqual(exportableKeys(data,'target'),[{id:'key',fingerprint:'SHA256:synthetic'}]);
});
test('cannot export another connection credential or a password',()=>{
 for(const id of ['other-key','password','missing'])assert.throws(()=>exportKey(fixture(),'target',id));
});
test('locked, deleted, conflicting and missing entries cannot export',()=>{
 assert.throws(()=>exportKey(null,'target','key'));
 for(const field of ['deleted','conflicts']){const d=fixture();d[field].target=true;assert.throws(()=>exportKey(d,'target','key'));}
 assert.throws(()=>exportKey(fixture(),'missing','key'));
});
test('rejects invalid base64 and public keys; makes filenames safe',()=>{
 for(const key of ['!!!',Buffer.from('ssh-ed25519 AAAA synthetic').toString('base64')]){const d=fixture();d.credentials.key.key=key;assert.throws(()=>exportKey(d,'target','key'));}
 const d=fixture();d.entries.target.aliases=['../../bad\\name\n'];assert.match(exportKey(d,'target','key').filename,/^[\p{L}\p{N}_-]+\.key$/u);
});
test('exports valid PEM with preamble without changing imported bytes',()=>{
 for(const prefix of ['\n','Imported SSH key\n']){
  const d=fixture(),original=prefix+pem;d.credentials.key.key=Buffer.from(original).toString('base64');
  assert.equal(createPrivateKey({key:original,passphrase:'synthetic-only'}).asymmetricKeyType,'ed25519');
  assert.equal(Buffer.from(exportKey(d,'target','key').bytes).toString(),original);
 }
});
test('multiple attached keys export exactly the selected key',()=>{
 const d=fixture(),second=generateKeyPairSync('rsa',{modulusLength:2048}).privateKey.export({format:'pem',type:'pkcs1'});
 d.entries.target.credentials.push('second');d.credentials.second={kind:'key',key:Buffer.from(second).toString('base64')};
 assert.deepEqual(exportableKeys(d,'target').map(c=>c.id),['key','second']);
 assert.deepEqual(Buffer.from(exportKey(d,'target','second').bytes),Buffer.from(second));
});
