import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createUnlockFlow} from './unlock-flow.js';

test('locked action opens one prompt and resumes exactly once after unlock',async()=>{
 let unlocked=false,shown=[],calls=0;
 const flow=createUnlockFlow({isUnlocked:()=>unlocked,show:label=>shown.push(label)});
 await flow.run('批准设备',()=>calls++);
 const ticket=flow.ticket();
 await flow.run('其他设备',()=>calls+=10);
 assert.deepEqual(shown,['批准设备']);assert.equal(calls,0);
 assert.equal(await flow.resume(ticket),false);assert.equal(calls,0);
 unlocked=true;assert.equal(await flow.resume(ticket),true);assert.equal(calls,1);
 assert.equal(await flow.resume(ticket),false);assert.equal(calls,1);
});
test('cancelled or superseded unlock cannot run a queued action',async()=>{
 let unlocked=false,calls=0;
 const flow=createUnlockFlow({isUnlocked:()=>unlocked,show:()=>{}});
 await flow.run('old',()=>calls+=100);const old=flow.ticket();flow.cancel();
 await flow.run('new',()=>calls++);const current=flow.ticket();unlocked=true;
 assert.equal(await flow.resume(old),false);assert.equal(calls,0);
 await flow.resume(current);assert.equal(calls,1);
});
test('already unlocked action proceeds without another prompt',async()=>{
 let calls=0;const flow=createUnlockFlow({isUnlocked:()=>true,show:()=>assert.fail('unexpected prompt')});
 await flow.run('操作',()=>calls++);assert.equal(calls,1);assert.equal(flow.ticket(),null);
});
test('failed continuation is consumed rather than silently retried',async()=>{
 let unlocked=false,calls=0;const flow=createUnlockFlow({isUnlocked:()=>unlocked,show:()=>{}});
 await flow.run('操作',()=>{calls++;throw Error('expired request');});const ticket=flow.ticket();unlocked=true;
 await assert.rejects(flow.resume(ticket),/expired request/);assert.equal(await flow.resume(ticket),false);assert.equal(calls,1);
});
