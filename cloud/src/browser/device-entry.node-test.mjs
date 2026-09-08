import {test} from 'node:test';
import assert from 'node:assert/strict';
import {addDeviceEntry,deviceConnectionId} from './device-entry.js';
test('adding a client twice updates its stable identity and retains SSH connections',async()=>{
 const data={entries:{ssh:{id:'ssh',server:{Host:'example.invalid'},credentials:['key']}},deleted:{},activity:{},conflicts:{}};
 const device={id:'Device_Test_123',label:'Linux one',kind:'cli',platform:'linux'};
 const a=await addDeviceEntry(data,device);const id=a.id;assert.equal(id,'1963594c6b6b58a9637f04cf0d4a29110c11d8ca5d3e7d52e94630fff0a8de5e');
 const b=await addDeviceEntry(data,{...device,label:'renamed',note:'second'});
 assert.equal(b.id,id);assert.equal(Object.keys(data.entries).length,2);assert.deepEqual(b.aliases,['renamed']);assert.equal(b.server.Description,'second');assert.deepEqual(b.credentials,[]);assert.equal(deviceConnectionId(b.server),device.id);
 assert.deepEqual(data.entries.ssh.credentials,['key']);
});
test('browser sessions and conflicted device entries cannot be silently added',async()=>{
 const data={entries:{},deleted:{},activity:{},conflicts:{}};
 await assert.rejects(addDeviceEntry(data,{id:'browser_123',kind:'browser'}));
 const device={id:'Device_Test_123',label:'Mac',kind:'cli',platform:'darwin'};const entry=await addDeviceEntry(data,device);assert.equal(data.activity[entry.id].platform,'macos');data.conflicts[entry.id]={};await assert.rejects(addDeviceEntry(data,device));
});
