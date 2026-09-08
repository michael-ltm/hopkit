import {test} from 'node:test';
import assert from 'node:assert/strict';
import {deviceVersion} from './device-version.js';
const now=1000000;
test('old heartbeat cannot make a current installation look old; live agent needs restart',()=>{
 const v=deviceVersion({version:'old',installed_version:'new',installed_checked_at:now},{runtime_version:'old'},'new',now);
 assert.equal(v.label,'new');assert.equal(v.kind,'latest');assert.equal(v.restart,true);assert.match(v.detail,/待重启/);
});
test('legacy heartbeat does not prove an installation or live agent version',()=>{
 const v=deviceVersion({version:'old',last_seen:now},{},'new',now);
 assert.equal(v.kind,'unknown');assert.equal(v.installed,'');assert.equal(v.runtime,'');assert.equal(v.restart,false);assert.match(v.detail,/版本未上报/);
});
test('offline observations are historical, never green current/latest',()=>{
 const v=deviceVersion({version:'new',installed_version:'new',installed_checked_at:1},null,'new',now);
 assert.equal(v.kind,'unknown');assert.equal(v.recent,false);assert.match(v.detail,/代理未连接/);
});
test('restart and a real downgrade are represented without keeping a maximum version',()=>{
 assert.equal(deviceVersion({installed_version:'new',installed_checked_at:now},{runtime_version:'new'},'new',now).restart,false);
 const v=deviceVersion({installed_version:'old',installed_checked_at:now},{runtime_version:'old'},'new',now);
 assert.equal(v.kind,'outdated');assert.equal(v.restart,false);
});
