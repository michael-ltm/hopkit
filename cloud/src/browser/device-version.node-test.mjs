import {test} from 'node:test';
import assert from 'node:assert/strict';
import {deviceVersion} from './device-version.js';
const now=1000000;
test('known relay mismatch requests only a web terminal restart while keeping the installed version',()=>{
 const v=deviceVersion({version:'old',installed_version:'new',installed_checked_at:now},{runtime_version:'old'},'new',now);
 assert.equal(v.label,'new');assert.equal(v.kind,'latest');assert.equal(v.restart,true);
 assert.match(v.detail,/网页终端.*待重启/);assert.match(v.detail,/old/);
 assert.doesNotMatch(v.help,/MCP|解锁|需要重新启动/);
});
test('a current installation without an optional web terminal never presents an old heartbeat as its runtime',()=>{
 const v=deviceVersion({version:'old',last_seen:now,installed_version:'new',installed_checked_at:now},null,'new',now);
 assert.equal(v.label,'new');assert.equal(v.kind,'latest');assert.equal(v.runtime,'');assert.equal(v.restart,false);
 assert.match(v.detail,/网页终端.*未连接/);assert.match(v.detail,/可选/);
 assert.doesNotMatch(v.detail,/old|上报进程|重启|解锁/);
});
test('legacy heartbeat does not prove an installation or the age of an unreported relay runtime',()=>{
 const v=deviceVersion({version:'old',last_seen:now},{},'new',now);
 assert.equal(v.kind,'unknown');assert.equal(v.installed,'');assert.equal(v.runtime,'');assert.equal(v.restart,false);assert.match(v.detail,/版本未上报/);
 assert.match(v.detail,/网页终端.*已连接/);assert.doesNotMatch(v.detail,/旧|重启|解锁/);
});
test('an unreported relay version does not tell a current installation to restart or unlock',()=>{
 const v=deviceVersion({installed_version:'new',installed_checked_at:now},{},'new',now);
 assert.equal(v.kind,'latest');assert.equal(v.restart,false);
 assert.match(v.detail,/网页终端.*已连接/);assert.match(v.detail,/版本未上报/);
 assert.doesNotMatch(v.detail+' '+v.help,/旧代理|重启|重新启动|解锁/);
});
test('a known relay version cannot stand in for an unconfirmed installation',()=>{
 const v=deviceVersion({last_seen:now},{runtime_version:'new'},'new',now);
 assert.equal(v.label,'安装版本未确认');assert.equal(v.installed,'');assert.equal(v.kind,'unknown');assert.equal(v.restart,false);
 assert.equal(v.runtime,'new');assert.match(v.detail,/网页终端/);
});
test('offline observations are historical, never green current/latest',()=>{
 const v=deviceVersion({version:'new',installed_version:'new',installed_checked_at:1},null,'new',now);
 assert.equal(v.label,'new');assert.equal(v.kind,'unknown');assert.equal(v.recent,false);assert.match(v.detail,/网页终端.*未连接/);
});
test('installation freshness and an unavailable release keep the version status unknown',()=>{
 assert.equal(deviceVersion({installed_version:'new',installed_checked_at:now-90_000},null,'new',now).kind,'unknown');
 assert.equal(deviceVersion({installed_version:'new',installed_checked_at:now},null,'',now).kind,'unknown');
});
test('restart and a real downgrade are represented without keeping a maximum version',()=>{
 assert.equal(deviceVersion({installed_version:'new',installed_checked_at:now},{runtime_version:'new'},'new',now).restart,false);
 const v=deviceVersion({installed_version:'old',installed_checked_at:now},{runtime_version:'old'},'new',now);
 assert.equal(v.kind,'outdated');assert.equal(v.restart,false);
});
