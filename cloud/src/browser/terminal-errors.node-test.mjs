import test from 'node:test';
import assert from 'node:assert/strict';
import {terminalFailureMessage} from './terminal-errors.js';

test('only confirmed PTY denial suggests explicit raw exec', () => {
 const payload={data:'pty_unavailable',diagnostics:{stage:'pty_request',reason_code:'pty_denied',ssh_authenticated:true,pty_requested:true,pty_granted:false,suggested_action:'explicit_exec'}};
 assert.match(terminalFailureMessage(payload),/认证成功/);
 assert.match(terminalFailureMessage(payload),/--raw-environment/);
 for(const reason_code of ['pty_request_failed','cancelled','timeout']){
  const text=terminalFailureMessage({...payload,diagnostics:{...payload.diagnostics,reason_code}});
  assert.doesNotMatch(text,/--raw-environment|拒绝分配/);
 }
});

test('shell failure after a granted PTY is distinct from authentication and PTY denial',()=>{
 const text=terminalFailureMessage({data:'pty_unavailable',diagnostics:{stage:'shell_start',reason_code:'shell_start_failed',ssh_authenticated:true,pty_requested:true,pty_granted:true}});
 assert.match(text,/shell/);
 assert.doesNotMatch(text,/认证失败|--raw-environment|拒绝分配/);
});

test('legacy errors still render and unknown diagnostic values never become UI text',()=>{
 assert.match(terminalFailureMessage({data:'pty_unavailable'}),/交互终端/);
 assert.match(terminalFailureMessage({data:'ssh_authentication'}),/认证失败/);
 const unknown=terminalFailureMessage({data:'private-host',diagnostics:{stage:'private-command',reason_code:'secret'}});
 assert.doesNotMatch(unknown,/private|secret/);
 assert.match(unknown,/连接未成功/);
 const forged=terminalFailureMessage({data:'ssh_authentication',diagnostics:{stage:'pty_request',reason_code:'pty_denied',ssh_authenticated:true}});
 assert.doesNotMatch(forged,/--raw-environment/);
});
