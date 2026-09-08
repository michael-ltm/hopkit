import {describe,it,expect} from 'vitest';
import {resources} from '../src/resources';
describe('account resource metadata',()=>{
 it('keeps capacity and zero remaining space but strips paths and unknown data',()=>{
  const h=resources({status:'ok',checked_at:Date.now(),cpu:'test',memory_total:1024,disks:[{id:'volume-test',kind:'volume',total:100,free:0,mounts:['/private']},{id:'\\\\?\\Volume{private-guid}\\',kind:'volume',free:25}],password:'never store'});
  expect(h.disks).toEqual([{id:'volume-test',kind:'volume',total:100,free:0},{id:'volume-1',kind:'volume',free:25}]);expect(h.password).toBeUndefined();
 });
 it('rejects invalid samples and unreasonable payloads',()=>{for(const value of [{status:'ok',checked_at:Date.now(),memory_total:-1},{status:'ok',checked_at:Date.now(),disks:[{id:'x',kind:'disk',free:NaN}]},{status:'ok',checked_at:Date.now(),disks:new Array(257).fill({id:'x',kind:'disk'})}])expect(()=>resources(value)).toThrow();});
});
