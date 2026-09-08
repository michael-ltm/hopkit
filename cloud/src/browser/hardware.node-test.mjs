import {test} from 'node:test';
import assert from 'node:assert/strict';
import {storageKind,bytes} from './hardware.js';
test('storage totals exclude RAM, eMMC boot regions and disconnected NBD but preserve mounted and unmounted disks',()=>{
 const disks=[{id:'/dev/mmcblk1',kind:'disk',total:32},{id:'/dev/mmcblk1boot0',kind:'disk',total:4},{id:'/dev/zram0',kind:'disk',total:2},{id:'/dev/nbd0',kind:'disk'},{id:'/dev/nbd1',kind:'disk',total:128},{id:'/dev/nvme1n1',kind:'disk',total:960},{id:'/dev/sda',kind:'disk',total:4000},{id:'/dev/sda1',kind:'partition',total:3000},{id:'/dev/disk3',kind:'container',total:32}];
 const physical=disks.filter(d=>storageKind(d)==='disk');assert.equal(physical.length,4);assert.equal(physical.reduce((n,d)=>n+d.total,0),5120);assert.equal(disks.length,9);
 assert.equal(storageKind({id:'\\\\.\\PHYSICALDRIVE1',kind:'disk'}),'disk');assert.equal(bytes(undefined),'未知');assert.equal(bytes(0),'0 B');
});

test('remaining space deduplicates APFS containers and accepts zero free space',async()=>{
 const {freeSpace}=await import('./hardware.js');
 assert.deepEqual(freeSpace({disks:[{id:'/dev/disk3',kind:'container',total:100,free:25},{id:'/dev/disk3s1',parent:'/dev/disk3',kind:'volume',total:100,free:25},{id:'/dev/disk3s1s1',kind:'volume',total:100,free:25},{id:'/dev/sdb1',kind:'partition',total:80,free:0}]}),{known:2,total:180,free:25});
 assert.equal(freeSpace({disks:[{id:'/dev/sda',kind:'disk',total:100}]}).known,0);
});
