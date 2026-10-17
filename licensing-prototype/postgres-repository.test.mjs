import test from 'node:test';
import assert from 'node:assert/strict';
import {PostgresLicenseRepository} from './postgres/repository.mjs';
function fakePool(handler){
 const calls=[];
 return {calls,connect:async()=>({query:async(sql,args=[])=>{calls.push({sql,args});if(['BEGIN','COMMIT','ROLLBACK'].includes(sql))return {rowCount:0,rows:[]};return handler(sql,args)},release:()=>calls.push({sql:'RELEASE'})})};
}
test('approval commits order, license and audit together',async()=>{
 const pool=fakePool(sql=>sql.startsWith('UPDATE license_orders')?{rowCount:1,rows:[{id:'order'}]}:sql.startsWith('INSERT INTO licenses')?{rowCount:1,rows:[{id:'license'}]}:{rowCount:1,rows:[]});
 const result=await new PostgresLicenseRepository(pool).approveOrder({orderId:'order',adminId:'owner',licenseId:'license',activationTokenHash:Buffer.alloc(32)});
 assert.equal(result.licenseId,'license');
 assert.deepEqual(pool.calls.map(c=>c.sql==='BEGIN'||c.sql==='COMMIT'||c.sql==='RELEASE'?c.sql:c.sql.split(' ').slice(0,3).join(' ')),['BEGIN','UPDATE license_orders SET','INSERT INTO licenses(id,order_id,activation_token_hash)','INSERT INTO license_events(order_id,license_id,actor_id,action)','COMMIT','RELEASE']);
});
test('failed license creation rolls back approval',async()=>{
 const pool=fakePool(sql=>{if(sql.startsWith('UPDATE license_orders'))return {rowCount:1,rows:[{id:'order'}]};throw Error('unique_violation')});
 await assert.rejects(()=>new PostgresLicenseRepository(pool).approveOrder({orderId:'order',adminId:'owner',licenseId:'license',activationTokenHash:Buffer.alloc(32)}),/unique_violation/);
 assert.ok(pool.calls.some(c=>c.sql==='ROLLBACK'));
 assert.ok(!pool.calls.some(c=>c.sql==='COMMIT'));
});
test('transfer refuses invalid proof without update and rolls back',async()=>{
 const pool=fakePool(sql=>sql.startsWith('SELECT')?{rowCount:1,rows:[{id:'license',revision:0,status:'active'}]}:{rowCount:1,rows:[]});
 await assert.rejects(()=>new PostgresLicenseRepository(pool).transferLicense({licenseId:'license',adminId:'owner',newDevicePublicKey:'public',expectedRevision:0,verifyDeviceProof:()=>false}),/invalid_device_proof/);
 assert.ok(!pool.calls.some(c=>c.sql.startsWith('UPDATE licenses')));
 assert.ok(pool.calls.some(c=>c.sql==='ROLLBACK'));
});
test('valid transfer updates revision and logs event atomically',async()=>{
 const pool=fakePool(sql=>sql.startsWith('SELECT')?{rowCount:1,rows:[{id:'license',revision:2,status:'active'}]}:sql.startsWith('UPDATE licenses')?{rowCount:1,rows:[{revision:3}]}:{rowCount:1,rows:[]});
 const result=await new PostgresLicenseRepository(pool).transferLicense({licenseId:'license',adminId:'owner',newDevicePublicKey:'public',expectedRevision:2,verifyDeviceProof:()=>true});
 assert.equal(result.revision,3);
 assert.ok(pool.calls.some(c=>c.sql.includes('device_transferred')));
 assert.ok(pool.calls.some(c=>c.sql==='COMMIT'));
});

test('activation binds an approved license and records the event',async()=>{
 const pool=fakePool(sql=>sql.startsWith('SELECT l.id')?{rowCount:1,rows:[{id:'license',status:'active',device_public_key:null,revision:0,order_status:'approved'}]}:sql.startsWith('UPDATE licenses')?{rowCount:1,rows:[{revision:0}]}:{rowCount:1,rows:[]});
 const result=await new PostgresLicenseRepository(pool).activateLicense({licenseId:'license',devicePublicKey:'deviceA',verifyDeviceProof:()=>true});
 assert.equal(result.alreadyBound,false);
 assert.ok(pool.calls.some(x=>x.sql.includes('device_activated')));
 assert.ok(pool.calls.some(x=>x.sql==='COMMIT'));
});
test('activation rejects unpaid order without writing',async()=>{
 const pool=fakePool(sql=>sql.startsWith('SELECT l.id')?{rowCount:1,rows:[{status:'active',device_public_key:null,revision:0,order_status:'pending'}]}:{rowCount:1,rows:[]});
 await assert.rejects(()=>new PostgresLicenseRepository(pool).activateLicense({licenseId:'license',devicePublicKey:'deviceA',verifyDeviceProof:()=>true}),/payment_not_approved/);
 assert.ok(!pool.calls.some(x=>x.sql.startsWith('UPDATE licenses')));
 assert.ok(pool.calls.some(x=>x.sql==='ROLLBACK'));
});
test('activation rejects a different device before proof or update',async()=>{
 const pool=fakePool(sql=>sql.startsWith('SELECT l.id')?{rowCount:1,rows:[{status:'active',device_public_key:'deviceA',revision:0,order_status:'approved'}]}:{rowCount:1,rows:[]});
 let proofCalled=false;
 await assert.rejects(()=>new PostgresLicenseRepository(pool).activateLicense({licenseId:'license',devicePublicKey:'deviceB',verifyDeviceProof:()=>{proofCalled=true;return true}}),/already_bound/);
 assert.equal(proofCalled,false);
 assert.ok(!pool.calls.some(x=>x.sql.startsWith('UPDATE licenses')));
});
test('activation rejects missing device proof and rolls back',async()=>{
 const pool=fakePool(sql=>sql.startsWith('SELECT l.id')?{rowCount:1,rows:[{status:'active',device_public_key:null,revision:0,order_status:'approved'}]}:{rowCount:1,rows:[]});
 await assert.rejects(()=>new PostgresLicenseRepository(pool).activateLicense({licenseId:'license',devicePublicKey:'deviceA',verifyDeviceProof:()=>false}),/invalid_device_proof/);
 assert.ok(!pool.calls.some(x=>x.sql.startsWith('UPDATE licenses')));
});
