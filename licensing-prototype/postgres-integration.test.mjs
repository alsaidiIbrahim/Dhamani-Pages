import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID,randomBytes} from 'node:crypto';
import {PostgresLicenseRepository} from './postgres/repository.mjs';
test('real PostgreSQL approval, uniqueness, rollback and transfer',async t=>{
 if(!process.env.DHAMANI_TEST_DATABASE_URL){t.skip('No temporary PostgreSQL test database configured');return;}
 const {default:pg}=await import('pg');
 const pool=new pg.Pool({connectionString:process.env.DHAMANI_TEST_DATABASE_URL,max:3});
 const {readFileSync}=await import('node:fs');
 try{
  await pool.query(readFileSync(new URL('./postgres/001_schema.sql',import.meta.url),'utf8'));
  const repo=new PostgresLicenseRepository(pool);
  const orderId=randomUUID(),licenseId=randomUUID(),adminId='integration-test-owner';
  await pool.query('INSERT INTO license_orders(id) VALUES($1)',[orderId]);
  const approved=await repo.approveOrder({orderId,licenseId,adminId,activationTokenHash:randomBytes(32)});
  assert.equal(approved.licenseId,licenseId);
  await assert.rejects(()=>repo.approveOrder({orderId,licenseId:randomUUID(),adminId,activationTokenHash:randomBytes(32)}),/order_not_pending/);
  const count=await pool.query('SELECT count(*)::int AS count FROM licenses WHERE order_id=$1',[orderId]);
  assert.equal(count.rows[0].count,1);
  await assert.rejects(()=>repo.transferLicense({licenseId,adminId,newDevicePublicKey:'device-b',expectedRevision:0,verifyDeviceProof:()=>false}),/invalid_device_proof/);
  const unchanged=await pool.query('SELECT revision,device_public_key FROM licenses WHERE id=$1',[licenseId]);
  assert.equal(unchanged.rows[0].revision,0);
  assert.equal(unchanged.rows[0].device_public_key,null);
  const transferred=await repo.transferLicense({licenseId,adminId,newDevicePublicKey:'device-b',expectedRevision:0,verifyDeviceProof:()=>true});
  assert.equal(transferred.revision,1);
  await assert.rejects(()=>repo.transferLicense({licenseId,adminId,newDevicePublicKey:'device-c',expectedRevision:0,verifyDeviceProof:()=>true}),/license_changed_or_inactive/);
  const events=await pool.query('SELECT action FROM license_events WHERE license_id=$1 ORDER BY id',[licenseId]);
  assert.deepEqual(events.rows.map(x=>x.action),['payment_approved','device_transferred']);
 }finally{await pool.end()}
});

test('real PostgreSQL concurrent approvals create exactly one license',async t=>{
 if(!process.env.DHAMANI_TEST_DATABASE_URL){t.skip('No temporary PostgreSQL test database configured');return;}
 const {default:pg}=await import('pg');
 const pool=new pg.Pool({connectionString:process.env.DHAMANI_TEST_DATABASE_URL,max:4});
 const repo=new PostgresLicenseRepository(pool);
 try{
  const orderId=randomUUID(),adminId='concurrency-test';
  await pool.query('INSERT INTO license_orders(id) VALUES($1)',[orderId]);
  const attempts=await Promise.allSettled(Array.from({length:2},()=>repo.approveOrder({orderId,adminId,licenseId:randomUUID(),activationTokenHash:randomBytes(32)})));
  assert.equal(attempts.filter(x=>x.status==='fulfilled').length,1);
  assert.equal(attempts.filter(x=>x.status==='rejected').length,1);
  const licenses=await pool.query('SELECT count(*)::int AS n FROM licenses WHERE order_id=$1',[orderId]);
  const events=await pool.query("SELECT count(*)::int AS n FROM license_events WHERE order_id=$1 AND action='payment_approved'",[orderId]);
  assert.equal(licenses.rows[0].n,1);
  assert.equal(events.rows[0].n,1);
 }finally{await pool.end()}
});
test('real PostgreSQL concurrent transfers reject stale revision',async t=>{
 if(!process.env.DHAMANI_TEST_DATABASE_URL){t.skip('No temporary PostgreSQL test database configured');return;}
 const {default:pg}=await import('pg');
 const pool=new pg.Pool({connectionString:process.env.DHAMANI_TEST_DATABASE_URL,max:4});
 const repo=new PostgresLicenseRepository(pool);
 try{
  const orderId=randomUUID(),licenseId=randomUUID(),adminId='concurrency-test';
  await pool.query('INSERT INTO license_orders(id) VALUES($1)',[orderId]);
  await repo.approveOrder({orderId,licenseId,adminId,activationTokenHash:randomBytes(32)});
  const attempts=await Promise.allSettled(['device-A','device-B'].map(newDevicePublicKey=>repo.transferLicense({licenseId,adminId,newDevicePublicKey,expectedRevision:0,verifyDeviceProof:()=>true})));
  assert.equal(attempts.filter(x=>x.status==='fulfilled').length,1);
  assert.equal(attempts.filter(x=>x.status==='rejected').length,1);
  const license=await pool.query('SELECT revision FROM licenses WHERE id=$1',[licenseId]);
  assert.equal(license.rows[0].revision,1);
  const events=await pool.query("SELECT count(*)::int AS n FROM license_events WHERE license_id=$1 AND action='device_transferred'",[licenseId]);
  assert.equal(events.rows[0].n,1);
 }finally{await pool.end()}
});
