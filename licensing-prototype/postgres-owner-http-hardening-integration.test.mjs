import test from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes,randomUUID,createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {PostgresOwnerSessionRepository} from './postgres/owner-session-repository.mjs';
import {startLoopbackPostgresOwnerReadServer} from './postgres/owner-read-http.mjs';
test('real PostgreSQL owner HTTP rejects bodies, oversized cookies, long URLs and adds safe headers',async t=>{
 if(!process.env.DHAMANI_TEST_DATABASE_URL){t.skip('No temporary PostgreSQL test database configured');return;}
 const {default:pg}=await import('pg');const pool=new pg.Pool({connectionString:process.env.DHAMANI_TEST_DATABASE_URL,max:3});let server;
 try{
  await pool.query(readFileSync(new URL('./postgres/003_owner_auth_proposal.sql',import.meta.url),'utf8'));
  const token=randomBytes(32).toString('base64url'),now=new Date();
  await pool.query('INSERT INTO owner_auth_sessions(session_hash,owner_id,mfa_verified,created_at,last_activity_at,expires_at) VALUES($1,$2,TRUE,$3,$3,$4)',[createHash('sha256').update(token).digest(),randomUUID(),new Date(now.getTime()-1000),new Date(now.getTime()+30*60*1000)]);
  server=await startLoopbackPostgresOwnerReadServer({sessionRepository:new PostgresOwnerSessionRepository(pool),licenseRepository:{listOrders:async()=>[],listLicenses:async()=>[],listEvents:async()=>[]}});
  const base=`http://127.0.0.1:${server.address().port}`,cookie='dhamani_owner_session='+token;
  const ok=await fetch(base+'/owner/orders',{headers:{cookie}});
  assert.equal(ok.status,200);assert.equal(ok.headers.get('x-frame-options'),'DENY');
  assert.equal(ok.headers.get('referrer-policy'),'no-referrer');
  assert.match(ok.headers.get('content-security-policy'),/default-src 'none'/);
  assert.equal((await fetch(base+'/owner/orders',{headers:{cookie,'content-length':'1'}})).status,400);
  assert.equal((await fetch(base+'/owner/orders',{headers:{cookie:cookie+'; junk='+('x'.repeat(4200))}})).status,403);
  assert.equal((await fetch(base+'/owner/orders?x='+('a'.repeat(2100)),{headers:{cookie}})).status,414);
  assert.equal((await fetch(base+'/owner/orders',{method:'POST',headers:{cookie},body:'{}'})).status,405);
 }finally{if(server)await new Promise((resolve,reject)=>server.close(err=>err?reject(err):resolve()));await pool.end();}
});
