import test from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes,randomUUID,createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {PostgresOwnerSessionRepository} from './postgres/owner-session-repository.mjs';
import {startLoopbackPostgresOwnerReadServer} from './postgres/owner-read-http.mjs';
test('real PostgreSQL owner read-only HTTP requires active owner session and rejects hostile origin',async t=>{
 if(!process.env.DHAMANI_TEST_DATABASE_URL){t.skip('No temporary PostgreSQL test database configured');return;}
 const {default:pg}=await import('pg');const pool=new pg.Pool({connectionString:process.env.DHAMANI_TEST_DATABASE_URL,max:4});
 let server;
 try{
  await pool.query(readFileSync(new URL('./postgres/003_owner_auth_proposal.sql',import.meta.url),'utf8'));
  const token=randomBytes(32).toString('base64url'),ownerId=randomUUID(),now=new Date();
  await pool.query('INSERT INTO owner_auth_sessions(session_hash,owner_id,mfa_verified,created_at,last_activity_at,expires_at) VALUES($1,$2,TRUE,$3,$3,$4)',[createHash('sha256').update(token).digest(),ownerId,new Date(now.getTime()-1000),new Date(now.getTime()+30*60*1000)]);
  const licenseRepository={listOrders:async()=>[{id:'test-order'}],listLicenses:async()=>[],listEvents:async()=>[]};
  const sessions=new PostgresOwnerSessionRepository(pool);
  server=await startLoopbackPostgresOwnerReadServer({sessionRepository:sessions,licenseRepository});
  const base=`http://127.0.0.1:${server.address().port}`,cookie='dhamani_owner_session='+token;
  assert.equal((await fetch(base+'/owner/orders')).status,403);
  assert.equal((await fetch(base+'/owner/orders',{headers:{cookie,origin:'http://malicious.example'}})).status,403);
  const ok=await fetch(base+'/owner/orders',{headers:{cookie}});
  assert.equal(ok.status,200);
  assert.deepEqual((await ok.json()).items,[{id:'test-order'}]);
  assert.equal((await fetch(base+'/owner/orders',{method:'POST',headers:{cookie}})).status,405);
  assert.equal((await fetch(base+'/owner/unknown',{headers:{cookie}})).status,404);
  assert.equal(await sessions.revoke({token}),true);
  assert.equal((await fetch(base+'/owner/orders',{headers:{cookie}})).status,403);
 }finally{
  if(server)await new Promise((resolve,reject)=>server.close(err=>err?reject(err):resolve()));
  await pool.end();
 }
});
