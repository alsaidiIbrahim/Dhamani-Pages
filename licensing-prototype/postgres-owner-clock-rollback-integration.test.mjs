import test from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes,randomUUID,createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {PostgresOwnerSessionRepository} from './postgres/owner-session-repository.mjs';
test('real PostgreSQL rejects backwards session timestamps without mutating activity or CSRF',async t=>{
 if(!process.env.DHAMANI_TEST_DATABASE_URL){t.skip('No temporary PostgreSQL test database configured');return;}
 const {default:pg}=await import('pg');const pool=new pg.Pool({connectionString:process.env.DHAMANI_TEST_DATABASE_URL,max:3});
 try{
  await pool.query(readFileSync(new URL('./postgres/003_owner_auth_proposal.sql',import.meta.url),'utf8'));
  const token=randomBytes(32).toString('base64url'),ownerId=randomUUID(),now=new Date(),future=new Date(now.getTime()+10000),past=new Date(now.getTime()+5000),hash=createHash('sha256').update(token).digest(),repo=new PostgresOwnerSessionRepository(pool);
  await pool.query('INSERT INTO owner_auth_sessions(session_hash,owner_id,mfa_verified,created_at,last_activity_at,expires_at) VALUES($1,$2,TRUE,$3,$4,$5)',[hash,ownerId,now,future,new Date(now.getTime()+30*60*1000)]);
  assert.equal(await repo.verify({token,now:past}),null);
  assert.equal(await repo.issueCsrf({token,now:past}),null);
  const validCsrf=await repo.issueCsrf({token,now:future});
  assert.equal(typeof validCsrf,'string');
  assert.equal(await repo.verifyCsrf({token,csrf:validCsrf,now:past}),false);
  assert.equal(await repo.revokeWithCsrf({token,csrf:validCsrf,now:past}),false);
  const state=await pool.query('SELECT last_activity_at,revoked_at FROM owner_auth_sessions WHERE session_hash=$1',[hash]);
  assert.equal(new Date(state.rows[0].last_activity_at).getTime(),future.getTime());
  assert.equal(state.rows[0].revoked_at,null);
  assert.deepEqual(await repo.verify({token,now:future}),{id:ownerId,role:'owner',active:true});
 }finally{await pool.end();}
});
