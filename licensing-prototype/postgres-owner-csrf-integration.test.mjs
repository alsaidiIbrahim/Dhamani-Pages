import test from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes,randomUUID,createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {PostgresOwnerSessionRepository} from './postgres/owner-session-repository.mjs';
test('real PostgreSQL owner CSRF rotation invalidates previous token and revocation invalidates all',async t=>{
 if(!process.env.DHAMANI_TEST_DATABASE_URL){t.skip('No temporary PostgreSQL test database configured');return;}
 const {default:pg}=await import('pg');
 const pool=new pg.Pool({connectionString:process.env.DHAMANI_TEST_DATABASE_URL,max:3});
 try{
  await pool.query(readFileSync(new URL('./postgres/003_owner_auth_proposal.sql',import.meta.url),'utf8'));
  const token=randomBytes(32).toString('base64url'),ownerId=randomUUID(),now=new Date(),repo=new PostgresOwnerSessionRepository(pool);
  await pool.query("INSERT INTO owner_auth_sessions(session_hash,owner_id,mfa_verified,created_at,last_activity_at,expires_at) VALUES($1,$2,TRUE,$3,$3,$4)",[createHash('sha256').update(token).digest(),ownerId,now,new Date(now.getTime()+30*60*1000)]);
  const first=await repo.issueCsrf({token,now});
  assert.equal(typeof first,'string');
  assert.equal(await repo.verifyCsrf({token,csrf:first,now}),true);
  const second=await repo.issueCsrf({token,now});
  assert.notEqual(first,second);
  assert.equal(await repo.verifyCsrf({token,csrf:first,now}),false);
  assert.equal(await repo.verifyCsrf({token,csrf:second,now}),true);
  assert.equal(await repo.revoke({token,now}),true);
  assert.equal(await repo.verifyCsrf({token,csrf:second,now}),false);
  assert.equal(await repo.issueCsrf({token,now}),null);
 }finally{await pool.end();}
});
test('real PostgreSQL rejects CSRF issuance for expired and idle owner sessions',async t=>{
 if(!process.env.DHAMANI_TEST_DATABASE_URL){t.skip('No temporary PostgreSQL test database configured');return;}
 const {default:pg}=await import('pg');
 const pool=new pg.Pool({connectionString:process.env.DHAMANI_TEST_DATABASE_URL,max:3});
 try{
  await pool.query(readFileSync(new URL('./postgres/003_owner_auth_proposal.sql',import.meta.url),'utf8'));
  const repo=new PostgresOwnerSessionRepository(pool,{maxIdleMs:60_000}),now=new Date();
  for(const kind of ['expired','idle']){
   const token=randomBytes(32).toString('base64url'),created=new Date(now.getTime()-20*60*1000),lastActivity=kind==='idle'?new Date(now.getTime()-120_000):new Date(now.getTime()-10_000),expires=kind==='expired'?new Date(now.getTime()-1000):new Date(now.getTime()+60_000);
   await pool.query('INSERT INTO owner_auth_sessions(session_hash,owner_id,mfa_verified,created_at,last_activity_at,expires_at) VALUES($1,$2,TRUE,$3,$4,$5)',[createHash('sha256').update(token).digest(),randomUUID(),created,lastActivity,expires]);
   assert.equal(await repo.issueCsrf({token,now}),null,kind);
  }
 }finally{await pool.end();}
});
