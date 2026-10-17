import test from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes,randomUUID,createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {PostgresOwnerSessionRepository} from './postgres/owner-session-repository.mjs';
test('real PostgreSQL verifies and revokes owner sessions',async t=>{
 if(!process.env.DHAMANI_TEST_DATABASE_URL){t.skip('No temporary PostgreSQL test database configured');return;}
 const {default:pg}=await import('pg');
 const pool=new pg.Pool({connectionString:process.env.DHAMANI_TEST_DATABASE_URL,max:3});
 try{
  await pool.query(readFileSync(new URL('./postgres/003_owner_auth_proposal.sql',import.meta.url),'utf8'));
  const token=randomBytes(32).toString('base64url'),ownerId=randomUUID(),now=new Date();
  await pool.query("INSERT INTO owner_auth_sessions(session_hash,owner_id,mfa_verified,created_at,last_activity_at,expires_at) VALUES($1,$2,TRUE,$3,$3,$4)",[createHash('sha256').update(token).digest(),ownerId,now,new Date(now.getTime()+30*60*1000)]);
  const repo=new PostgresOwnerSessionRepository(pool);
  assert.deepEqual(await repo.verify({token,now:new Date(now.getTime()+1000)}),{id:ownerId,role:'owner',active:true});
  assert.equal(await repo.revoke({token,now:new Date(now.getTime()+2000)}),true);
  assert.equal(await repo.verify({token,now:new Date(now.getTime()+3000)}),null);
  assert.equal(await repo.revoke({token,now:new Date(now.getTime()+4000)}),false);
 }finally{await pool.end();}
});
test('real PostgreSQL refuses expired, idle and MFA-unverified sessions',async t=>{
 if(!process.env.DHAMANI_TEST_DATABASE_URL){t.skip('No temporary PostgreSQL test database configured');return;}
 const {default:pg}=await import('pg');
 const pool=new pg.Pool({connectionString:process.env.DHAMANI_TEST_DATABASE_URL,max:3});
 try{
  await pool.query(readFileSync(new URL('./postgres/003_owner_auth_proposal.sql',import.meta.url),'utf8'));
  const repo=new PostgresOwnerSessionRepository(pool,{maxIdleMs:60_000}),now=new Date();
  for(const kind of ['expired','idle','unverified']){
   const token=randomBytes(32).toString('base64url'),created=new Date(now.getTime()-20*60*1000);
   const lastActivity=kind==='idle'?new Date(now.getTime()-120_000):new Date(now.getTime()-10_000);
   const expires=kind==='expired'?new Date(now.getTime()-1000):new Date(now.getTime()+60_000);
   await pool.query('INSERT INTO owner_auth_sessions(session_hash,owner_id,mfa_verified,created_at,last_activity_at,expires_at) VALUES($1,$2,$3,$4,$5,$6)',[createHash('sha256').update(token).digest(),randomUUID(),kind!=='unverified',created,lastActivity,expires]);
   assert.equal(await repo.verify({token,now}),null,kind);
  }
 }finally{await pool.end();}
});
