import test from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes,randomUUID,createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {PostgresOwnerSessionRepository} from './postgres/owner-session-repository.mjs';
test('real PostgreSQL atomic CSRF logout rejects wrong token and permits one concurrent logout',async t=>{
 if(!process.env.DHAMANI_TEST_DATABASE_URL){t.skip('No temporary PostgreSQL test database configured');return;}
 const {default:pg}=await import('pg');
 const pool=new pg.Pool({connectionString:process.env.DHAMANI_TEST_DATABASE_URL,max:6});
 try{
  await pool.query(readFileSync(new URL('./postgres/003_owner_auth_proposal.sql',import.meta.url),'utf8'));
  const token=randomBytes(32).toString('base64url'),now=new Date(),repo=new PostgresOwnerSessionRepository(pool);
  await pool.query("INSERT INTO owner_auth_sessions(session_hash,owner_id,mfa_verified,created_at,last_activity_at,expires_at) VALUES($1,$2,TRUE,$3,$3,$4)",[createHash('sha256').update(token).digest(),randomUUID(),now,new Date(now.getTime()+30*60*1000)]);
  const csrf=await repo.issueCsrf({token,now});
  assert.equal(await repo.revokeWithCsrf({token,csrf:randomBytes(32).toString('base64url'),now}),false);
  assert.notEqual(await repo.verify({token,now}),null);
  const attempts=await Promise.all(Array.from({length:5},()=>repo.revokeWithCsrf({token,csrf,now})));
  assert.equal(attempts.filter(Boolean).length,1);
  assert.equal(await repo.verify({token,now}),null);
  assert.equal(await repo.verifyCsrf({token,csrf,now}),false);
 }finally{await pool.end();}
});
test('real PostgreSQL atomic logout refuses expired, idle and unverified sessions',async t=>{
 if(!process.env.DHAMANI_TEST_DATABASE_URL){t.skip('No temporary PostgreSQL test database configured');return;}
 const {default:pg}=await import('pg');
 const pool=new pg.Pool({connectionString:process.env.DHAMANI_TEST_DATABASE_URL,max:3});
 try{
  await pool.query(readFileSync(new URL('./postgres/003_owner_auth_proposal.sql',import.meta.url),'utf8'));
  const repo=new PostgresOwnerSessionRepository(pool,{maxIdleMs:60_000}),now=new Date();
  for(const kind of ['expired','idle','unverified']){
   const token=randomBytes(32).toString('base64url'),csrf=randomBytes(32).toString('base64url'),created=new Date(now.getTime()-20*60*1000),lastActivity=kind==='idle'?new Date(now.getTime()-120_000):new Date(now.getTime()-10_000),expires=kind==='expired'?new Date(now.getTime()-1000):new Date(now.getTime()+60_000);
   await pool.query('INSERT INTO owner_auth_sessions(session_hash,owner_id,mfa_verified,created_at,last_activity_at,expires_at,csrf_hash) VALUES($1,$2,$3,$4,$5,$6,$7)',[createHash('sha256').update(token).digest(),randomUUID(),kind!=='unverified',created,lastActivity,expires,createHash('sha256').update(csrf).digest()]);
   assert.equal(await repo.revokeWithCsrf({token,csrf,now}),false,kind);
  }
 }finally{await pool.end();}
});
