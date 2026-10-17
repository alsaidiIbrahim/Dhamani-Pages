import test from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes,randomUUID,createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {PostgresOwnerSessionRepository} from './postgres/owner-session-repository.mjs';
test('real PostgreSQL effective expiry is bounded by idle and absolute session limits',async t=>{
 if(!process.env.DHAMANI_TEST_DATABASE_URL){t.skip('No temporary PostgreSQL test database configured');return;}
 const {default:pg}=await import('pg');const pool=new pg.Pool({connectionString:process.env.DHAMANI_TEST_DATABASE_URL,max:3});
 try{
  await pool.query(readFileSync(new URL('./postgres/003_owner_auth_proposal.sql',import.meta.url),'utf8'));
  const now=new Date(),repo=new PostgresOwnerSessionRepository(pool,{maxIdleMs:60000});
  const add=async(expiresOffset)=>{
   const token=randomBytes(32).toString('base64url'),hash=createHash('sha256').update(token).digest();
   await pool.query('INSERT INTO owner_auth_sessions(session_hash,owner_id,mfa_verified,created_at,last_activity_at,expires_at) VALUES($1,$2,TRUE,$3,$3,$4)',[hash,randomUUID(),now,new Date(now.getTime()+expiresOffset)]);
   return token;
  };
  const idleBound=await add(30*60*1000);
  assert.equal(await repo.expiresAt({token:idleBound,now}),now.getTime()+60000);
  assert.deepEqual(await repo.verify({token:idleBound,now:new Date(now.getTime()+1000)}).then(x=>x?.role),'owner');
  assert.equal(await repo.expiresAt({token:idleBound,now:new Date(now.getTime()+1000)}),now.getTime()+61000);
  const absoluteBound=await add(30000);
  assert.equal(await repo.expiresAt({token:absoluteBound,now}),now.getTime()+30000);
  assert.equal(await repo.expiresAt({token:absoluteBound,now:new Date(now.getTime()+30000)}),null);
  assert.equal(await repo.expiresAt({token:idleBound,now:new Date(now.getTime()+62000)}),null);
  assert.equal(await repo.expiresAt({token:idleBound,now:new Date(now.getTime()-1000)}),null);
 }finally{await pool.end();}
});
