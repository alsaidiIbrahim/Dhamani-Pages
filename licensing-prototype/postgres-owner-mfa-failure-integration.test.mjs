import test from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes,randomUUID,createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {totpCode} from './owner-totp.mjs';
import {PostgresOwnerMfaService} from './postgres/owner-mfa-service.mjs';
test('real PostgreSQL locks MFA challenge after five invalid TOTP codes',async t=>{
 if(!process.env.DHAMANI_TEST_DATABASE_URL){t.skip('No temporary PostgreSQL test database configured');return;}
 const {default:pg}=await import('pg');const pool=new pg.Pool({connectionString:process.env.DHAMANI_TEST_DATABASE_URL,max:5});
 try{
  await pool.query(readFileSync(new URL('./postgres/003_owner_auth_proposal.sql',import.meta.url),'utf8'));
  const now=Date.now(),ownerId=randomUUID(),secret=randomBytes(32),service=new PostgresOwnerMfaService({pool,ownerId,totpSecret:secret,now:()=>now});
  const challenge=await service.challenges.issue({ownerId,now:new Date(now)});
  const valid=totpCode(secret,Math.floor(now/30000)),invalid=valid==='000000'?'999999':'000000';
  for(let i=0;i<5;i++)assert.equal(await service.complete({challenge,code:invalid}),null);
  const state=await pool.query('SELECT failed_attempts,consumed_at FROM owner_auth_challenges WHERE challenge_hash=$1',[createHash('sha256').update(challenge).digest()]);
  assert.equal(state.rows[0].failed_attempts,5);
  assert.equal(state.rows[0].consumed_at,null);
  assert.equal(await service.complete({challenge,code:valid}),null);
  assert.equal((await pool.query('SELECT count(*)::int AS n FROM owner_auth_sessions WHERE owner_id=$1',[ownerId])).rows[0].n,0);
 }finally{await pool.end();}
});
test('real PostgreSQL issues one session after invalid attempts below limit',async t=>{
 if(!process.env.DHAMANI_TEST_DATABASE_URL){t.skip('No temporary PostgreSQL test database configured');return;}
 const {default:pg}=await import('pg');const pool=new pg.Pool({connectionString:process.env.DHAMANI_TEST_DATABASE_URL,max:5});
 try{
  await pool.query(readFileSync(new URL('./postgres/003_owner_auth_proposal.sql',import.meta.url),'utf8'));
  const now=Date.now(),ownerId=randomUUID(),secret=randomBytes(32),service=new PostgresOwnerMfaService({pool,ownerId,totpSecret:secret,now:()=>now});
  const challenge=await service.challenges.issue({ownerId,now:new Date(now)});
  const valid=totpCode(secret,Math.floor(now/30000)),invalid=valid==='000000'?'999999':'000000';
  assert.equal(await service.complete({challenge,code:invalid}),null);
  const token=await service.complete({challenge,code:valid});
  assert.equal(typeof token,'string');
  assert.equal(await service.complete({challenge,code:valid}),null);
  const row=await pool.query('SELECT failed_attempts,consumed_at FROM owner_auth_challenges WHERE challenge_hash=$1',[createHash('sha256').update(challenge).digest()]);
  assert.equal(row.rows[0].failed_attempts,1);
  assert.notEqual(row.rows[0].consumed_at,null);
 }finally{await pool.end();}
});
