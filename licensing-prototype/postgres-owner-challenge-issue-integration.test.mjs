import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {PostgresOwnerChallengeRepository} from './postgres/owner-challenge-repository.mjs';
test('real PostgreSQL challenge issuance is capped under concurrent requests',async t=>{
 if(!process.env.DHAMANI_TEST_DATABASE_URL){t.skip('No temporary PostgreSQL test database configured');return;}
 const {default:pg}=await import('pg');const pool=new pg.Pool({connectionString:process.env.DHAMANI_TEST_DATABASE_URL,max:8});
 try{
  await pool.query(readFileSync(new URL('./postgres/003_owner_auth_proposal.sql',import.meta.url),'utf8'));
  const repo=new PostgresOwnerChallengeRepository(pool),ownerId=randomUUID();
  const issued=await Promise.all(Array.from({length:8},()=>repo.issue({ownerId,maxPending:3})));
  assert.equal(issued.filter(Boolean).length,3);
  assert.equal(new Set(issued.filter(Boolean)).size,3);
  const count=await pool.query('SELECT count(*)::int AS n FROM owner_auth_challenges WHERE owner_id=$1',[ownerId]);
  assert.equal(count.rows[0].n,3);
 }finally{await pool.end();}
});
test('real PostgreSQL MFA failures stop at five and prevent consumption',async t=>{
 if(!process.env.DHAMANI_TEST_DATABASE_URL){t.skip('No temporary PostgreSQL test database configured');return;}
 const {default:pg}=await import('pg');const pool=new pg.Pool({connectionString:process.env.DHAMANI_TEST_DATABASE_URL,max:6});
 try{
  await pool.query(readFileSync(new URL('./postgres/003_owner_auth_proposal.sql',import.meta.url),'utf8'));
  const repo=new PostgresOwnerChallengeRepository(pool),ownerId=randomUUID(),challenge=await repo.issue({ownerId});
  assert.equal(typeof challenge,'string');
  const results=await Promise.all(Array.from({length:10},()=>repo.recordFailure({challenge,ownerId})));
  assert.equal(results.filter(Boolean).length,5);
  const {createHash}=await import('node:crypto');
  const state=await pool.query('SELECT failed_attempts FROM owner_auth_challenges WHERE challenge_hash=$1',[createHash('sha256').update(challenge).digest()]);
  assert.equal(state.rows[0].failed_attempts,5);
  assert.equal(await repo.consume({challenge,ownerId}),false);
  assert.equal(await repo.recordFailure({challenge,ownerId}),false);
 }finally{await pool.end();}
});
