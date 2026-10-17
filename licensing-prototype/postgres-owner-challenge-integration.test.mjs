import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,randomBytes} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {PostgresOwnerChallengeRepository} from './postgres/owner-challenge-repository.mjs';
test('real PostgreSQL accepts one of two concurrent MFA challenge consumers',async t=>{
 if(!process.env.DHAMANI_TEST_DATABASE_URL){t.skip('No temporary PostgreSQL test database configured');return;}
 const {default:pg}=await import('pg');
 const pool=new pg.Pool({connectionString:process.env.DHAMANI_TEST_DATABASE_URL,max:4});
 const challenge=randomBytes(32).toString('base64url'),ownerId='owner-test';
 const digest=createHash('sha256').update(challenge).digest();
 try{
  await pool.query(readFileSync(new URL('./postgres/003_owner_auth_proposal.sql',import.meta.url),'utf8'));
  await pool.query("INSERT INTO owner_auth_challenges(challenge_hash,owner_id,expires_at) VALUES($1,$2,now()+interval '5 minutes')",[digest,ownerId]);
  const repo=new PostgresOwnerChallengeRepository(pool);
  const results=await Promise.all([repo.consume({challenge,ownerId}),repo.consume({challenge,ownerId})]);
  assert.deepEqual(results.sort(),[false,true]);
  const row=await pool.query('SELECT consumed_at,failed_attempts FROM owner_auth_challenges WHERE challenge_hash=$1',[digest]);
  assert.notEqual(row.rows[0].consumed_at,null);
  assert.equal(row.rows[0].failed_attempts,0);
  assert.equal(await repo.consume({challenge,ownerId}),false);
 }finally{await pool.end();}
});
test('real PostgreSQL rejects expired, exhausted and wrong-owner MFA challenges',async t=>{
 if(!process.env.DHAMANI_TEST_DATABASE_URL){t.skip('No temporary PostgreSQL test database configured');return;}
 const {default:pg}=await import('pg');
 const pool=new pg.Pool({connectionString:process.env.DHAMANI_TEST_DATABASE_URL,max:2});
 try{
  await pool.query(readFileSync(new URL('./postgres/003_owner_auth_proposal.sql',import.meta.url),'utf8'));
  const repo=new PostgresOwnerChallengeRepository(pool);
  for(const config of [{expiry:"now()-interval '1 minute'",attempts:0,owner:'owner-test'},{expiry:"now()+interval '5 minutes'",attempts:5,owner:'owner-test'},{expiry:"now()+interval '5 minutes'",attempts:0,owner:'different-owner'}]){
   const challenge=randomBytes(32).toString('base64url'),digest=createHash('sha256').update(challenge).digest();
   await pool.query('INSERT INTO owner_auth_challenges(challenge_hash,owner_id,expires_at,failed_attempts) VALUES($1,$2,'+config.expiry+',$3)',[digest,config.owner,config.attempts]);
   assert.equal(await repo.consume({challenge,ownerId:'owner-test'}),false);
  }
 }finally{await pool.end();}
});
