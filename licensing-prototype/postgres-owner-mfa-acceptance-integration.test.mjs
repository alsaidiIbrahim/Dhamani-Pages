import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID,randomBytes,createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {PostgresOwnerMfaAcceptance} from './postgres/owner-mfa-acceptance.mjs';
test('real PostgreSQL MFA transaction accepts only one concurrent challenge and TOTP step',async t=>{
 if(!process.env.DHAMANI_TEST_DATABASE_URL){t.skip('No temporary PostgreSQL test database configured');return;}
 const {default:pg}=await import('pg');
 const pool=new pg.Pool({connectionString:process.env.DHAMANI_TEST_DATABASE_URL,max:5});
 try{
  await pool.query(readFileSync(new URL('./postgres/003_owner_auth_proposal.sql',import.meta.url),'utf8'));
  const ownerId=randomUUID(),challenge=randomBytes(32).toString('base64url'),digest=createHash('sha256').update(challenge).digest();
  await pool.query("INSERT INTO owner_auth_challenges(challenge_hash,owner_id,expires_at) VALUES($1,$2,now()+interval '5 minutes')",[digest,ownerId]);
  const repo=new PostgresOwnerMfaAcceptance(pool);
  const results=await Promise.all(Array.from({length:5},()=>repo.accept({challenge,ownerId,totpStep:1000})));
  assert.equal(results.filter(Boolean).length,1);
  const replay=await pool.query('SELECT last_accepted_step FROM owner_auth_totp_replay WHERE owner_id=$1',[ownerId]);
  assert.equal(Number(replay.rows[0].last_accepted_step),1000);
  const consumed=await pool.query('SELECT consumed_at FROM owner_auth_challenges WHERE challenge_hash=$1',[digest]);
  assert.notEqual(consumed.rows[0].consumed_at,null);
 }finally{await pool.end();}
});
test('real PostgreSQL MFA replay denial rolls back challenge consumption',async t=>{
 if(!process.env.DHAMANI_TEST_DATABASE_URL){t.skip('No temporary PostgreSQL test database configured');return;}
 const {default:pg}=await import('pg');
 const pool=new pg.Pool({connectionString:process.env.DHAMANI_TEST_DATABASE_URL,max:3});
 try{
  await pool.query(readFileSync(new URL('./postgres/003_owner_auth_proposal.sql',import.meta.url),'utf8'));
  const ownerId=randomUUID(),repo=new PostgresOwnerMfaAcceptance(pool);
  const create=async()=>{
   const challenge=randomBytes(32).toString('base64url'),digest=createHash('sha256').update(challenge).digest();
   await pool.query("INSERT INTO owner_auth_challenges(challenge_hash,owner_id,expires_at) VALUES($1,$2,now()+interval '5 minutes')",[digest,ownerId]);
   return {challenge,digest};
  };
  const first=await create();
  assert.equal(await repo.accept({challenge:first.challenge,ownerId,totpStep:500}),true);
  const second=await create();
  assert.equal(await repo.accept({challenge:second.challenge,ownerId,totpStep:500}),false);
  const state=await pool.query('SELECT consumed_at FROM owner_auth_challenges WHERE challenge_hash=$1',[second.digest]);
  assert.equal(state.rows[0].consumed_at,null);
  assert.equal(await repo.accept({challenge:second.challenge,ownerId,totpStep:501}),true);
 }finally{await pool.end();}
});
