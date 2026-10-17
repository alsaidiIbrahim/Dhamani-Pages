import test from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes,randomUUID,createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {PostgresOwnerMfaAcceptance} from './postgres/owner-mfa-acceptance.mjs';
test('real PostgreSQL commits MFA challenge, replay step and hashed session together',async t=>{
 if(!process.env.DHAMANI_TEST_DATABASE_URL){t.skip('No temporary PostgreSQL test database configured');return;}
 const {default:pg}=await import('pg');
 const pool=new pg.Pool({connectionString:process.env.DHAMANI_TEST_DATABASE_URL,max:3});
 try{
  await pool.query(readFileSync(new URL('./postgres/003_owner_auth_proposal.sql',import.meta.url),'utf8'));
  const ownerId=randomUUID(),challenge=randomBytes(32).toString('base64url'),sessionToken=randomBytes(32).toString('base64url');
  const challengeHash=createHash('sha256').update(challenge).digest(),sessionHash=createHash('sha256').update(sessionToken).digest();
  await pool.query("INSERT INTO owner_auth_challenges(challenge_hash,owner_id,expires_at) VALUES($1,$2,now()+interval '5 minutes')",[challengeHash,ownerId]);
  const result=await new PostgresOwnerMfaAcceptance(pool).accept({challenge,ownerId,totpStep:100,sessionToken,sessionExpiresAt:new Date(Date.now()+20*60*1000)});
  assert.equal(result,true);
  const sessions=await pool.query('SELECT mfa_verified FROM owner_auth_sessions WHERE session_hash=$1',[sessionHash]);
  assert.equal(sessions.rowCount,1);assert.equal(sessions.rows[0].mfa_verified,true);
  assert.equal(await new PostgresOwnerMfaAcceptance(pool).accept({challenge,ownerId,totpStep:101,sessionToken:randomBytes(32).toString('base64url'),sessionExpiresAt:new Date(Date.now()+20*60*1000)}),false);
 }finally{await pool.end();}
});
test('real PostgreSQL rolls back MFA consumption and replay on session hash collision',async t=>{
 if(!process.env.DHAMANI_TEST_DATABASE_URL){t.skip('No temporary PostgreSQL test database configured');return;}
 const {default:pg}=await import('pg');
 const pool=new pg.Pool({connectionString:process.env.DHAMANI_TEST_DATABASE_URL,max:3});
 try{
  await pool.query(readFileSync(new URL('./postgres/003_owner_auth_proposal.sql',import.meta.url),'utf8'));
  const ownerId=randomUUID(),challenge=randomBytes(32).toString('base64url'),sessionToken=randomBytes(32).toString('base64url');
  const challengeHash=createHash('sha256').update(challenge).digest(),sessionHash=createHash('sha256').update(sessionToken).digest();
  await pool.query("INSERT INTO owner_auth_challenges(challenge_hash,owner_id,expires_at) VALUES($1,$2,now()+interval '5 minutes')",[challengeHash,ownerId]);
  await pool.query("INSERT INTO owner_auth_sessions(session_hash,owner_id,mfa_verified,expires_at) VALUES($1,$2,TRUE,now()+interval '20 minutes')",[sessionHash,ownerId]);
  await assert.rejects(new PostgresOwnerMfaAcceptance(pool).accept({challenge,ownerId,totpStep:200,sessionToken,sessionExpiresAt:new Date(Date.now()+20*60*1000)}),/duplicate key/);
  const challengeRow=await pool.query('SELECT consumed_at FROM owner_auth_challenges WHERE challenge_hash=$1',[challengeHash]);
  const replay=await pool.query('SELECT last_accepted_step FROM owner_auth_totp_replay WHERE owner_id=$1',[ownerId]);
  assert.equal(challengeRow.rows[0].consumed_at,null);
  assert.equal(replay.rowCount,0);
 }finally{await pool.end();}
});
