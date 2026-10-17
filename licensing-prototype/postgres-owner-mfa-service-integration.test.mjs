import test from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes,randomUUID,createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {totpCode} from './owner-totp.mjs';
import {PostgresOwnerMfaService} from './postgres/owner-mfa-service.mjs';
test('real PostgreSQL owner MFA service cryptographically validates code and atomically issues one session',async t=>{
 if(!process.env.DHAMANI_TEST_DATABASE_URL){t.skip('No temporary PostgreSQL test database configured');return;}
 const {default:pg}=await import('pg');
 const pool=new pg.Pool({connectionString:process.env.DHAMANI_TEST_DATABASE_URL,max:5});
 try{
  await pool.query(readFileSync(new URL('./postgres/003_owner_auth_proposal.sql',import.meta.url),'utf8'));
  const now=Date.now(),ownerId=randomUUID(),secret=randomBytes(32),step=Math.floor(now/30000);
  const service=new PostgresOwnerMfaService({pool,ownerId,totpSecret:secret,now:()=>now});
  const create=async()=>{const challenge=randomBytes(32).toString('base64url');await pool.query("INSERT INTO owner_auth_challenges(challenge_hash,owner_id,expires_at) VALUES($1,$2,now()+interval '5 minutes')",[createHash('sha256').update(challenge).digest(),ownerId]);return challenge;};
  const challenge=await create();
  assert.equal(await service.complete({challenge,code:'not-a-code'}),null);
  const code=totpCode(secret,step);
  const results=await Promise.all(Array.from({length:4},()=>service.complete({challenge,code})));
  const issued=results.filter(x=>typeof x==='string');
  assert.equal(issued.length,1);
  const sessionHash=createHash('sha256').update(issued[0]).digest();
  const session=await pool.query('SELECT mfa_verified FROM owner_auth_sessions WHERE session_hash=$1',[sessionHash]);
  assert.equal(session.rowCount,1);assert.equal(session.rows[0].mfa_verified,true);
  const nextChallenge=await create();
  assert.equal(await service.complete({challenge:nextChallenge,code}),null);
  const state=await pool.query('SELECT consumed_at FROM owner_auth_challenges WHERE challenge_hash=$1',[createHash('sha256').update(nextChallenge).digest()]);
  assert.equal(state.rows[0].consumed_at,null);
 }finally{await pool.end();}
});
