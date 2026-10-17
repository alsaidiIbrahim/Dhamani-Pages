import test from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes,randomUUID,createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {createPasswordVerifier} from './owner-login.mjs';
import {totpCode} from './owner-totp.mjs';
import {PostgresOwnerLoginService} from './postgres/owner-login-service.mjs';
test('real PostgreSQL login prototype requires password and MFA before issuing a session',async t=>{
 if(!process.env.DHAMANI_TEST_DATABASE_URL){t.skip('No temporary PostgreSQL test database configured');return;}
 const {default:pg}=await import('pg');const pool=new pg.Pool({connectionString:process.env.DHAMANI_TEST_DATABASE_URL,max:6});
 try{
  await pool.query(readFileSync(new URL('./postgres/003_owner_auth_proposal.sql',import.meta.url),'utf8'));
  const now=Date.now(),ownerId=randomUUID(),secret=randomBytes(32),password='Correct-Owner-Password-2026!',login=new PostgresOwnerLoginService({pool,ownerId,passwordRecord:createPasswordVerifier(password),totpSecret:secret,now:()=>now});
  assert.equal(await login.start({password:'wrong'}),null);
  assert.equal((await pool.query('SELECT count(*)::int AS n FROM owner_auth_challenges WHERE owner_id=$1',[ownerId])).rows[0].n,0);
  const challenge=await login.start({password});
  assert.equal(typeof challenge,'string');
  const code=totpCode(secret,Math.floor(now/30000));
  const session=await login.complete({challenge,code});
  assert.equal(typeof session,'string');
  assert.equal(await login.complete({challenge,code}),null);
  const found=await pool.query('SELECT mfa_verified FROM owner_auth_sessions WHERE session_hash=$1',[createHash('sha256').update(session).digest()]);
  assert.equal(found.rowCount,1);assert.equal(found.rows[0].mfa_verified,true);
 }finally{await pool.end();}
});
test('real PostgreSQL password login cannot exceed pending challenge cap under concurrency',async t=>{
 if(!process.env.DHAMANI_TEST_DATABASE_URL){t.skip('No temporary PostgreSQL test database configured');return;}
 const {default:pg}=await import('pg');const pool=new pg.Pool({connectionString:process.env.DHAMANI_TEST_DATABASE_URL,max:8});
 try{
  await pool.query(readFileSync(new URL('./postgres/003_owner_auth_proposal.sql',import.meta.url),'utf8'));
  const now=Date.now(),ownerId=randomUUID(),secret=randomBytes(32),password='Correct-Owner-Password-2026!',login=new PostgresOwnerLoginService({pool,ownerId,passwordRecord:createPasswordVerifier(password),totpSecret:secret,now:()=>now});
  const results=await Promise.all(Array.from({length:22},()=>login.start({password})));
  assert.equal(results.filter(Boolean).length,20);
 }finally{await pool.end();}
});
