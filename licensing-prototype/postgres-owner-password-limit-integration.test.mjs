import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID,randomBytes} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {createPasswordVerifier} from './owner-login.mjs';
import {PostgresOwnerLoginService} from './postgres/owner-login-service.mjs';
test('real PostgreSQL shares owner password lockout across independent service instances',async t=>{
 if(!process.env.DHAMANI_TEST_DATABASE_URL){t.skip('No temporary PostgreSQL test database configured');return;}
 const {default:pg}=await import('pg');const pool=new pg.Pool({connectionString:process.env.DHAMANI_TEST_DATABASE_URL,max:8});
 try{
  await pool.query(readFileSync(new URL('./postgres/003_owner_auth_proposal.sql',import.meta.url),'utf8'));
  let now=Date.now();const ownerId=randomUUID(),password='Strong-Owner-Password-2026!',passwordRecord=createPasswordVerifier(password),totpSecret=randomBytes(32);
  const a=new PostgresOwnerLoginService({pool,ownerId,passwordRecord,totpSecret,now:()=>now});
  const b=new PostgresOwnerLoginService({pool,ownerId,passwordRecord,totpSecret,now:()=>now});
  const wrong=await Promise.all(Array.from({length:5},(_,i)=>(i%2?a:b).start({password:'wrong'})));
  assert.ok(wrong.every(x=>x===null));
  assert.equal(await b.start({password}),null,'correct password cannot bypass lockout');
  const state=await pool.query('SELECT failed_attempts,locked_until FROM owner_auth_password_limits WHERE owner_id=$1',[ownerId]);
  assert.equal(state.rows[0].failed_attempts,5);
  assert.ok(new Date(state.rows[0].locked_until).getTime()>now);
  now+=15*60*1000+1000;
  assert.equal(typeof await a.start({password}),'string','correct password works after lockout');
  const reset=await pool.query('SELECT failed_attempts,locked_until FROM owner_auth_password_limits WHERE owner_id=$1',[ownerId]);
  assert.equal(reset.rows[0].failed_attempts,0);assert.equal(reset.rows[0].locked_until,null);
 }finally{await pool.end();}
});
