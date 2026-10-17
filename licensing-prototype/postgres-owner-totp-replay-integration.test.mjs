import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {PostgresTotpReplayGuard} from './postgres/owner-totp-replay.mjs';
test('real PostgreSQL accepts each owner TOTP step once under concurrent calls',async t=>{
 if(!process.env.DHAMANI_TEST_DATABASE_URL){t.skip('No temporary PostgreSQL test database configured');return;}
 const {default:pg}=await import('pg');
 const pool=new pg.Pool({connectionString:process.env.DHAMANI_TEST_DATABASE_URL,max:4});
 try{
  await pool.query(readFileSync(new URL('./postgres/003_owner_auth_proposal.sql',import.meta.url),'utf8'));
  const guard=new PostgresTotpReplayGuard(pool),ownerId=randomUUID();
  const attempts=await Promise.all(Array.from({length:8},()=>guard.accept({ownerId,step:12345})));
  assert.equal(attempts.filter(Boolean).length,1);
  assert.equal(await guard.accept({ownerId,step:12344}),false);
  assert.equal(await guard.accept({ownerId,step:12346}),true);
  const result=await pool.query('SELECT last_accepted_step FROM owner_auth_totp_replay WHERE owner_id=$1',[ownerId]);
  assert.equal(Number(result.rows[0].last_accepted_step),12346);
 }finally{await pool.end();}
});
