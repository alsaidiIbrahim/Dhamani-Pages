import test from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes,randomUUID,createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {ownerSessionAuthenticator} from './owner-session.mjs';
import {PostgresOwnerSessionRepository} from './postgres/owner-session-repository.mjs';
import {createPostgresOwnerSessionAdapter} from './postgres/owner-session-adapter.mjs';
test('real PostgreSQL session adapter supports cookie authentication, CSRF and atomic logout',async t=>{
 if(!process.env.DHAMANI_TEST_DATABASE_URL){t.skip('No temporary PostgreSQL test database configured');return;}
 const {default:pg}=await import('pg');const pool=new pg.Pool({connectionString:process.env.DHAMANI_TEST_DATABASE_URL,max:5});
 try{
  await pool.query(readFileSync(new URL('./postgres/003_owner_auth_proposal.sql',import.meta.url),'utf8'));
  const token=randomBytes(32).toString('base64url'),ownerId=randomUUID(),now=new Date(),hash=createHash('sha256').update(token).digest();
  await pool.query('INSERT INTO owner_auth_sessions(session_hash,owner_id,mfa_verified,created_at,last_activity_at,expires_at) VALUES($1,$2,TRUE,$3,$3,$4)',[hash,ownerId,new Date(now.getTime()-1000),new Date(now.getTime()+30*60*1000)]);
  const adapter=createPostgresOwnerSessionAdapter(new PostgresOwnerSessionRepository(pool));
  const auth=ownerSessionAuthenticator(adapter);
  assert.deepEqual(await auth({headers:{cookie:'dhamani_owner_session='+token}}),{id:ownerId,role:'owner',active:true});
  assert.ok((await adapter.expiresAt(token))>Date.now());
  const csrf=await adapter.issueCsrf(token);
  assert.equal(typeof csrf,'string');
  assert.equal(await adapter.verifyCsrf(token,csrf),true);
  assert.equal(await adapter.revokeWithCsrf(token,'invalid'),false);
  assert.equal(await adapter.revokeWithCsrf(token,csrf),true);
  assert.equal(await adapter.revokeWithCsrf(token,csrf),false);
  assert.equal(await adapter.verify(token),null);
  assert.equal(await adapter.expiresAt(token),null);
  assert.equal(await auth({headers:{cookie:'dhamani_owner_session='+token}}),null);
 }finally{await pool.end();}
});
