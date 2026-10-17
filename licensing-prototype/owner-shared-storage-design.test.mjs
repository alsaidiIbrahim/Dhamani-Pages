import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
test('proposed shared owner-auth schema stores only hashed bearer credentials',async()=>{
 const sql=await readFile(new URL('./postgres/003_owner_auth_proposal.sql',import.meta.url),'utf8');
 assert.match(sql,/owner_auth_sessions/);
 assert.match(sql,/owner_auth_challenges/);
 assert.match(sql,/session_hash BYTEA PRIMARY KEY/);
 assert.match(sql,/challenge_hash BYTEA PRIMARY KEY/);
 assert.match(sql,/revoked_at TIMESTAMPTZ/);
 assert.match(sql,/failed_attempts SMALLINT/);
 assert.doesNotMatch(sql,/CREATE TABLE[^;]*raw_token/i);
});
test('dashboard audit column matches PostgreSQL repository action field',async()=>{
 const dashboard=await readFile(new URL('./owner-local/dashboard.js',import.meta.url),'utf8');
 const repo=await readFile(new URL('./postgres/repository.mjs',import.meta.url),'utf8');
 assert.match(dashboard,/events:\['action','created_at','license_id'\]/);
 assert.match(repo,/actor_id,action,created_at FROM license_events/);
});
