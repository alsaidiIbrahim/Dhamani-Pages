import test from 'node:test';
import assert from 'node:assert/strict';
import {PostgresOwnerChallengeRepository} from './postgres/owner-challenge-repository.mjs';
const challenge='A'.repeat(43);
function fakePool({expiresAt=new Date('2030-01-01'),failedAttempts=0,consumedAt=null,ownerId='owner'}={}){
 const statements=[];let released=false;let consumed=consumedAt;
 const client={async query(sql,args=[]){
  statements.push(sql);
  if(sql==='BEGIN'||sql==='COMMIT'||sql==='ROLLBACK')return {rowCount:0,rows:[]};
  if(sql.includes('FOR UPDATE'))return {rowCount:1,rows:[{owner_id:ownerId,expires_at:expiresAt,failed_attempts:failedAttempts,consumed_at:consumed}]};
  if(sql.includes('SET consumed_at=')){if(consumed!==null)return {rowCount:0,rows:[]};consumed=args[1];return {rowCount:1,rows:[{challenge_hash:args[0]}]};}
  throw Error('unexpected_sql');
 },release(){released=true;}};
 return {pool:{connect:async()=>client},statements,get released(){return released}};
}
test('shared challenge consumption uses row lock, hashed challenge and one transaction',async()=>{
 const db=fakePool(),repo=new PostgresOwnerChallengeRepository(db.pool);
 assert.equal(await repo.consume({challenge,ownerId:'owner',now:new Date('2026-01-01')}),true);
 assert.deepEqual(db.statements.map(s=>s.split(' ')[0]),['BEGIN','SELECT','UPDATE','COMMIT']);
 assert.match(db.statements[1],/FOR UPDATE/);
 assert.equal(db.released,true);
 assert.equal(await repo.consume({challenge,ownerId:'owner',now:new Date('2026-01-01')}),false);
});
test('expired, exhausted, consumed and wrong-owner challenges fail closed',async()=>{
 for(const config of [{expiresAt:new Date('2020-01-01')},{failedAttempts:5},{consumedAt:new Date('2025-01-01')},{ownerId:'other'}]){
  const db=fakePool(config),repo=new PostgresOwnerChallengeRepository(db.pool);
  assert.equal(await repo.consume({challenge,ownerId:'owner',now:new Date('2026-01-01')}),false);
  assert.deepEqual(db.statements.map(s=>s.split(' ')[0]),['BEGIN','SELECT','ROLLBACK']);
  assert.equal(db.released,true);
 }
});
test('rejects malformed challenge before opening a transaction',async()=>{
 const db=fakePool(),repo=new PostgresOwnerChallengeRepository(db.pool);
 await assert.rejects(repo.consume({challenge:'short',ownerId:'owner'}),/invalid_challenge_input/);
 assert.equal(db.statements.length,0);
});
