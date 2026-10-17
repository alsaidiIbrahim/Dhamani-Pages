import test from 'node:test';
import assert from 'node:assert/strict';
import {OwnerSessionStore} from './owner-session.mjs';
test('server revokes access after idle deadline even if browser remains open',()=>{
 let now=1000;
 const store=new OwnerSessionStore({now:()=>now,maxIdleMs:2000,maxLifetimeMs:10000});
 const token='A'.repeat(43);
 store.add({token,ownerId:'demo',expiresAt:9000,mfaVerified:true});
 assert.equal(store.expiresAt(token),3000);
 now=2500;
 assert.equal(store.verify(token).role,'owner');
 assert.equal(store.expiresAt(token),4500);
 now=4500;
 assert.equal(store.verify(token),null);
 assert.equal(store.expiresAt(token),null);
 assert.equal(store.issueCsrf(token),null);
});
test('invalid idle configuration rejected',()=>{
 assert.throws(()=>new OwnerSessionStore({maxIdleMs:0}),/invalid_idle_lifetime/);
 assert.throws(()=>new OwnerSessionStore({maxIdleMs:9000,maxLifetimeMs:8000}),/invalid_idle_lifetime/);
});
