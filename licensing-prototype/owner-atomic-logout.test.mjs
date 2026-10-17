import test from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
import {OwnerSessionStore} from './owner-session.mjs';
test('local CSRF logout accepts only current token and revokes once',()=>{
 const now=Date.now(),store=new OwnerSessionStore({now:()=>now,maxLifetimeMs:1800000});
 const token=randomBytes(32).toString('base64url');
 store.add({token,ownerId:'owner',expiresAt:now+600000,mfaVerified:true});
 const old=store.issueCsrf(token),current=store.issueCsrf(token);
 assert.equal(store.revokeWithCsrf(token,old),false);
 assert.notEqual(store.verify(token),null);
 assert.equal(store.revokeWithCsrf(token,current),true);
 assert.equal(store.revokeWithCsrf(token,current),false);
 assert.equal(store.verify(token),null);
});
test('local CSRF logout refuses idle and expired sessions',()=>{
 let now=Date.now(),store=new OwnerSessionStore({now:()=>now,maxLifetimeMs:1800000,maxIdleMs:60000});
 const token=randomBytes(32).toString('base64url');
 store.add({token,ownerId:'owner',expiresAt:now+600000,mfaVerified:true});
 const csrf=store.issueCsrf(token);now+=60001;
 assert.equal(store.revokeWithCsrf(token,csrf),false);
});
