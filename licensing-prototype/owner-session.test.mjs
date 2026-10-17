import test from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
import {OwnerSessionStore,ownerSessionAuthenticator} from './owner-session.mjs';
import {createOwnerReadHandler} from './owner-api.mjs';
const token=()=>randomBytes(32).toString('base64url');
function res(){return {status:null,body:null,writeHead(status){this.status=status},end(body){this.body=JSON.parse(body)}}}
test('owner sessions require MFA and expire and revoke',()=>{
 let now=1000;
 const store=new OwnerSessionStore({now:()=>now});
 const noMfa=token(),valid=token();
 store.add({token:noMfa,ownerId:'owner',expiresAt:3000,mfaVerified:false});
 store.add({token:valid,ownerId:'owner',expiresAt:3000,mfaVerified:true});
 assert.equal(store.verify(noMfa),null);
 assert.equal(store.verify('wrong'),null);
 assert.equal(store.verify(valid).role,'owner');
 now=3000;assert.equal(store.verify(valid),null);
 now=1000;assert.equal(store.revoke(valid),true);
 assert.equal(store.verify(valid),null);
});
test('cookie authenticator rejects duplicates and malformed tokens',async()=>{
 const store=new OwnerSessionStore();
 const valid=token();store.add({token:valid,ownerId:'owner',expiresAt:Date.now()+60000,mfaVerified:true});
 const auth=ownerSessionAuthenticator(store);
 assert.equal((await auth({headers:{cookie:'dhamani_owner_session='+valid}})).role,'owner');
 assert.equal(await auth({headers:{cookie:'dhamani_owner_session='+valid+'; dhamani_owner_session='+valid}}),null);
 assert.equal(await auth({headers:{cookie:'dhamani_owner_session=invalid'}}),null);
});
test('owner read endpoint denies missing and non-MFA sessions',async()=>{
 const store=new OwnerSessionStore(),valid=token(),noMfa=token();
 store.add({token:valid,ownerId:'owner',expiresAt:Date.now()+60000,mfaVerified:true});
 store.add({token:noMfa,ownerId:'owner',expiresAt:Date.now()+60000,mfaVerified:false});
 let reads=0;
 const handler=createOwnerReadHandler({repository:{listOrders:async()=>{reads++;return []}},authenticateOwner:ownerSessionAuthenticator(store)});
 for(const value of [undefined,noMfa]){
  const response=res();await handler({method:'GET',url:'/owner/orders',headers:value?{cookie:'dhamani_owner_session='+value}:{}},response);
  assert.equal(response.status,403);
 }
 const response=res();await handler({method:'GET',url:'/owner/orders',headers:{cookie:'dhamani_owner_session='+valid}},response);
 assert.equal(response.status,200);assert.equal(reads,1);
});

test('session store caps lifetime and cleans revoked or expired sessions',()=>{
 let now=1000;
 const store=new OwnerSessionStore({now:()=>now,maxLifetimeMs:5000});
 const a=token(),b=token(),c=token();
 assert.throws(()=>store.add({token:a,ownerId:'owner',expiresAt:6001,mfaVerified:true}),/invalid_session/);
 store.add({token:a,ownerId:'owner',expiresAt:2000,mfaVerified:true});
 store.add({token:b,ownerId:'owner',expiresAt:5000,mfaVerified:true});
 store.add({token:c,ownerId:'owner',expiresAt:5000,mfaVerified:true});
 assert.equal(store.revoke(b),true);
 now=2000;
 assert.equal(store.cleanup(),2);
 assert.equal(store.sessions.size,1);
 assert.equal(store.verify(a),null);
 assert.equal(store.verify(b),null);
 assert.equal(store.verify(c).role,'owner');
});
