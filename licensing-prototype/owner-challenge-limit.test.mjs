import test from 'node:test';
import assert from 'node:assert/strict';
import {OwnerLoginPrototype,createPasswordVerifier} from './owner-login.mjs';
import {OwnerSessionStore} from './owner-session.mjs';
import {OwnerTotpVerifier} from './owner-totp.mjs';
test('pending owner MFA challenges are bounded and freed after expiry',()=>{
 let clock=90_000;const now=()=>clock;
 const login=new OwnerLoginPrototype({ownerId:'demo',passwordRecord:createPasswordVerifier('correct-password-demo'),sessionStore:new OwnerSessionStore({now}),totpVerifier:new OwnerTotpVerifier({secret:Buffer.alloc(32,3),now}),now,maxPendingChallenges:2});
 const first=login.verifyFirstFactor('correct-password-demo');
 const second=login.verifyFirstFactor('correct-password-demo');
 assert.equal(first.ok,true);assert.equal(second.ok,true);
 assert.notEqual(first.challenge,second.challenge);
 assert.deepEqual(login.verifyFirstFactor('correct-password-demo'),{ok:false,reason:'temporarily_unavailable'});
 assert.equal(login.pending.size,2);
 clock+=5*60*1000;
 assert.equal(login.verifyFirstFactor('correct-password-demo').ok,true);
 assert.equal(login.pending.size,1);
});
test('invalid pending challenge capacity is rejected',()=>{
 const opts={ownerId:'demo',passwordRecord:createPasswordVerifier('correct-password-demo'),sessionStore:new OwnerSessionStore(),totpVerifier:new OwnerTotpVerifier({secret:Buffer.alloc(32,3)})};
 assert.throws(()=>new OwnerLoginPrototype({...opts,maxPendingChallenges:0}),/invalid_pending_limit/);
});
