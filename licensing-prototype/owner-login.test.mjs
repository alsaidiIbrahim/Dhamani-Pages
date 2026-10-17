import test from 'node:test';
import assert from 'node:assert/strict';
import {createPasswordVerifier,verifyPassword,OwnerLoginPrototype} from './owner-login.mjs';
import {OwnerSessionStore} from './owner-session.mjs';
import {OwnerTotpVerifier,totpCode} from './owner-totp.mjs';
test('owner password verifier uses salted scrypt and rejects incorrect password',()=>{
 const a=createPasswordVerifier('correct horse battery staple');
 const b=createPasswordVerifier('correct horse battery staple');
 assert.notEqual(a.hash,b.hash);assert.notEqual(a.salt,b.salt);
 assert.equal(verifyPassword('correct horse battery staple',a),true);
 assert.equal(verifyPassword('wrong password',a),false);
 assert.equal(verifyPassword('correct horse battery staple',{salt:'bad',hash:'bad'}),false);
});
test('login lockout and MFA challenge binding',()=>{
 let now=1000;
 const secret=Buffer.alloc(32,7);
 const store=new OwnerSessionStore({now:()=>now});
 const login=new OwnerLoginPrototype({ownerId:'owner',passwordRecord:createPasswordVerifier('correct horse battery staple'),sessionStore:store,now:()=>now,maxFailures:3,lockMs:5000});
 for(let i=0;i<3;i++)assert.equal(login.verifyFirstFactor('wrong').ok,false);
 assert.equal(login.verifyFirstFactor('correct horse battery staple').reason,'temporarily_locked');
 now=6000;
 const first=login.verifyFirstFactor('correct horse battery staple');
 assert.equal(first.ok,true);
 const verifier=new OwnerTotpVerifier({secret,now:()=>now});
 const code=totpCode(secret,0);
 assert.throws(()=>login.verifyTotpAndIssueSession({challenge:'fake',totpCode:code,totpVerifier:verifier}),/mfa_required/);
 const token=login.verifyTotpAndIssueSession({challenge:first.challenge,totpCode:code,totpVerifier:verifier});
 assert.equal(store.verify(token).role,'owner');
 assert.throws(()=>login.verifyTotpAndIssueSession({challenge:first.challenge,totpCode:code,totpVerifier:verifier}),/mfa_required/);
 now+=30*60*1000;assert.equal(store.verify(token),null);
});
test('expired challenges and repeated wrong TOTP attempts are rejected',()=>{
 let now=90_000;
 const secret=Buffer.alloc(32,8),verifier=new OwnerTotpVerifier({secret,now:()=>now});
 const store=new OwnerSessionStore({now:()=>now});
 const login=new OwnerLoginPrototype({ownerId:'owner',passwordRecord:createPasswordVerifier('correct horse battery staple'),sessionStore:store,now:()=>now});
 const first=login.verifyFirstFactor('correct horse battery staple');
 now+=300000;
 assert.throws(()=>login.verifyTotpAndIssueSession({challenge:first.challenge,totpCode:totpCode(secret,13),totpVerifier:verifier}),/mfa_required/);
 const second=login.verifyFirstFactor('correct horse battery staple');
 for(let i=0;i<5;i++)assert.throws(()=>login.verifyTotpAndIssueSession({challenge:second.challenge,totpCode:'invalid',totpVerifier:verifier}),/mfa_required/);
 assert.throws(()=>login.verifyTotpAndIssueSession({challenge:second.challenge,totpCode:totpCode(secret,13),totpVerifier:verifier}),/mfa_required/);
});

test('invalid session lifetime does not consume challenge or TOTP',()=>{
 let now=90_000;
 const secret=Buffer.alloc(32,9),verifier=new OwnerTotpVerifier({secret,now:()=>now});
 const sessionStore=new OwnerSessionStore({now:()=>now});
 const login=new OwnerLoginPrototype({ownerId:'owner',passwordRecord:createPasswordVerifier('correct horse battery staple'),sessionStore,now:()=>now});
 const first=login.verifyFirstFactor('correct horse battery staple');
 const code=totpCode(secret,3);
 assert.throws(()=>login.verifyTotpAndIssueSession({challenge:first.challenge,totpCode:code,totpVerifier:verifier,ttlMs:999999999}),/invalid_session_lifetime/);
 assert.equal(login.pending.has(first.challenge),true);
 const token=login.verifyTotpAndIssueSession({challenge:first.challenge,totpCode:code,totpVerifier:verifier});
 assert.equal(sessionStore.verify(token).role,'owner');
});
test('expired challenges are cleaned before new password challenges',()=>{
 let now=90_000;
 const login=new OwnerLoginPrototype({ownerId:'owner',passwordRecord:createPasswordVerifier('correct horse battery staple'),sessionStore:new OwnerSessionStore({now:()=>now}),now:()=>now});
 const first=login.verifyFirstFactor('correct horse battery staple');
 assert.equal(login.pending.size,1);
 now+=300001;
 const second=login.verifyFirstFactor('correct horse battery staple');
 assert.notEqual(first.challenge,second.challenge);
 assert.equal(login.pending.size,1);
 assert.equal(login.pending.has(first.challenge),false);
});
