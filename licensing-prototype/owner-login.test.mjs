import test from 'node:test';
import assert from 'node:assert/strict';
import {createPasswordVerifier,verifyPassword,OwnerLoginPrototype} from './owner-login.mjs';
import {OwnerSessionStore} from './owner-session.mjs';
test('owner password verifier uses salted scrypt and rejects incorrect password',()=>{
 const a=createPasswordVerifier('correct horse battery staple');
 const b=createPasswordVerifier('correct horse battery staple');
 assert.notEqual(a.hash,b.hash);assert.notEqual(a.salt,b.salt);
 assert.equal(verifyPassword('correct horse battery staple',a),true);
 assert.equal(verifyPassword('wrong password',a),false);
 assert.equal(verifyPassword('correct horse battery staple',{salt:'bad',hash:'bad'}),false);
});
test('login lockout and MFA gate',()=>{
 let now=1000;
 const store=new OwnerSessionStore({now:()=>now});
 const login=new OwnerLoginPrototype({ownerId:'owner',passwordRecord:createPasswordVerifier('correct horse battery staple'),sessionStore:store,now:()=>now,maxFailures:3,lockMs:5000});
 for(let i=0;i<3;i++)assert.equal(login.verifyFirstFactor('wrong').ok,false);
 assert.equal(login.verifyFirstFactor('correct horse battery staple').reason,'temporarily_locked');
 now=6000;
 assert.equal(login.verifyFirstFactor('correct horse battery staple').ok,true);
 assert.throws(()=>login.issueMfaVerifiedSession({ownerId:'owner',mfaProofValidated:false}),/mfa_required/);
 const token=login.issueMfaVerifiedSession({ownerId:'owner',mfaProofValidated:true});
 assert.equal(store.verify(token).role,'owner');
 now+=30*60*1000;assert.equal(store.verify(token),null);
});
