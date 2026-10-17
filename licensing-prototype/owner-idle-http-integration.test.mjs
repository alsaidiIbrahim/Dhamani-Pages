import test from 'node:test';
import assert from 'node:assert/strict';
import {OwnerLoginPrototype,createPasswordVerifier} from './owner-login.mjs';
import {OwnerSessionStore} from './owner-session.mjs';
import {OwnerTotpVerifier,totpCode} from './owner-totp.mjs';
import {startLoopbackOwnerLoginServer} from './owner-login-http.mjs';
test('HTTP login, idle expiration, access rejection and fresh MFA login',async()=>{
 let clock=90_000;
 const now=()=>clock;
 const secret=Buffer.alloc(32,19);
 const sessionStore=new OwnerSessionStore({now,maxIdleMs:2000,maxLifetimeMs:30*60*1000});
 const totpVerifier=new OwnerTotpVerifier({secret,now});
 const login=new OwnerLoginPrototype({ownerId:'DEMO-OWNER',passwordRecord:createPasswordVerifier('test-only-password-12345'),sessionStore,totpVerifier,now});
 const repository={listOrders:async()=>[{id:'DEMO-ORDER'}],listLicenses:async()=>[],listEvents:async()=>[]};
 const server=await startLoopbackOwnerLoginServer({login,totpVerifier,sessionStore,repository});
 const base='http://127.0.0.1:'+server.address().port;
 const post=(path,data)=>fetch(base+path,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(data)});
 async function signIn(){
  const first=await post('/owner/login/password',{password:'test-only-password-12345'});
  assert.equal(first.status,200);
  const {challenge}=await first.json();
  const second=await post('/owner/login/totp',{challenge,code:totpCode(secret,Math.floor(clock/30000))});
  assert.equal(second.status,200);
  return second.headers.get('set-cookie').split(';')[0];
 }
 try{
  const oldCookie=await signIn();
  assert.equal((await fetch(base+'/owner/orders',{headers:{cookie:oldCookie}})).status,200);
  const session=await fetch(base+'/owner/session',{headers:{cookie:oldCookie}});
  assert.equal((await session.json()).expiresAt,clock+2000);
  clock+=2001;
  assert.equal((await fetch(base+'/owner/orders',{headers:{cookie:oldCookie}})).status,403);
  assert.equal((await fetch(base+'/owner/dashboard',{headers:{cookie:oldCookie}})).status,403);
  assert.equal((await fetch(base+'/owner/session',{headers:{cookie:oldCookie}})).status,403);
  assert.equal(sessionStore.cleanup(),1);
  clock+=30000;
  const newCookie=await signIn();
  assert.notEqual(newCookie,oldCookie);
  assert.equal((await fetch(base+'/owner/orders',{headers:{cookie:newCookie}})).status,200);
  assert.equal((await fetch(base+'/owner/orders',{headers:{cookie:oldCookie}})).status,403);
 }finally{await new Promise(resolve=>server.close(resolve));}
});
