import test from 'node:test';
import assert from 'node:assert/strict';
import {OwnerLoginPrototype,createPasswordVerifier} from './owner-login.mjs';
import {OwnerSessionStore} from './owner-session.mjs';
import {OwnerTotpVerifier,totpCode} from './owner-totp.mjs';
import {startLoopbackOwnerLoginServer} from './owner-login-http.mjs';
test('local HTTP owner login enforces two factors and logout',async()=>{
 const now=()=>90000;
 const secret=Buffer.alloc(32,11);
 const sessionStore=new OwnerSessionStore({now});
 const login=new OwnerLoginPrototype({ownerId:'owner',passwordRecord:createPasswordVerifier('correct horse battery staple'),sessionStore,now});
 const server=await startLoopbackOwnerLoginServer({login,totpVerifier:new OwnerTotpVerifier({secret,now}),sessionStore});
 try{
  assert.equal(server.address().address,'127.0.0.1');
  const base='http://127.0.0.1:'+server.address().port;
  async function post(path,data,cookie){
   return fetch(base+path,{method:'POST',headers:{'content-type':'application/json',...(cookie?{cookie}:{})},body:JSON.stringify(data)});
  }
  const badHost=await fetch(base+'/owner/login/password',{method:'POST',headers:{'content-type':'application/json',host:'other.example:1234'},body:JSON.stringify({password:'correct horse battery staple'})});
  assert.equal(badHost.status,403);
  const foreign=await fetch(base+'/owner/login/password',{method:'POST',headers:{'content-type':'application/json',origin:'https://untrusted.example'},body:JSON.stringify({password:'correct horse battery staple'})});
  assert.equal(foreign.status,403);
  const badType=await fetch(base+'/owner/login/password',{method:'POST',headers:{'content-type':'text/plain'},body:'hello'});
  assert.equal(badType.status,415);
  const crossSite=await fetch(base+'/owner/login/password',{method:'POST',headers:{'content-type':'application/json','sec-fetch-site':'cross-site'},body:JSON.stringify({password:'correct horse battery staple'})});
  assert.equal(crossSite.status,403);
  assert.equal((await post('/owner/login/password',{password:'incorrect'})).status,401);
  assert.equal((await post('/owner/login/totp',{challenge:'invalid',code:totpCode(secret,3)})).status,401);
  const first=await post('/owner/login/password',{password:'correct horse battery staple'});
  assert.equal(first.status,200);
  const {challenge}=await first.json();
  const second=await post('/owner/login/totp',{challenge,code:totpCode(secret,3)});
  assert.equal(second.status,200);
  const cookie=second.headers.get('set-cookie');
  assert.match(cookie,/HttpOnly/);
  assert.match(cookie,/SameSite=Strict/);
  assert.equal((await post('/owner/login/totp',{challenge,code:totpCode(secret,3)})).status,401);
  assert.equal((await post('/owner/logout',{},cookie.split(';')[0])).status,200);
  assert.equal((await post('/owner/logout',{},cookie.split(';')[0])).status,403);
 }finally{await new Promise(resolve=>server.close(resolve));}
});
