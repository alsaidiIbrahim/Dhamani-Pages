import test from 'node:test';
import {request} from 'node:http';
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
 const repository={listOrders:async()=>[{id:'DEMO-1'}],listLicenses:async()=>[],listEvents:async()=>[]};
 const server=await startLoopbackOwnerLoginServer({login,totpVerifier:new OwnerTotpVerifier({secret,now}),sessionStore,repository});
 try{
  assert.equal(server.address().address,'127.0.0.1');
  const base='http://127.0.0.1:'+server.address().port;
  async function post(path,data,cookie,csrf){
   return fetch(base+path,{method:'POST',headers:{'content-type':'application/json',...(cookie?{cookie}:{}),...(csrf?{'x-csrf-token':csrf}:{})},body:JSON.stringify(data)});
  }
  const badHostStatus=await new Promise((resolve,reject)=>{
   const req=request({hostname:'127.0.0.1',port:server.address().port,path:'/owner/login/password',method:'POST',headers:{host:'other.example:1234','content-type':'application/json'}},res=>{res.resume();res.on('end',()=>resolve(res.statusCode));});
   req.on('error',reject);req.end(JSON.stringify({password:'correct horse battery staple'}));
  });
  assert.equal(badHostStatus,403);
  assert.equal((await fetch(base+'/owner/orders')).status,403);
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
  const {csrfToken}=await second.json();
  const cookie=second.headers.get('set-cookie');
  assert.match(cookie,/HttpOnly/);
  assert.match(cookie,/SameSite=Strict/);
  const authorized=await fetch(base+'/owner/orders',{headers:{cookie:cookie.split(';')[0]}});
  assert.equal(authorized.status,200);
  assert.deepEqual((await authorized.json()).items,[{id:'DEMO-1'}]);
  assert.equal((await fetch(base+'/owner/licenses',{headers:{cookie:cookie.split(';')[0]}})).status,200);
  assert.equal((await fetch(base+'/owner/events',{headers:{cookie:cookie.split(';')[0]}})).status,200);
  assert.equal((await fetch(base+'/owner/orders',{headers:{cookie:'dhamani_owner_session=invalid'}})).status,403);
  assert.equal((await fetch(base+'/owner/orders',{headers:{cookie:cookie.split(';')[0]+'; '+cookie.split(';')[0]}})).status,403);
  assert.equal((await fetch(base+'/owner/orders?limit=101',{headers:{cookie:cookie.split(';')[0]}})).status,400);
  assert.equal((await fetch(base+'/owner/orders?offset=-1',{headers:{cookie:cookie.split(';')[0]}})).status,400);

  assert.equal((await fetch(base+'/owner/orders',{method:'POST',headers:{cookie:cookie.split(';')[0],'content-type':'application/json'},body:'{}'})).status,404);
  assert.equal((await post('/owner/login/totp',{challenge,code:totpCode(secret,3)})).status,401);
  assert.equal((await post('/owner/logout',{},cookie.split(';')[0])).status,403);
  assert.equal((await post('/owner/logout',{},cookie.split(';')[0],'invalid')).status,403);
  assert.equal((await post('/owner/logout',{},cookie.split(';')[0],csrfToken)).status,200);
  assert.equal((await fetch(base+'/owner/orders',{headers:{cookie:cookie.split(';')[0]}})).status,403);
  assert.equal((await post('/owner/logout',{},cookie.split(';')[0])).status,403);
 }finally{await new Promise(resolve=>server.close(resolve));}
});
