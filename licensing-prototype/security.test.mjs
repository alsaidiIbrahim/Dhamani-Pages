import test from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
import {createPrototypeServer} from './server.mjs';
test('prototype API rate limits requests and does not leak supplied tokens',async()=>{
 const {server,listen}=createPrototypeServer({adminToken:randomBytes(32).toString('hex')});
 const address=await listen(),url='http://127.0.0.1:'+address.port;
 try{
  const fake='sensitive-token-must-not-appear-in-error';
  const first=await fetch(url+'/challenge',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({activationToken:fake,devicePublicKey:'x'})});
  assert.equal(first.status,400);
  assert.ok(!(await first.text()).includes(fake));
  let last;
  for(let i=0;i<61;i++)last=await fetch(url+'/health');
  assert.equal(last.status,429);
  assert.deepEqual(await last.json(),{error:'rate_limited'});
 }finally{await new Promise((resolve,reject)=>server.close(e=>e?reject(e):resolve()))}
});
