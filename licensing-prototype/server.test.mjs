import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,sign,randomBytes} from 'node:crypto';
import {createPrototypeServer} from './server.mjs';
test('loopback API requires admin token and signed device proof',async()=>{
 const token=randomBytes(32).toString('hex');
 const {server,listen}=createPrototypeServer({adminToken:token});
 const address=await listen();
 assert.equal(address.address,'127.0.0.1');
 const url='http://127.0.0.1:'+address.port;
 const post=async(path,body,headers={})=>{
  const res=await fetch(url+path,{method:'POST',headers:{'content-type':'application/json',...headers},body:JSON.stringify(body)});
  return {status:res.status,data:await res.json()};
 };
 try{
  const order=await post('/orders',{});
  assert.equal(order.status,200);
  assert.equal((await post('/admin/approve',{orderId:order.data.id})).status,403);
  const approved=await post('/admin/approve',{orderId:order.data.id},{'x-admin-token':token});
  assert.equal(approved.status,200);
  const {activationToken}=approved.data;
  const key=generateKeyPairSync('ed25519');
  const devicePublicKey=key.publicKey.export({format:'pem',type:'spki'});
  const ch=await post('/challenge',{activationToken,devicePublicKey,purpose:'activate'});
  assert.equal(ch.status,200);
  const signature=sign(null,Buffer.from('dhamani-device-proof-v1:activate:'+ch.data.id+':'+ch.data.nonce),key.privateKey).toString('base64url');
  const result=await post('/complete',{activationToken,challengeId:ch.data.id,signature});
  assert.equal(result.status,200);
  assert.ok(result.data.signature);
  assert.equal((await post('/complete',{activationToken,challengeId:ch.data.id,signature})).status,400);
  assert.equal((await post('/admin/suspend',{licenseId:approved.data.licenseId},{'x-admin-token':token})).status,200);
  assert.equal((await post('/challenge',{activationToken,devicePublicKey,purpose:'verify'})).status,400);
 }finally{await new Promise((resolve,reject)=>server.close(e=>e?reject(e):resolve()))}
});
