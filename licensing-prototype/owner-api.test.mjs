import test from 'node:test';
import assert from 'node:assert/strict';
import {createOwnerReadHandler} from './owner-api.mjs';
function response(){return {status:0,headers:{},body:null,writeHead(status,headers){this.status=status;this.headers=headers},end(data){this.body=JSON.parse(data)}}}
test('owner API rejects unauthenticated and non-owner requests',async()=>{
 let called=0;
 const repository={listOrders:async()=>{called++;return []}};
 for(const principal of [null,{role:'viewer',active:true},{role:'owner',active:false}]){
  const handler=createOwnerReadHandler({repository,authenticateOwner:async()=>principal});
  const res=response();
  await handler({method:'GET',url:'/owner/orders'},res);
  assert.equal(res.status,403);
 }
 assert.equal(called,0);
});
test('owner API exposes only approved read routes and bounded pagination',async()=>{
 const requests=[];
 const repository={listOrders:async args=>{requests.push(args);return [{id:'demo'}]}};
 const handler=createOwnerReadHandler({repository,authenticateOwner:async()=>({role:'owner',active:true})});
 const ok=response();await handler({method:'GET',url:'/owner/orders?limit=10&offset=5'},ok);
 assert.equal(ok.status,200);assert.deepEqual(ok.body.items,[{id:'demo'}]);
 assert.deepEqual(requests,[{limit:10,offset:5}]);
 assert.equal(ok.headers['cache-control'],'no-store');
 for(const url of ['/owner/orders?limit=101','/owner/orders?offset=-1','/owner/orders?limit=1e3']){
  const res=response();await handler({method:'GET',url},res);assert.equal(res.status,400);
 }
 const unknown=response();await handler({method:'GET',url:'/owner/secrets'},unknown);assert.equal(unknown.status,404);
 const post=response();await handler({method:'POST',url:'/owner/orders'},post);assert.equal(post.status,405);
 assert.equal(requests.length,1);
});
test('owner API fails closed on authentication exceptions',async()=>{
 const handler=createOwnerReadHandler({repository:{listOrders:async()=>[]},authenticateOwner:async()=>{throw Error('secret_token')}});
 const res=response();await handler({method:'GET',url:'/owner/orders'},res);
 assert.equal(res.status,500);
 assert.doesNotMatch(JSON.stringify(res.body),/secret_token/);
});
