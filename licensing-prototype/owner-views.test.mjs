import test from 'node:test';
import assert from 'node:assert/strict';
import {PostgresLicenseRepository} from './postgres/repository.mjs';
test('owner listings are paginated and do not request secrets',async()=>{
 const calls=[];
 const pool={connect:async()=>{throw Error('unused')},query:async(sql,args)=>{calls.push({sql,args});return {rows:[{id:'one',status:'active'}]}}};
 const repo=new PostgresLicenseRepository(pool);
 for(const method of ['listOrders','listLicenses','listEvents']){
  assert.deepEqual(await repo[method]({limit:20,offset:10}),[{id:'one',status:'active'}]);
  assert.deepEqual(calls.at(-1).args,[20,10]);
  assert.match(calls.at(-1).sql,/LIMIT \$1 OFFSET \$2/);
  assert.doesNotMatch(calls.at(-1).sql,/activation_token_hash|device_public_key\s*,|details\s*,/);
  await assert.rejects(()=>repo[method]({limit:101}),/invalid_pagination/);
  await assert.rejects(()=>repo[method]({offset:-1}),/invalid_pagination/);
 }
});
