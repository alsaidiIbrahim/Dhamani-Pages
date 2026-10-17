import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,rmSync,readFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {LicenseEngine} from './engine.mjs';
import {PrototypeStore} from './store.mjs';
test('prototype snapshot preserves orders, license hashes, bindings and audit',()=>{
 const dir=mkdtempSync(join(tmpdir(),'dhamani-license-'));
 try{
  const path=join(dir,'state.json'),store=new PrototypeStore(path);
  const e=new LicenseEngine(),order=e.order(),{activationToken,licenseId}=e.approve(order.id);
  e.activate(activationToken,'device-A');
  const challenge=e.issueChallenge(activationToken,'device-A','verify');
  store.save(e);
  const raw=readFileSync(path,'utf8');
  assert.ok(!raw.includes(activationToken),'activation token must never be stored in plaintext');
  assert.ok(!raw.includes(challenge.nonce),'ephemeral challenges must not be persisted');
  const restarted=new LicenseEngine();
  assert.equal(store.load(restarted),true);
  assert.equal(restarted.licenses.get(licenseId).device,'device-A');
  assert.equal(restarted.audit.length,e.audit.length);
  assert.equal(restarted.challenges.size,0);
  assert.equal(restarted.getByToken(activationToken).id,licenseId);
  assert.notEqual(restarted.publicKey.export({format:'pem',type:'spki'}),e.publicKey.export({format:'pem',type:'spki'}),'key persistence is not implemented');
 }finally{rmSync(dir,{recursive:true,force:true})}
});
