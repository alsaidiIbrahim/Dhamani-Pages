import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,readFileSync,writeFileSync,rmSync} from 'node:fs';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {LicenseEngine} from './engine.mjs';
import {PrototypeStore} from './store.mjs';
test('invalid audit snapshot does not change existing in-memory state',()=>{
 const dir=mkdtempSync(join(tmpdir(),'dhamani-recovery-'));
 try{
  const path=join(dir,'state.json'),store=new PrototypeStore(path);
  const original=new LicenseEngine();
  const order=original.order();original.approve(order.id);store.save(original);
  const active=new LicenseEngine();active.order();
  const previous={orders:[...active.orders],licenses:[...active.licenses],audit:structuredClone(active.audit),head:active.auditHead};
  const tampered=JSON.parse(readFileSync(path,'utf8'));tampered.audit[0].action='tampered';
  writeFileSync(path,JSON.stringify(tampered));
  assert.throws(()=>store.load(active),/invalid_audit_chain/);
  assert.deepEqual([...active.orders],previous.orders);
  assert.deepEqual([...active.licenses],previous.licenses);
  assert.deepEqual(active.audit,previous.audit);
  assert.equal(active.auditHead,previous.head);
  assert.equal(active.verifyAudit(),true);
 }finally{rmSync(dir,{recursive:true,force:true})}
});
