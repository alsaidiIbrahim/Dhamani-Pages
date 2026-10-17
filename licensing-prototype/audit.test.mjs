import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,readFileSync,writeFileSync,rmSync} from 'node:fs';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {LicenseEngine} from './engine.mjs';
import {PrototypeStore} from './store.mjs';
test('audit hash chain detects altered events and persists across restart',()=>{
 const dir=mkdtempSync(join(tmpdir(),'dhamani-audit-'));
 try{
  const path=join(dir,'audit.json'),e=new LicenseEngine();
  const order=e.order();e.approve(order.id);
  assert.equal(e.verifyAudit(),true);
  const store=new PrototypeStore(path);store.save(e);
  const next=new LicenseEngine();store.load(next);
  assert.equal(next.verifyAudit(),true);
  const altered=JSON.parse(readFileSync(path,'utf8'));
  altered.audit[0].action='forged_approval';
  writeFileSync(path,JSON.stringify(altered));
  assert.throws(()=>store.load(new LicenseEngine()),/invalid_audit_chain/);
 }finally{rmSync(dir,{recursive:true,force:true})}
});
