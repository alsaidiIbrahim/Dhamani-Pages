import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,readFileSync,rmSync} from 'node:fs';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {LicenseEngine} from './engine.mjs';
import {PrototypeStore} from './store.mjs';
test('save refuses tampered live audit and leaves last valid snapshot intact',()=>{
 const dir=mkdtempSync(join(tmpdir(),'dhamani-safe-save-'));
 try{
  const file=join(dir,'state.json'),store=new PrototypeStore(file),e=new LicenseEngine();
  e.order();store.save(e);
  const before=readFileSync(file,'utf8');
  e.audit[0].action='forged';
  assert.throws(()=>store.save(e),/invalid_live_audit_chain/);
  assert.equal(readFileSync(file,'utf8'),before);
  const restored=new LicenseEngine();
  assert.equal(store.load(restored),true);
  assert.equal(restored.verifyAudit(),true);
 }finally{rmSync(dir,{recursive:true,force:true})}
});
