import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync} from 'node:crypto';
import {mkdtempSync,writeFileSync,chmodSync,rmSync} from 'node:fs';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {LicenseEngine} from './engine.mjs';
import {PrototypeStore} from './store.mjs';
import {loadSigningKeyFromFile} from './signing-key.mjs';
test('persistent private key verifies previously issued license after server restart',()=>{
 const dir=mkdtempSync(join(tmpdir(),'dhamani-keys-'));
 try{
  const keyFile=join(dir,'signing.pem'),stateFile=join(dir,'licenses.json');
  const {privateKey}=generateKeyPairSync('ed25519');
  writeFileSync(keyFile,privateKey.export({format:'pem',type:'pkcs8'}),{mode:0o600});
  const key=loadSigningKeyFromFile(keyFile);
  const before=new LicenseEngine({signingPrivateKey:key});
  const {activationToken}=before.approve(before.order().id);
  const cert=before.activate(activationToken,'device-A');
  new PrototypeStore(stateFile).save(before);
  const after=new LicenseEngine({signingPrivateKey:loadSigningKeyFromFile(keyFile)});
  assert.equal(new PrototypeStore(stateFile).load(after),true);
  assert.equal(LicenseEngine.verifyCertificate(cert,after.publicKey).devicePublicKey,'device-A');
  assert.equal(LicenseEngine.verifyCertificate(after.verify(activationToken,'device-A'),after.publicKey).licenseType,'perpetual_single_device');
  if(process.platform!=='win32'){
   chmodSync(keyFile,0o644);
   assert.throws(()=>loadSigningKeyFromFile(keyFile),/permissions_too_broad/);
  }
 }finally{rmSync(dir,{recursive:true,force:true})}
});
