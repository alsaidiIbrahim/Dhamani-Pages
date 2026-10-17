import {randomBytes,createHash,generateKeyPairSync,sign,verify} from 'node:crypto';
const sha=v=>createHash('sha256').update(v).digest('hex');
const day=86400000;
export class LicenseEngine {
 constructor({now=()=>Date.now()}={}){this.now=now;this.orders=new Map();this.licenses=new Map();this.audit=[];this.challenges=new Map();const k=generateKeyPairSync('ed25519');this.privateKey=k.privateKey;this.publicKey=k.publicKey;}
 log(action,id){this.audit.push({action,id,at:new Date(this.now()).toISOString()});}
 order(){const id=randomBytes(12).toString('hex');this.orders.set(id,{id,paid:false});this.log('order',id);return {id,status:'pending_payment'};}
 approve(id){const o=this.orders.get(id);if(!o)throw Error('order_not_found');if(o.paid)throw Error('already_approved');o.paid=true;const token=randomBytes(24).toString('base64url');const licenseId=randomBytes(12).toString('hex');this.licenses.set(licenseId,{id:licenseId,orderId:id,tokenHash:sha(token),device:null,status:'approved',revision:0});this.log('approve',licenseId);return {licenseId,activationToken:token};}
 getByToken(token){const l=[...this.licenses.values()].find(x=>x.tokenHash===sha(token));if(!l)throw Error('invalid_token');return l;}
 certificate(l){const payload={licenseId:l.id,devicePublicKey:l.device,licenseType:'perpetual_single_device',revision:l.revision,verifiedAt:this.now(),nextCheckAt:this.now()+30*day};const body=Buffer.from(JSON.stringify(payload)).toString('base64url');return {body,signature:sign(null,Buffer.from(body),this.privateKey).toString('base64url')};}
 activate(token,devicePublicKey){const l=this.getByToken(token);if(!devicePublicKey||typeof devicePublicKey!=='string')throw Error('invalid_device_key');if(l.status==='revoked'||l.status==='suspended')throw Error('license_inactive');if(l.device&&l.device!==devicePublicKey)throw Error('already_bound');l.device=devicePublicKey;l.status='active';this.log('activate',l.id);return this.certificate(l);}
 verify(token,devicePublicKey){const l=this.getByToken(token);if(l.status!=='active'||l.device!==devicePublicKey)throw Error('device_not_authorized');this.log('verify',l.id);return this.certificate(l);}
 issueChallenge(token,devicePublicKey,purpose='activate'){
  const l=this.getByToken(token);
  if(!['activate','verify'].includes(purpose))throw Error('invalid_purpose');
  if(l.status==='revoked'||l.status==='suspended')throw Error('license_inactive');
  if(purpose==='activate'&&l.device&&l.device!==devicePublicKey)throw Error('already_bound');
  if(purpose==='verify'&&(l.status!=='active'||l.device!==devicePublicKey))throw Error('device_not_authorized');
  const id=randomBytes(18).toString('base64url');
  const nonce=randomBytes(32).toString('base64url');
  this.challenges.set(id,{licenseId:l.id,devicePublicKey,purpose,nonce,expiresAt:this.now()+120000});
  return {id,nonce,expiresAt:this.now()+120000};
 }
 completeChallenge(token,id,signature){
  const challenge=this.challenges.get(id);
  if(!challenge)throw Error('challenge_not_found');
  this.challenges.delete(id);
  const l=this.getByToken(token);
  if(l.id!==challenge.licenseId||this.now()>challenge.expiresAt)throw Error('challenge_expired_or_mismatched');
  const message=Buffer.from('dhamani-device-proof-v1:'+challenge.purpose+':'+id+':'+challenge.nonce);
  let valid=false;
  try{valid=verify(null,message,challenge.devicePublicKey,Buffer.from(signature,'base64url'))}catch{}
  if(!valid)throw Error('invalid_device_proof');
  if(challenge.purpose==='activate')return this.activate(token,challenge.devicePublicKey);
  return this.verify(token,challenge.devicePublicKey);
 }
 transfer(licenseId,newDevicePublicKey){const l=this.licenses.get(licenseId);if(!l||l.status!=='active')throw Error('license_not_active');if(!newDevicePublicKey||newDevicePublicKey===l.device)throw Error('invalid_new_device');l.device=newDevicePublicKey;l.revision++;this.log('transfer',l.id);return {licenseId:l.id,revision:l.revision};}
 suspend(id){const l=this.licenses.get(id);if(!l)throw Error('license_not_found');l.status='suspended';l.revision++;this.log('suspend',id);}
 static verifyCertificate(cert,publicKey){return verify(null,Buffer.from(cert.body),publicKey,Buffer.from(cert.signature,'base64url'))?JSON.parse(Buffer.from(cert.body,'base64url').toString()):null;}
}
