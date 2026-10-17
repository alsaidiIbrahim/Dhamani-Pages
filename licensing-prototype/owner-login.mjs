// Isolated owner login prototype. No real accounts, MFA delivery, or HTTP endpoint.
// scrypt salts and hashes must be provisioned server-side, never committed.
import {scryptSync,randomBytes,timingSafeEqual} from 'node:crypto';
export function createPasswordVerifier(password,{salt=randomBytes(16)}={}){
 if(typeof password!=='string'||password.length<12||password.length>1024)throw Error('invalid_password');
 if(!Buffer.isBuffer(salt)||salt.length!==16)throw Error('invalid_salt');
 return {salt:salt.toString('hex'),hash:scryptSync(password,salt,64).toString('hex')};
}
export function verifyPassword(password,record){
 if(typeof password!=='string'||password.length>1024||!record||!(/^[a-f0-9]{32}$/.test(record.salt))||!(/^[a-f0-9]{128}$/.test(record.hash)))return false;
 const actual=scryptSync(password,Buffer.from(record.salt,'hex'),64);
 return timingSafeEqual(actual,Buffer.from(record.hash,'hex'));
}
export class OwnerLoginPrototype {
 constructor({ownerId,passwordRecord,sessionStore,now=()=>Date.now(),maxFailures=5,lockMs=15*60*1000}={}){
  if(!ownerId||!passwordRecord||!sessionStore||typeof sessionStore.add!=='function')throw Error('login_configuration_required');
  this.ownerId=ownerId;this.passwordRecord=passwordRecord;this.sessionStore=sessionStore;this.now=now;this.maxFailures=maxFailures;this.lockMs=lockMs;this.failures=0;this.lockUntil=0;this.pending=new Map();this.challengeLifetimeMs=5*60*1000;
 }
 verifyFirstFactor(password){
  if(this.now()<this.lockUntil)return {ok:false,reason:'temporarily_locked'};
  const ok=verifyPassword(password,this.passwordRecord);
  if(!ok){
   this.failures++;
   if(this.failures>=this.maxFailures){this.lockUntil=this.now()+this.lockMs;this.failures=0;}
   return {ok:false,reason:'invalid_credentials'};
  }
  this.failures=0;
  const challenge=randomBytes(32).toString('base64url');
  this.pending.set(challenge,{expiresAt:this.now()+this.challengeLifetimeMs,failures:0});
  return {ok:true,challenge};
 }
 verifyTotpAndIssueSession({challenge,totpCode,totpVerifier,ttlMs=30*60*1000}){
  const pending=typeof challenge==='string'?this.pending.get(challenge):null;
  if(!pending||this.now()>=pending.expiresAt){if(pending)this.pending.delete(challenge);throw Error('mfa_required');}
  if(!totpVerifier||typeof totpVerifier.verify!=='function')throw Error('mfa_required');
  if(!totpVerifier.verify(totpCode)){
   pending.failures++;
   if(pending.failures>=5)this.pending.delete(challenge);
   throw Error('mfa_required');
  }
  // Consume challenge before issuing the session. No reusable boolean bypass.
  this.pending.delete(challenge);
  if(!Number.isSafeInteger(ttlMs)||ttlMs<1000||ttlMs>30*60*1000)throw Error('invalid_session_lifetime');
  const token=randomBytes(32).toString('base64url');
  this.sessionStore.add({token,ownerId:this.ownerId,expiresAt:this.now()+ttlMs,mfaVerified:true});
  return token;
 }
}
