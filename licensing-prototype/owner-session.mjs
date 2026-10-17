// Prototype session verifier for a future owner API.
// Production issuer must provide HTTPS, secure HttpOnly SameSite cookies,
// MFA and CSRF protection. This module only verifies a server-side session.
import {createHash,timingSafeEqual,randomBytes} from 'node:crypto';
const hash=token=>createHash('sha256').update(token).digest();
export class OwnerSessionStore {
 constructor({now=()=>Date.now(),maxLifetimeMs=8*60*60*1000}={}){if(!Number.isSafeInteger(maxLifetimeMs)||maxLifetimeMs<1000||maxLifetimeMs>24*60*60*1000)throw Error('invalid_max_lifetime');this.now=now;this.maxLifetimeMs=maxLifetimeMs;this.sessions=new Map();}
 add({token,ownerId,expiresAt,mfaVerified=false}){
  if(typeof token!=='string'||token.length<32||typeof ownerId!=='string'||!ownerId||!Number.isFinite(expiresAt)||expiresAt<=this.now()||expiresAt-this.now()>this.maxLifetimeMs)throw Error('invalid_session');
  this.sessions.set(hash(token).toString('hex'),{ownerId,expiresAt,mfaVerified,revoked:false,csrfHash:null});
 }
 issueCsrf(token){const entry=typeof token==='string'?this.sessions.get(hash(token).toString('hex')):null;if(!entry||entry.revoked||entry.expiresAt<=this.now()||!entry.mfaVerified)return null;const csrf=randomBytes(32).toString('base64url');entry.csrfHash=hash(csrf);return csrf;}
 verifyCsrf(token,csrf){if(typeof token!=='string'||typeof csrf!=='string'||!/^[A-Za-z0-9_-]{32,256}$/.test(csrf))return false;const entry=this.sessions.get(hash(token).toString('hex'));return Boolean(entry&&!entry.revoked&&entry.expiresAt>this.now()&&entry.mfaVerified&&entry.csrfHash&&timingSafeEqual(entry.csrfHash,hash(csrf)));}
 cleanup(){let removed=0;for(const [key,entry] of this.sessions){if(entry.revoked||entry.expiresAt<=this.now()){this.sessions.delete(key);removed++;}}return removed;}
 revoke(token){
  if(typeof token!=='string')return false;
  const entry=this.sessions.get(hash(token).toString('hex'));
  if(!entry)return false;
  entry.revoked=true;return true;
 }
 verify(token){
  if(typeof token!=='string'||token.length<32)return null;
  const digest=hash(token);
  let matched=null;
  for(const [key,entry] of this.sessions){
   const candidate=Buffer.from(key,'hex');
   if(timingSafeEqual(candidate,digest))matched=entry;
  }
  if(!matched||matched.revoked||matched.expiresAt<=this.now()||!matched.mfaVerified)return null;
  return {id:matched.ownerId,role:'owner',active:true};
 }
}
export function ownerSessionAuthenticator(store,{cookieName='dhamani_owner_session'}={}){
 if(!store||typeof store.verify!=='function')throw Error('session_store_required');
 return async req=>{
  const cookie=req.headers?.cookie;
  if(typeof cookie!=='string'||cookie.length>4096)return null;
  const values=cookie.split(';').map(s=>s.trim()).filter(s=>s.startsWith(cookieName+'='));
  if(values.length!==1)return null;
  const token=values[0].slice(cookieName.length+1);
  if(!/^[A-Za-z0-9_-]{32,256}$/.test(token))return null;
  return store.verify(token);
 };
}
