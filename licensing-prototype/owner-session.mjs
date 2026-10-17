// Prototype session verifier for a future owner API.
// Production issuer must provide HTTPS, secure HttpOnly SameSite cookies,
// MFA and CSRF protection. This module only verifies a server-side session.
import {createHash,timingSafeEqual} from 'node:crypto';
const hash=token=>createHash('sha256').update(token).digest();
export class OwnerSessionStore {
 constructor({now=()=>Date.now()}={}){this.now=now;this.sessions=new Map();}
 add({token,ownerId,expiresAt,mfaVerified=false}){
  if(typeof token!=='string'||token.length<32||typeof ownerId!=='string'||!ownerId||!Number.isFinite(expiresAt)||expiresAt<=this.now())throw Error('invalid_session');
  this.sessions.set(hash(token).toString('hex'),{ownerId,expiresAt,mfaVerified,revoked:false});
 }
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
