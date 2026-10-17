// Isolated service for future PostgreSQL-backed owner MFA login.
// No password verification, HTTP endpoint, cookie, or enrollment lifecycle.
import {randomBytes} from 'node:crypto';
import {matchTotpStep} from './owner-totp-match.mjs';
import {PostgresOwnerMfaAcceptance} from './owner-mfa-acceptance.mjs';
export class PostgresOwnerMfaService {
 constructor({pool,ownerId,totpSecret,now=()=>Date.now()}={}){
  if(!pool||typeof pool.connect!=='function'||typeof ownerId!=='string'||!ownerId||!Buffer.isBuffer(totpSecret)||totpSecret.length<20||typeof now!=='function')throw Error('invalid_mfa_service');
  this.ownerId=ownerId;this.totpSecret=Buffer.from(totpSecret);this.now=now;this.acceptance=new PostgresOwnerMfaAcceptance(pool);
 }
 async complete({challenge,code}={}){
  const timestamp=this.now();
  if(!Number.isSafeInteger(timestamp)||timestamp<0)return null;
  const step=matchTotpStep({secret:this.totpSecret,code,now:timestamp});
  if(step===null)return null;
  const sessionToken=randomBytes(32).toString('base64url');
  const ok=await this.acceptance.accept({challenge,ownerId:this.ownerId,totpStep:step,sessionToken,now:new Date(timestamp),sessionExpiresAt:new Date(timestamp+30*60*1000)});
  return ok?sessionToken:null;
 }
}
