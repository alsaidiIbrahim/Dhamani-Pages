// Isolated password + PostgreSQL MFA login orchestration prototype.
// Not exposed over HTTP. Real deployments require durable rate limits, secret vault,
// TLS, CSRF defenses and identity lifecycle management.
import {verifyPassword} from '../owner-login.mjs';
import {PostgresOwnerChallengeRepository} from './owner-challenge-repository.mjs';
import {PostgresOwnerMfaService} from './owner-mfa-service.mjs';
export class PostgresOwnerLoginService {
 constructor({pool,ownerId,passwordRecord,totpSecret,now=()=>Date.now()}={}){
  if(!pool||typeof pool.connect!=='function'||typeof ownerId!=='string'||!ownerId||!passwordRecord||!Buffer.isBuffer(totpSecret)||totpSecret.length<20||typeof now!=='function')throw Error('invalid_login_service');
  this.ownerId=ownerId;this.passwordRecord=passwordRecord;this.now=now;
  this.challenges=new PostgresOwnerChallengeRepository(pool);
  this.mfa=new PostgresOwnerMfaService({pool,ownerId,totpSecret,now});
 }
 async start({password}={}){
  if(!verifyPassword(password,this.passwordRecord))return null;
  const now=this.now();
  if(!Number.isSafeInteger(now)||now<0)return null;
  return this.challenges.issue({ownerId:this.ownerId,now:new Date(now)});
 }
 async complete({challenge,code}={}){
  return this.mfa.complete({challenge,code});
 }
}
