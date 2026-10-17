// Experimental PostgreSQL-backed owner session verification and revocation.
// No HTTP routes or cookie issuance are connected to this module.
import {createHash,randomBytes} from 'node:crypto';
const digest=token=>createHash('sha256').update(token).digest();
export class PostgresOwnerSessionRepository {
 constructor(pool,{maxIdleMs=10*60*1000}={}){
  if(!pool||typeof pool.query!=='function'||!Number.isSafeInteger(maxIdleMs)||maxIdleMs<1000||maxIdleMs>24*60*60*1000)throw Error('invalid_session_repository');
  this.pool=pool;this.maxIdleMs=maxIdleMs;
 }
 async verify({token,now=new Date()}={}){
  if(typeof token!=='string'||!/^[A-Za-z0-9_-]{32,256}$/.test(token)||!(now instanceof Date)||!Number.isFinite(now.getTime()))return null;
  const result=await this.pool.query(
   "UPDATE owner_auth_sessions SET last_activity_at=$2 WHERE session_hash=$1 AND mfa_verified=TRUE AND revoked_at IS NULL AND expires_at>$2 AND last_activity_at<=$2 AND last_activity_at>$2-($3::bigint * interval '1 millisecond') RETURNING owner_id,expires_at,last_activity_at",
   [digest(token),now,this.maxIdleMs]
  );
  if(result.rowCount!==1)return null;
  return {id:result.rows[0].owner_id,role:'owner',active:true};
 }
 async issueCsrf({token,now=new Date()}={}){
  if(typeof token!=='string'||!/^[A-Za-z0-9_-]{32,256}$/.test(token)||!(now instanceof Date)||!Number.isFinite(now.getTime()))return null;
  const csrf=randomBytes(32).toString('base64url');
  const result=await this.pool.query("UPDATE owner_auth_sessions SET csrf_hash=$3 WHERE session_hash=$1 AND mfa_verified=TRUE AND revoked_at IS NULL AND expires_at>$2 AND last_activity_at<=$2 AND last_activity_at>$2-($4::bigint * interval '1 millisecond') RETURNING session_hash",[digest(token),now,digest(csrf),this.maxIdleMs]);
  return result.rowCount===1?csrf:null;
 }
 async verifyCsrf({token,csrf,now=new Date()}={}){
  if(typeof token!=='string'||!/^[A-Za-z0-9_-]{32,256}$/.test(token)||typeof csrf!=='string'||!/^[A-Za-z0-9_-]{32,256}$/.test(csrf)||!(now instanceof Date)||!Number.isFinite(now.getTime()))return false;
  const result=await this.pool.query("SELECT 1 FROM owner_auth_sessions WHERE session_hash=$1 AND csrf_hash=$2 AND mfa_verified=TRUE AND revoked_at IS NULL AND expires_at>$3 AND last_activity_at<=$3 AND last_activity_at>$3-($4::bigint * interval '1 millisecond')",[digest(token),digest(csrf),now,this.maxIdleMs]);
  return result.rowCount===1;
 }
 async revokeWithCsrf({token,csrf,now=new Date()}={}){
  if(typeof token!=='string'||!/^[A-Za-z0-9_-]{32,256}$/.test(token)||typeof csrf!=='string'||!/^[A-Za-z0-9_-]{32,256}$/.test(csrf)||!(now instanceof Date)||!Number.isFinite(now.getTime()))return false;
  const result=await this.pool.query("UPDATE owner_auth_sessions SET revoked_at=$3,csrf_hash=NULL WHERE session_hash=$1 AND csrf_hash=$2 AND mfa_verified=TRUE AND revoked_at IS NULL AND expires_at>$3 AND last_activity_at<=$3 AND last_activity_at>$3-($4::bigint * interval '1 millisecond') RETURNING session_hash",[digest(token),digest(csrf),now,this.maxIdleMs]);
  return result.rowCount===1;
 }
 async revoke({token,now=new Date()}={}){
  if(typeof token!=='string'||!/^[A-Za-z0-9_-]{32,256}$/.test(token)||!(now instanceof Date)||!Number.isFinite(now.getTime()))return false;
  const result=await this.pool.query('UPDATE owner_auth_sessions SET revoked_at=$2,csrf_hash=NULL WHERE session_hash=$1 AND revoked_at IS NULL RETURNING session_hash',[digest(token),now]);
  return result.rowCount===1;
 }
}
