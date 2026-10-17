// Experimental PostgreSQL atomic MFA acceptance. Not wired into HTTP owner login.
// The caller MUST verify the TOTP code cryptographically before calling accept.
// Session issuance is optional for isolated tests; real login integration is NOT implemented.
import {createHash} from 'node:crypto';
const hash=token=>createHash('sha256').update(token).digest();
export class PostgresOwnerMfaAcceptance {
 constructor(pool){if(!pool||typeof pool.connect!=='function')throw Error('pool_required');this.pool=pool;}
 async accept({challenge,ownerId,totpStep,sessionToken,sessionExpiresAt,now=new Date()}={}){
  if(typeof challenge!=='string'||!/^[A-Za-z0-9_-]{32,256}$/.test(challenge)||typeof ownerId!=='string'||!ownerId||!Number.isSafeInteger(totpStep)||totpStep<0||!(now instanceof Date)||!Number.isFinite(now.getTime()))throw Error('invalid_mfa_input');
  const issueSession=sessionToken!==undefined||sessionExpiresAt!==undefined;
  if(issueSession&&(typeof sessionToken!=='string'||!/^[A-Za-z0-9_-]{32,256}$/.test(sessionToken)||!(sessionExpiresAt instanceof Date)||!Number.isFinite(sessionExpiresAt.getTime())||sessionExpiresAt.getTime()<=now.getTime()||sessionExpiresAt.getTime()-now.getTime()>30*60*1000))throw Error('invalid_session_input');
  const client=await this.pool.connect();let begun=false;
  try{
   await client.query('BEGIN');begun=true;
   const row=await client.query('SELECT owner_id,expires_at,failed_attempts,consumed_at FROM owner_auth_challenges WHERE challenge_hash=$1 FOR UPDATE',[hash(challenge)]);
   const record=row.rows?.[0];
   if(row.rowCount!==1||record.owner_id!==ownerId||record.consumed_at!==null||new Date(record.expires_at).getTime()<=now.getTime()||Number(record.failed_attempts)>=5){
    await client.query('ROLLBACK');begun=false;return false;
   }
   const replay=await client.query('INSERT INTO owner_auth_totp_replay(owner_id,last_accepted_step) VALUES($1,$2) ON CONFLICT (owner_id) DO UPDATE SET last_accepted_step=EXCLUDED.last_accepted_step,updated_at=now() WHERE owner_auth_totp_replay.last_accepted_step<EXCLUDED.last_accepted_step RETURNING last_accepted_step',[ownerId,totpStep]);
   if(replay.rowCount!==1){await client.query('ROLLBACK');begun=false;return false;}
   const consumed=await client.query('UPDATE owner_auth_challenges SET consumed_at=$2 WHERE challenge_hash=$1 AND consumed_at IS NULL RETURNING challenge_hash',[hash(challenge),now]);
   if(consumed.rowCount!==1)throw Error('challenge_changed');
   if(issueSession){
    const inserted=await client.query('INSERT INTO owner_auth_sessions(session_hash,owner_id,mfa_verified,created_at,last_activity_at,expires_at) VALUES($1,$2,TRUE,$3,$3,$4) RETURNING session_hash',[hash(sessionToken),ownerId,now,sessionExpiresAt]);
    if(inserted.rowCount!==1)throw Error('session_not_issued');
   }
   await client.query('COMMIT');begun=false;return true;
  }catch(error){if(begun){try{await client.query('ROLLBACK')}catch{}}throw error;}
  finally{client.release();}
 }
}
