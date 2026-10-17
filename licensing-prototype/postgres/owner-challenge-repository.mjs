// Prototype PostgreSQL owner MFA challenge repository. No database connection is opened here.
// Caller provides a pg-compatible Pool; never store raw challenge tokens.
import {createHash} from 'node:crypto';
const digest=value=>createHash('sha256').update(value).digest();
export class PostgresOwnerChallengeRepository {
 constructor(pool){if(!pool||typeof pool.connect!=='function')throw Error('pool_required');this.pool=pool;}
 async consume({challenge,ownerId,now=new Date(),maxAttempts=5}={}){
  if(typeof challenge!=='string'||!(/^[A-Za-z0-9_-]{32,256}$/.test(challenge))||typeof ownerId!=='string'||!ownerId||!(now instanceof Date)||!Number.isFinite(now.getTime())||!Number.isSafeInteger(maxAttempts)||maxAttempts<1||maxAttempts>5)throw Error('invalid_challenge_input');
  const client=await this.pool.connect();
  let begun=false;
  try{
   await client.query('BEGIN');begun=true;
   const found=await client.query('SELECT owner_id,expires_at,failed_attempts,consumed_at FROM owner_auth_challenges WHERE challenge_hash=$1 FOR UPDATE',[digest(challenge)]);
   const row=found.rows?.[0];
   if(found.rowCount!==1||row.owner_id!==ownerId||row.consumed_at!==null||new Date(row.expires_at).getTime()<=now.getTime()||Number(row.failed_attempts)>=maxAttempts){
    await client.query('ROLLBACK');begun=false;return false;
   }
   const updated=await client.query('UPDATE owner_auth_challenges SET consumed_at=$2 WHERE challenge_hash=$1 AND consumed_at IS NULL RETURNING challenge_hash',[digest(challenge),now]);
   if(updated.rowCount!==1)throw Error('challenge_changed');
   await client.query('COMMIT');begun=false;return true;
  }catch(error){if(begun){try{await client.query('ROLLBACK')}catch{}}throw error;}
  finally{client.release();}
 }
}
