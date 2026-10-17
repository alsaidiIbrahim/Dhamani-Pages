// Isolated shared PostgreSQL password-attempt lockout prototype.
// Account-scoped only; no IP/device abuse controls or production deployment.
export class PostgresOwnerPasswordLimit {
 constructor(pool,{maxFailures=5,lockMs=15*60*1000}={}){
  if(!pool||typeof pool.connect!=='function'||!Number.isSafeInteger(maxFailures)||maxFailures<1||maxFailures>5||!Number.isSafeInteger(lockMs)||lockMs<1000||lockMs>24*60*60*1000)throw Error('invalid_password_limit');
  this.pool=pool;this.maxFailures=maxFailures;this.lockMs=lockMs;
 }
 async evaluate({ownerId,passwordValid,now=new Date()}={}){
  if(typeof ownerId!=='string'||!ownerId||typeof passwordValid!=='boolean'||!(now instanceof Date)||!Number.isFinite(now.getTime()))throw Error('invalid_password_attempt');
  const client=await this.pool.connect();let begun=false;
  try{
   await client.query('BEGIN');begun=true;
   await client.query('INSERT INTO owner_auth_password_limits(owner_id) VALUES($1) ON CONFLICT(owner_id) DO NOTHING',[ownerId]);
   const found=await client.query('SELECT failed_attempts,locked_until FROM owner_auth_password_limits WHERE owner_id=$1 FOR UPDATE',[ownerId]);
   const record=found.rows[0],lockedUntil=record.locked_until?new Date(record.locked_until).getTime():0;
   if(lockedUntil>now.getTime()){await client.query('ROLLBACK');begun=false;return false;}
   if(passwordValid){
    await client.query('UPDATE owner_auth_password_limits SET failed_attempts=0,locked_until=NULL,updated_at=$2 WHERE owner_id=$1',[ownerId,now]);
    await client.query('COMMIT');begun=false;return true;
   }
   const failures=(lockedUntil&&lockedUntil<=now.getTime()?0:Number(record.failed_attempts))+1;
   const locked=failures>=this.maxFailures;
   await client.query('UPDATE owner_auth_password_limits SET failed_attempts=$2,locked_until=$3,updated_at=$4 WHERE owner_id=$1',[ownerId,Math.min(failures,this.maxFailures),locked?new Date(now.getTime()+this.lockMs):null,now]);
   await client.query('COMMIT');begun=false;return false;
  }catch(error){if(begun){try{await client.query('ROLLBACK')}catch{}}throw error;}
  finally{client.release();}
 }
}
