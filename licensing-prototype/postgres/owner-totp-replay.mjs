// Proposed PostgreSQL cross-node TOTP replay guard. Not wired to owner login.
export class PostgresTotpReplayGuard {
 constructor(pool){if(!pool||typeof pool.query!=='function')throw Error('pool_required');this.pool=pool;}
 async accept({ownerId,step}={}){
  if(typeof ownerId!=='string'||!ownerId||!Number.isSafeInteger(step)||step<0)throw Error('invalid_replay_input');
  const result=await this.pool.query(
   'INSERT INTO owner_auth_totp_replay(owner_id,last_accepted_step) VALUES($1,$2) ON CONFLICT (owner_id) DO UPDATE SET last_accepted_step=EXCLUDED.last_accepted_step,updated_at=now() WHERE owner_auth_totp_replay.last_accepted_step<EXCLUDED.last_accepted_step RETURNING last_accepted_step',
   [ownerId,step]
  );
  return result.rowCount===1;
 }
}
