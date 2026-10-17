// PostgreSQL transaction adapter prototype. Pass a pg-compatible Pool instance.
// No network connection is created by this module. Use parameterized SQL only.
export class PostgresLicenseRepository {
 constructor(pool){if(!pool||typeof pool.connect!=='function')throw Error('pool_required');this.pool=pool;}
 async transaction(work){
  const client=await this.pool.connect();
  let begun=false;
  try{
   await client.query('BEGIN');begun=true;
   const result=await work(client);
   await client.query('COMMIT');begun=false;
   return result;
  }catch(e){
   if(begun){try{await client.query('ROLLBACK')}catch{}}
   throw e;
  }finally{client.release()}
 }
 async approveOrder({orderId,adminId,licenseId,activationTokenHash}){
  if(!orderId||!adminId||!licenseId||!Buffer.isBuffer(activationTokenHash)||activationTokenHash.length!==32)throw Error('invalid_approval_input');
  return this.transaction(async client=>{
   const order=await client.query("UPDATE license_orders SET status='approved',approved_at=now(),approved_by=$2 WHERE id=$1 AND status='pending' RETURNING id",[orderId,adminId]);
   if(order.rowCount!==1)throw Error('order_not_pending');
   const license=await client.query('INSERT INTO licenses(id,order_id,activation_token_hash) VALUES ($1,$2,$3) RETURNING id',[licenseId,orderId,activationTokenHash]);
   await client.query("INSERT INTO license_events(order_id,license_id,actor_id,action) VALUES ($1,$2,$3,'payment_approved')",[orderId,licenseId,adminId]);
   return {licenseId:license.rows[0].id};
  });
 }
 async transferLicense({licenseId,adminId,newDevicePublicKey,expectedRevision,verifyDeviceProof}){
  if(!licenseId||!adminId||!newDevicePublicKey||!Number.isSafeInteger(expectedRevision)||expectedRevision<0||typeof verifyDeviceProof!=='function')throw Error('invalid_transfer_input');
  return this.transaction(async client=>{
   const locked=await client.query("SELECT id,revision,status FROM licenses WHERE id=$1 FOR UPDATE",[licenseId]);
   if(locked.rowCount!==1||locked.rows[0].status!=='active'||locked.rows[0].revision!==expectedRevision)throw Error('license_changed_or_inactive');
   if(!await verifyDeviceProof({licenseId,newDevicePublicKey,revision:expectedRevision}))throw Error('invalid_device_proof');
   const result=await client.query('UPDATE licenses SET device_public_key=$2,revision=revision+1,last_verified_at=NULL WHERE id=$1 AND revision=$3 RETURNING revision',[licenseId,newDevicePublicKey,expectedRevision]);
   if(result.rowCount!==1)throw Error('license_changed');
   await client.query("INSERT INTO license_events(license_id,actor_id,action) VALUES ($1,$2,'device_transferred')",[licenseId,adminId]);
   return {licenseId,revision:result.rows[0].revision};
  });
 }
}
