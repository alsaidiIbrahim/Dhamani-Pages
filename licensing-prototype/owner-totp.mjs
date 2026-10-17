// TOTP verifier prototype (RFC 6238, HMAC-SHA256).
// Enrollment secrets must be generated and stored encrypted on the server.
// Never commit TOTP seeds, log codes or expose enrollment via public pages.
import {createHmac,timingSafeEqual} from 'node:crypto';
export function totpCode(secret,step,{digits=6}={}){
 if(!Buffer.isBuffer(secret)||secret.length<20||!Number.isSafeInteger(step)||step<0||digits!==6)throw Error('invalid_totp_input');
 const counter=Buffer.alloc(8);counter.writeBigUInt64BE(BigInt(step));
 const mac=createHmac('sha256',secret).update(counter).digest();
 const offset=mac[mac.length-1]&15;
 const value=(mac.readUInt32BE(offset)&0x7fffffff)%1_000_000;
 return String(value).padStart(6,'0');
}
export class OwnerTotpVerifier {
 constructor({secret,now=()=>Date.now(),stepMs=30000,window=1}={}){
  if(!Buffer.isBuffer(secret)||secret.length<20||!Number.isSafeInteger(stepMs)||stepMs<1000||window!==1)throw Error('invalid_totp_configuration');
  this.secret=Buffer.from(secret);this.now=now;this.stepMs=stepMs;this.window=window;this.lastAcceptedStep=-1;
 }
 verify(code){
  if(typeof code!=='string'||!/^[0-9]{6}$/.test(code))return false;
  const current=Math.floor(this.now()/this.stepMs);
  for(let step=current-this.window;step<=current+this.window;step++){
   if(step<0||step<=this.lastAcceptedStep)continue;
   const expected=totpCode(this.secret,step);
   if(timingSafeEqual(Buffer.from(expected),Buffer.from(code))){
    this.lastAcceptedStep=step;return true;
   }
  }
  return false;
 }
}
