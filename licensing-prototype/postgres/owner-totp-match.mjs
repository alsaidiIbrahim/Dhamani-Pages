// Side-effect-free TOTP matching for a future transactional PostgreSQL login.
// The caller must atomically claim the returned step before granting access.
import {timingSafeEqual} from 'node:crypto';
import {totpCode} from '../owner-totp.mjs';
export function matchTotpStep({secret,code,now=Date.now(),stepMs=30_000,window=1}={}){
 if(!Buffer.isBuffer(secret)||secret.length<20||typeof code!=='string'||!/^[0-9]{6}$/.test(code)||!Number.isSafeInteger(now)||now<0||!Number.isSafeInteger(stepMs)||stepMs<1000||window!==1)return null;
 const current=Math.floor(now/stepMs);
 let matched=null;
 for(let step=current-window;step<=current+window;step++){
  if(step<0)continue;
  const expected=totpCode(secret,step);
  if(timingSafeEqual(Buffer.from(expected),Buffer.from(code)))matched=step;
 }
 return matched;
}
