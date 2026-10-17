import test from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
import {totpCode,OwnerTotpVerifier} from './owner-totp.mjs';
test('TOTP matches RFC 6238 SHA256 known vector at 59 seconds',()=>{
 const secret=Buffer.from('3132333435363738393031323334353637383930313233343536373839303132','hex');
 // RFC 6238 Appendix B SHA256 8-digit result at t=59 is 46119246; 6-digit suffix is 119246.
 assert.equal(totpCode(secret,1),'119246');
});
test('TOTP validates current step, prevents replay and rejects expired code',()=>{
 let now=90_000;
 const secret=randomBytes(32);
 const verifier=new OwnerTotpVerifier({secret,now:()=>now});
 const code=totpCode(secret,3);
 assert.equal(verifier.verify(code),true);
 assert.equal(verifier.verify(code),false);
 now=210_000;
 assert.equal(verifier.verify(code),false);
 assert.equal(verifier.verify(totpCode(secret,7)),true);
});
test('TOTP rejects malformed codes and short seeds',()=>{
 assert.throws(()=>new OwnerTotpVerifier({secret:Buffer.alloc(10)}),/invalid_totp_configuration/);
 const verifier=new OwnerTotpVerifier({secret:randomBytes(32)});
 for(const code of ['12345','1234567','abcdef',123456,''])assert.equal(verifier.verify(code),false);
});
