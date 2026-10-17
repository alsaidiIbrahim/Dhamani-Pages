import test from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
import {totpCode} from './owner-totp.mjs';
import {matchTotpStep} from './postgres/owner-totp-match.mjs';
test('side-effect-free TOTP matcher returns correct step without consuming code',()=>{
 const secret=randomBytes(32),step=123456,now=step*30000;
 const code=totpCode(secret,step);
 assert.equal(matchTotpStep({secret,code,now}),step);
 assert.equal(matchTotpStep({secret,code,now}),step);
 assert.equal(matchTotpStep({secret,code,now:now+30000}),step);
 assert.equal(matchTotpStep({secret,code,now:now+60000}),null);
});
test('side-effect-free TOTP matcher rejects malformed input',()=>{
 const secret=randomBytes(32);
 assert.equal(matchTotpStep({secret,code:'12345',now:30000}),null);
 assert.equal(matchTotpStep({secret,code:'abcdef',now:30000}),null);
 assert.equal(matchTotpStep({secret,code:'123456',now:-1}),null);
 assert.equal(matchTotpStep({secret:Buffer.alloc(8),code:'123456',now:30000}),null);
});
