// Loopback-only demo runner. Never use real customer or owner credentials.
import {randomBytes} from 'node:crypto';
import {OwnerLoginPrototype,createPasswordVerifier} from './owner-login.mjs';
import {OwnerSessionStore} from './owner-session.mjs';
import {OwnerTotpVerifier,totpCode} from './owner-totp.mjs';
import {startLoopbackOwnerLoginServer} from './owner-login-http.mjs';
const now=()=>Date.now();
const password=randomBytes(18).toString('base64url');
const secret=randomBytes(32);
const sessionStore=new OwnerSessionStore({now});
const totpVerifier=new OwnerTotpVerifier({secret,now});
const login=new OwnerLoginPrototype({ownerId:'DEMO-OWNER',passwordRecord:createPasswordVerifier(password),sessionStore,totpVerifier,now});
const repository={
 async listOrders(){return [{id:'DEMO-ORDER-001',status:'pending',payment_reference:'DEMO-PAY-001'}];},
 async listLicenses(){return [{id:'DEMO-LICENSE-001',status:'active',device_bound:false}];},
 async listEvents(){return [{event_type:'demo_created',created_at:'2026-10-17',license_id:'DEMO-LICENSE-001'}];}
};
const server=await startLoopbackOwnerLoginServer({login,totpVerifier,sessionStore,repository});
const base='http://127.0.0.1:'+server.address().port;
console.log('LOCAL DEMO ONLY — no production data or network access');
console.log('URL: '+base+'/owner/dashboard');
console.log('Password: '+password);
console.log('TOTP demo code (refreshes every 30 seconds): '+totpCode(secret,Math.floor(now()/30000)));
console.log('The dashboard requires login through the HTTP endpoints. This runner does not provide a browser login form.');
const timer=setInterval(()=>console.log('Demo TOTP: '+totpCode(secret,Math.floor(now()/30000))),30000);
timer.unref();
for(const signal of ['SIGINT','SIGTERM'])process.once(signal,()=>server.close(()=>process.exit(0)));
