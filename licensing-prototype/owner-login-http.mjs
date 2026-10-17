// Test-only loopback HTTP login handler. Do not expose to public networks.
// TLS, CSRF defenses, persistent rate limits, secure secret storage, and
// production-grade identity lifecycle are NOT implemented.
import {createServer} from 'node:http';
import {ownerSessionAuthenticator} from './owner-session.mjs';
function reply(res,status,body,headers={}){res.writeHead(status,{'content-type':'application/json; charset=utf-8','cache-control':'no-store','x-content-type-options':'nosniff',...headers});res.end(JSON.stringify(body));}
async function jsonBody(req){
 const chunks=[];let length=0;
 for await(const chunk of req){length+=chunk.length;if(length>4096)throw Error('body_too_large');chunks.push(chunk);}
 const raw=Buffer.concat(chunks).toString('utf8');
 const data=JSON.parse(raw);
 if(!data||typeof data!=='object'||Array.isArray(data))throw Error('invalid_json');
 return data;
}
export function createOwnerLoginHttpHandler({login,totpVerifier,sessionStore}={}){
 if(!login||!totpVerifier||!sessionStore)throw Error('missing_dependencies');
 const authenticate=ownerSessionAuthenticator(sessionStore);
 return async(req,res)=>{
  try{
   if(req.method==='POST'&&req.url==='/owner/login/password'){
    const body=await jsonBody(req);
    const result=login.verifyFirstFactor(body.password);
    return reply(res,result.ok?200:401,result.ok?{challenge:result.challenge}:{error:'invalid_credentials'});
   }
   if(req.method==='POST'&&req.url==='/owner/login/totp'){
    const body=await jsonBody(req);
    let token;
    try{token=login.verifyTotpAndIssueSession({challenge:body.challenge,totpCode:body.code,totpVerifier});}
    catch{return reply(res,401,{error:'invalid_credentials'});}
    return reply(res,200,{authenticated:true},{'set-cookie':`dhamani_owner_session=${token}; HttpOnly; SameSite=Strict; Path=/owner; Max-Age=1800`});
   }
   if(req.method==='POST'&&req.url==='/owner/logout'){
    const auth=await authenticate(req);
    if(!auth)return reply(res,403,{error:'forbidden'});
    const cookies=String(req.headers?.cookie||'').split(';').map(x=>x.trim());
    const cookie=cookies.find(x=>x.startsWith('dhamani_owner_session='));
    if(cookie)sessionStore.revoke(cookie.slice('dhamani_owner_session='.length));
    return reply(res,200,{authenticated:false},{'set-cookie':'dhamani_owner_session=; HttpOnly; SameSite=Strict; Path=/owner; Max-Age=0'});
   }
   return reply(res,404,{error:'not_found'});
  }catch{return reply(res,400,{error:'invalid_request'});}
 };
}
export function startLoopbackOwnerLoginServer({login,totpVerifier,sessionStore,port=0}={}){
 const server=createServer(createOwnerLoginHttpHandler({login,totpVerifier,sessionStore}));
 return new Promise((resolve,reject)=>{
  server.once('error',reject);
  server.listen(port,'127.0.0.1',()=>resolve(server));
 });
}
