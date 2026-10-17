// Separate read-only loopback HTTP experiment for PostgreSQL owner sessions.
// No login or cookie issuance, no public binding, no TLS. NOT production-ready.
import {createServer} from 'node:http';
import {ownerSessionAuthenticator} from '../owner-session.mjs';
import {createOwnerReadHandler} from '../owner-api.mjs';
import {createPostgresOwnerSessionAdapter} from './owner-session-adapter.mjs';
export function createPostgresOwnerReadHttpHandler({sessionRepository,licenseRepository}={}){
 if(!sessionRepository||!licenseRepository)throw Error('missing_dependencies');
 const sessions=createPostgresOwnerSessionAdapter(sessionRepository);
 const authenticateOwner=ownerSessionAuthenticator(sessions);
 const readOwner=createOwnerReadHandler({repository:licenseRepository,authenticateOwner});
 return async(req,res)=>{
  const respond=(status,body)=>{res.writeHead(status,{'content-type':'application/json; charset=utf-8','cache-control':'no-store','x-content-type-options':'nosniff'});res.end(JSON.stringify(body));};
  try{
   const host=req.headers?.host;
   if(typeof host!=='string'||host!==`127.0.0.1:${req.socket?.localPort}`)return respond(403,{error:'forbidden'});
   const origin=req.headers?.origin;
   if(origin!==undefined&&origin!==`http://${host}`)return respond(403,{error:'forbidden'});
   const site=req.headers?.['sec-fetch-site'];
   if(site!==undefined&&site!=='same-origin'&&site!=='none')return respond(403,{error:'forbidden'});
   if(req.method!=='GET')return respond(405,{error:'method_not_allowed'});
   if(!['/owner/orders','/owner/licenses','/owner/events'].includes(String(req.url||'').split('?')[0]))return respond(404,{error:'not_found'});
   return await readOwner(req,res);
  }catch{return respond(500,{error:'internal_error'});}
 };
}
export function startLoopbackPostgresOwnerReadServer({sessionRepository,licenseRepository,port=0}={}){
 const server=createServer(createPostgresOwnerReadHttpHandler({sessionRepository,licenseRepository}));
 return new Promise((resolve,reject)=>{server.once('error',reject);server.listen(port,'127.0.0.1',()=>resolve(server));});
}
