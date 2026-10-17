import http from 'node:http';
import {LicenseEngine} from './engine.mjs';
const send=(res,status,data)=>{res.writeHead(status,{'content-type':'application/json; charset=utf-8','cache-control':'no-store','x-content-type-options':'nosniff'});res.end(JSON.stringify(data));};
const readBody=async req=>{
 let bytes=0,parts=[];
 for await(const chunk of req){bytes+=chunk.length;if(bytes>8192)throw Error('request_too_large');parts.push(chunk);}
 return JSON.parse(Buffer.concat(parts).toString('utf8')||'{}');
};
// Only bind to loopback; no public network listener, TLS or persistent database.
export function createPrototypeServer({engine=new LicenseEngine(),adminToken}={}){
 if(typeof adminToken!=='string'||adminToken.length<24)throw Error('strong_admin_token_required');
 const server=http.createServer(async(req,res)=>{
  if(req.url==='/health'&&req.method==='GET')return send(res,200,{status:'prototype_only'});
  const routes={
   'POST /orders':{admin:false,run:b=>engine.order()},
   'POST /admin/approve':{admin:true,run:b=>engine.approve(b.orderId)},
   'POST /admin/transfer':{admin:true,run:b=>engine.transfer(b.licenseId,b.devicePublicKey)},
   'POST /admin/suspend':{admin:true,run:b=>{engine.suspend(b.licenseId);return {ok:true}}},
   'POST /challenge':{admin:false,run:b=>engine.issueChallenge(b.activationToken,b.devicePublicKey,b.purpose)},
   'POST /complete':{admin:false,run:b=>engine.completeChallenge(b.activationToken,b.challengeId,b.signature)}
  };
  const route=routes[req.method+' '+req.url];
  if(!route)return send(res,404,{error:'not_found'});
  // Prototype-only fixed admin secret; do not expose over the public internet.
  if(route.admin&&req.headers['x-admin-token']!==adminToken)return send(res,403,{error:'forbidden'});
  try{return send(res,200,route.run(await readBody(req)))}catch(e){
   return send(res,e.message==='request_too_large'?413:400,{error:e.message==='request_too_large'?'request_too_large':'invalid_request'});
  }
 });
 return {server,listen:()=>new Promise(resolve=>server.listen(0,'127.0.0.1',()=>resolve(server.address()))),engine};
}
