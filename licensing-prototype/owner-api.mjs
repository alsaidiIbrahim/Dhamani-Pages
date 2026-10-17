// Owner API router prototype. Intended to be mounted behind authenticated
// TLS reverse proxy; never expose it directly to the public internet.
// No admin credentials, token hashes or invoice data are returned.
export function createOwnerReadHandler({repository,authenticateOwner}){
 if(!repository||typeof authenticateOwner!=='function')throw Error('owner_api_configuration_required');
 const paths=new Map([['/owner/orders','listOrders'],['/owner/licenses','listLicenses'],['/owner/events','listEvents']]);
 return async function handleOwnerRead(req,res){
  const respond=(status,body)=>{
   res.writeHead(status,{'content-type':'application/json; charset=utf-8','cache-control':'no-store','x-content-type-options':'nosniff'});
   res.end(JSON.stringify(body));
  };
  try{
   if(req.method!=='GET')return respond(405,{error:'method_not_allowed'});
   const url=new URL(req.url,'http://localhost');
   const method=paths.get(url.pathname);
   if(!method)return respond(404,{error:'not_found'});
   const owner=await authenticateOwner(req);
   if(!owner||owner.role!=='owner'||owner.active!==true)return respond(403,{error:'forbidden'});
   const limitText=url.searchParams.get('limit')??'50';
   const offsetText=url.searchParams.get('offset')??'0';
   if(!/^[0-9]+$/.test(limitText)||!/^[0-9]+$/.test(offsetText))return respond(400,{error:'invalid_pagination'});
   const limit=Number(limitText),offset=Number(offsetText);
   if(!Number.isSafeInteger(limit)||limit<1||limit>100||!Number.isSafeInteger(offset)||offset<0)return respond(400,{error:'invalid_pagination'});
   const items=await repository[method]({limit,offset});
   return respond(200,{items,limit,offset});
  }catch{
   return respond(500,{error:'internal_error'});
  }
 };
}
