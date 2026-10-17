import {readFileSync,writeFileSync,renameSync,openSync,closeSync,fsyncSync,existsSync,mkdirSync} from 'node:fs';
import {dirname,resolve} from 'node:path';
const VERSION=1;
// Test-only JSON persistence; a transactional DB is required for production.
export class PrototypeStore {
 constructor(path){this.path=resolve(path);}
 save(engine){
  const state={version:VERSION,orders:[...engine.orders],licenses:[...engine.licenses],audit:engine.audit,auditHead:engine.auditHead};
  const folder=dirname(this.path);mkdirSync(folder,{recursive:true});
  const tmp=this.path+'.tmp';
  const fd=openSync(tmp,'w',0o600);
  try{writeFileSync(fd,JSON.stringify(state));fsyncSync(fd);}finally{closeSync(fd);}
  renameSync(tmp,this.path);
  // Best effort directory sync for durable rename on supporting platforms.
  try{const d=openSync(folder,'r');try{fsyncSync(d)}finally{closeSync(d)}}catch{}
 }
 load(engine){
  if(!existsSync(this.path))return false;
  const data=JSON.parse(readFileSync(this.path,'utf8'));
  if(data.version!==VERSION||!Array.isArray(data.orders)||!Array.isArray(data.licenses)||!Array.isArray(data.audit))throw Error('unsupported_or_invalid_state');
  for(const [id,o] of data.orders)if(typeof id!=='string'||!o||o.id!==id)throw Error('invalid_order');
  for(const [id,l] of data.licenses)if(typeof id!=='string'||!l||l.id!==id||typeof l.tokenHash!=='string')throw Error('invalid_license');
  const candidate={audit:data.audit,auditHead:data.auditHead??'GENESIS',verifyAudit:engine.verifyAudit};
  if(!candidate.verifyAudit())throw Error('invalid_audit_chain');
  const orders=new Map(data.orders),licenses=new Map(data.licenses);
  engine.orders=orders;engine.licenses=licenses;engine.audit=data.audit;engine.auditHead=candidate.auditHead;
  // Never persist short-lived challenges. Restart invalidates outstanding challenges.
  engine.challenges.clear();
  return true;
 }
}
