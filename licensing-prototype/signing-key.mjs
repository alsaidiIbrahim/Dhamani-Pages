import {readFileSync,statSync} from 'node:fs';
import {createPrivateKey} from 'node:crypto';
// Load from a deployment-mounted secret file, never from the public repository.
export function loadSigningKeyFromFile(path){
 if(!path||typeof path!=='string')throw Error('signing_key_path_required');
 const stat=statSync(path);
 if(!stat.isFile())throw Error('signing_key_not_file');
 if(process.platform!=='win32'&&(stat.mode&0o077)!==0)throw Error('signing_key_permissions_too_broad');
 const pem=readFileSync(path,'utf8');
 const key=createPrivateKey(pem);
 if(key.asymmetricKeyType!=='ed25519')throw Error('signing_key_must_be_ed25519');
 return key;
}
