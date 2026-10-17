// Promise-based adapter to bridge the isolated PostgreSQL session repository
// to the same token-first interface as the local in-memory session store.
// This does not mount any HTTP route or expose sessions to the internet.
export function createPostgresOwnerSessionAdapter(repository){
 if(!repository||!['verify','expiresAt','issueCsrf','verifyCsrf','revokeWithCsrf','revoke'].every(k=>typeof repository[k]==='function'))throw Error('invalid_owner_session_repository');
 return Object.freeze({
  verify:token=>repository.verify({token}),
  expiresAt:token=>repository.expiresAt({token}),
  issueCsrf:token=>repository.issueCsrf({token}),
  verifyCsrf:(token,csrf)=>repository.verifyCsrf({token,csrf}),
  revokeWithCsrf:(token,csrf)=>repository.revokeWithCsrf({token,csrf}),
  revoke:token=>repository.revoke({token})
 });
}
