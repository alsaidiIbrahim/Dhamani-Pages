import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
const source=readFileSync(new URL('./run-owner-local-demo.mjs',import.meta.url),'utf8');
test('local demo uses ephemeral credentials, fake records, and loopback server',()=>{
 assert.match(source,/randomBytes\(18\)/);
 assert.match(source,/randomBytes\(32\)/);
 assert.match(source,/startLoopbackOwnerLoginServer/);
 assert.match(source,/DEMO-ORDER-001/);
 assert.match(source,/DEMO-LICENSE-001/);
 assert.doesNotMatch(source,/DATABASE_URL|process\.env|0\.0\.0\.0|BEGIN PRIVATE KEY/);
});
