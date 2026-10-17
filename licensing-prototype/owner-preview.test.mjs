import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
const page=readFileSync(new URL('./owner-preview/index.html',import.meta.url),'utf8');
test('owner preview is Arabic RTL and clearly mock-only',()=>{
 assert.match(page,/<html lang="ar" dir="rtl">/);
 assert.match(page,/بيانات توضيحية فقط/);
 assert.match(page,/غير متصلة/);
 for(const section of ['طلبات الشراء','التراخيص','سجل العمليات'])assert.ok(page.includes(section));
 assert.match(page,/DEMO-LIC-01/);
 assert.doesNotMatch(page,/activation_token_hash|BEGIN PRIVATE KEY|x-admin-token|DATABASE_URL/);
 assert.doesNotMatch(page,/<script\b/i);
});
