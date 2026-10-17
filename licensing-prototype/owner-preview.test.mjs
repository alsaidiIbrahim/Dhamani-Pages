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
 assert.match(page,/حالة لوحة الإدارة/);
 assert.match(page,/غير متاح في هذه المعاينة العامة/);
 assert.match(page,/لا يمكن اعتماد دفعات/);
 assert.match(page,/ليس صفحة تسجيل دخول/);
 assert.doesNotMatch(page,/activation_token_hash|BEGIN PRIVATE KEY|x-admin-token|DATABASE_URL/);
 assert.doesNotMatch(page,/<script\b/i);
});
