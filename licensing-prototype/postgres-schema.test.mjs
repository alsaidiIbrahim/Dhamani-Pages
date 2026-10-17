import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
const schema=readFileSync(new URL('./postgres/001_schema.sql',import.meta.url),'utf8');
const tx=readFileSync(new URL('./postgres/002_transaction_examples.sql',import.meta.url),'utf8');
test('proposed PostgreSQL schema separates orders, licenses and events',()=>{
 for(const table of ['license_orders','licenses','license_events'])assert.match(schema,new RegExp('CREATE TABLE IF NOT EXISTS '+table));
 assert.match(schema,/activation_token_hash BYTEA NOT NULL UNIQUE/);
 assert.match(schema,/order_id UUID NOT NULL UNIQUE REFERENCES license_orders/);
 assert.match(schema,/CHECK \(revision >= 0\)/);
 assert.doesNotMatch(schema,/invoice_images|ocr_text|warranty_receipts/i);
});
test('approval and transfer transaction examples lock rows',()=>{
 assert.equal((tx.match(/FOR UPDATE/g)||[]).length,2);
 assert.match(tx,/revision=revision\+1/);
 assert.match(tx,/status='pending'/);
});
