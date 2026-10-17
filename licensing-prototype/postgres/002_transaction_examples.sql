-- Illustrative transactions. Parameters :order_id, :admin_id, :license_id, :new_device_key
-- must be bound by server-side parameterized queries; not executable directly in psql.
-- Approve payment only after independently verifying payment reference.
BEGIN;
SELECT id FROM license_orders WHERE id=:order_id AND status='pending' FOR UPDATE;
UPDATE license_orders SET status='approved',approved_at=now(),approved_by=:admin_id
 WHERE id=:order_id AND status='pending';
-- The server must assert exactly one row changed before continuing.
-- INSERT license with server-generated id and SHA-256 activation token hash.
-- INSERT audit event in same transaction.
COMMIT;

-- Transfer only after authenticated owner authorization and new-device challenge proof.
BEGIN;
SELECT id,revision FROM licenses WHERE id=:license_id AND status='active' FOR UPDATE;
-- Verify signed device proof against the selected revision BEFORE update.
UPDATE licenses SET device_public_key=:new_device_key,revision=revision+1,last_verified_at=NULL
 WHERE id=:license_id AND status='active';
-- The server must assert exactly one row changed and insert an audit event.
COMMIT;
