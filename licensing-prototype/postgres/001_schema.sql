-- Dhamani licensing: proposed PostgreSQL schema, NOT deployed.
-- Never store invoice images, OCR output or customer warranty details here.
BEGIN;
CREATE TABLE IF NOT EXISTS license_orders (
 id UUID PRIMARY KEY,
 payment_reference TEXT UNIQUE,
 status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','approved','rejected')),
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 approved_at TIMESTAMPTZ,
 approved_by TEXT,
 CHECK ((status = 'approved' AND approved_at IS NOT NULL AND approved_by IS NOT NULL) OR status <> 'approved')
);
CREATE TABLE IF NOT EXISTS licenses (
 id UUID PRIMARY KEY,
 order_id UUID NOT NULL UNIQUE REFERENCES license_orders(id),
 activation_token_hash BYTEA NOT NULL UNIQUE CHECK (octet_length(activation_token_hash)=32),
 device_public_key TEXT,
 status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','suspended')),
 revision INTEGER NOT NULL DEFAULT 0 CHECK (revision >= 0),
 last_verified_at TIMESTAMPTZ,
 created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS license_events (
 id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 license_id UUID REFERENCES licenses(id),
 order_id UUID REFERENCES license_orders(id),
 actor_id TEXT NOT NULL,
 action TEXT NOT NULL,
 details JSONB NOT NULL DEFAULT '{}'::jsonb,
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 CHECK (license_id IS NOT NULL OR order_id IS NOT NULL)
);
CREATE INDEX IF NOT EXISTS idx_license_events_license_time ON license_events(license_id,created_at DESC);
CREATE INDEX IF NOT EXISTS idx_license_events_order_time ON license_events(order_id,created_at DESC);
COMMIT;
