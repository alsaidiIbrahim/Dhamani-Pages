-- PROPOSAL ONLY: shared owner-auth storage; not wired into live application.
-- Run only on a disposable isolated PostgreSQL test database.
-- Never store raw session cookies, TOTP codes, passwords or invoice contents.
BEGIN;
CREATE TABLE IF NOT EXISTS owner_auth_sessions (
 session_hash BYTEA PRIMARY KEY CHECK (octet_length(session_hash)=32),
 owner_id TEXT NOT NULL,
 mfa_verified BOOLEAN NOT NULL DEFAULT FALSE,
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 last_activity_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 expires_at TIMESTAMPTZ NOT NULL,
 revoked_at TIMESTAMPTZ,
 csrf_hash BYTEA CHECK (csrf_hash IS NULL OR octet_length(csrf_hash)=32),
 CHECK (expires_at>created_at),
 CHECK (last_activity_at>=created_at)
);
CREATE INDEX IF NOT EXISTS idx_owner_auth_sessions_expiry ON owner_auth_sessions(expires_at);
CREATE TABLE IF NOT EXISTS owner_auth_challenges (
 challenge_hash BYTEA PRIMARY KEY CHECK (octet_length(challenge_hash)=32),
 owner_id TEXT NOT NULL,
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 expires_at TIMESTAMPTZ NOT NULL,
 failed_attempts SMALLINT NOT NULL DEFAULT 0 CHECK (failed_attempts BETWEEN 0 AND 5),
 consumed_at TIMESTAMPTZ,
 CHECK (expires_at>created_at)
);
CREATE INDEX IF NOT EXISTS idx_owner_auth_challenges_expiry ON owner_auth_challenges(expires_at);
-- Proposed shared replay state: enforce one accepted TOTP time step per owner across nodes.
-- This is not yet connected to the owner login or TOTP verifier.
CREATE TABLE IF NOT EXISTS owner_auth_totp_replay (
 owner_id TEXT PRIMARY KEY,
 last_accepted_step BIGINT NOT NULL CHECK (last_accepted_step >= 0),
 updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- Required before any deployment: transactional challenge consumption,
-- atomic TOTP replay protection shared across nodes, owner credential vault,
-- server-side idle expiration, lockout/rate limits, and cleanup jobs.
COMMIT;
