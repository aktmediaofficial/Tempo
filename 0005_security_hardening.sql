-- Rate-limit counters used by the Worker (login, register, audio tokens, playlist writes).
-- Apply once:  npx wrangler d1 migrations apply akt-media-productions --remote
-- (or paste into the D1 console). Keys are hashed; no raw IPs or emails are stored.

CREATE TABLE IF NOT EXISTS akt_rate_limits (
  key TEXT PRIMARY KEY,
  count INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS akt_rate_limits_expiry_idx
  ON akt_rate_limits(expires_at);
