CREATE TABLE IF NOT EXISTS page_views (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT DEFAULT (datetime('now')),
  country TEXT,
  city TEXT,
  region TEXT,
  timezone TEXT,
  user_agent TEXT,
  referrer TEXT,
  page_url TEXT,
  visitor_id TEXT
);

CREATE INDEX IF NOT EXISTS idx_created_at ON page_views(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_visitor_id ON page_views(visitor_id);

-- Rate limiting buckets (persistent, survives deploys / edge handoffs).
-- One row per (ip, scope, bucket). 'bucket' is the window start as unix seconds.
CREATE TABLE IF NOT EXISTS rate_limits (
  ip TEXT NOT NULL,
  scope TEXT NOT NULL,
  bucket INTEGER NOT NULL,
  count INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (ip, scope, bucket)
);

-- Server-side session store: lets logout actually revoke a token.
CREATE TABLE IF NOT EXISTS sessions (
  jti TEXT PRIMARY KEY,
  exp INTEGER NOT NULL
);
