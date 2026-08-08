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

-- Engagement tracking: heartbeats, clicks, pagehide events per session.
CREATE TABLE IF NOT EXISTS page_engagement (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT DEFAULT (datetime('now')),
  visitor_id TEXT NOT NULL,
  session_id TEXT NOT NULL,
  event_type TEXT NOT NULL,
  page_url TEXT,
  x INTEGER,
  y INTEGER,
  target TEXT,
  extra TEXT
);

CREATE INDEX IF NOT EXISTS idx_eng_visitor ON page_engagement(visitor_id);
CREATE INDEX IF NOT EXISTS idx_eng_session ON page_engagement(session_id);
CREATE INDEX IF NOT EXISTS idx_eng_type ON page_engagement(event_type);
