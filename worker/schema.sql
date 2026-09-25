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
  visitor_id TEXT,
  device_type TEXT,
  os TEXT,
  browser TEXT,
  latitude REAL,
  longitude REAL,
  postal_code TEXT,
  isp TEXT,
  language TEXT,
  ip_hash TEXT,
  colo TEXT
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
  extra TEXT,
  section TEXT,
  cls TEXT,
  href TEXT
);

CREATE INDEX IF NOT EXISTS idx_eng_visitor ON page_engagement(visitor_id);
CREATE INDEX IF NOT EXISTS idx_eng_session ON page_engagement(session_id);
CREATE INDEX IF NOT EXISTS idx_eng_type ON page_engagement(event_type);

-- Reversible manual identity grouping. Source IDs on visits/events remain immutable.
CREATE TABLE IF NOT EXISTS visitor_identity_links (
  visitor_id TEXT PRIMARY KEY,
  canonical_id TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  CHECK (visitor_id != canonical_id)
);
CREATE INDEX IF NOT EXISTS idx_identity_canonical ON visitor_identity_links(canonical_id);
CREATE TRIGGER IF NOT EXISTS identity_target_must_be_canonical_insert
BEFORE INSERT ON visitor_identity_links
WHEN EXISTS (SELECT 1 FROM visitor_identity_links WHERE visitor_id = NEW.canonical_id)
BEGIN SELECT RAISE(ABORT, 'target_not_canonical'); END;
CREATE TRIGGER IF NOT EXISTS identity_target_must_be_canonical_update
BEFORE UPDATE OF canonical_id ON visitor_identity_links
WHEN EXISTS (SELECT 1 FROM visitor_identity_links WHERE visitor_id = NEW.canonical_id)
BEGIN SELECT RAISE(ABORT, 'target_not_canonical'); END;

CREATE TABLE IF NOT EXISTS visitor_identity_events (
  id TEXT PRIMARY KEY,
  action TEXT NOT NULL CHECK (action IN ('merge', 'separate')),
  source_id TEXT NOT NULL,
  target_id TEXT,
  affected_ids TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_identity_events_created ON visitor_identity_events(created_at DESC);

-- Per-visit corrections for destructive legacy merges. The original row is unchanged.
CREATE TABLE IF NOT EXISTS visitor_visit_overrides (
  page_view_id INTEGER PRIMARY KEY REFERENCES page_views(id) ON DELETE CASCADE,
  profile_id TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_visit_override_profile ON visitor_visit_overrides(profile_id);

CREATE TABLE IF NOT EXISTS visitor_visit_events (
  id TEXT PRIMARY KEY,
  action TEXT NOT NULL CHECK (action IN ('move', 'restore')),
  page_view_id INTEGER NOT NULL,
  original_id TEXT NOT NULL,
  profile_id TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_visit_events_created ON visitor_visit_events(created_at DESC);
