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
