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
