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
