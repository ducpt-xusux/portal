-- Portal-owned DB only. Applied inside one explicit transaction after ownership check.
CREATE TABLE IF NOT EXISTS business_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS cursor_key (singleton INTEGER PRIMARY KEY CHECK(singleton=1), secret TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS users (
  user_id TEXT PRIMARY KEY, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL,
  roles TEXT NOT NULL, portal_admin INTEGER NOT NULL DEFAULT 0, active INTEGER NOT NULL DEFAULT 1,
  version INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(user_id),
  created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, revoked INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS sessions_user ON sessions(user_id);
CREATE TABLE IF NOT EXISTS login_limits (bucket TEXT PRIMARY KEY, start INTEGER NOT NULL, attempts INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS overlays (
  kind TEXT NOT NULL, object_id TEXT NOT NULL, stream_id TEXT NOT NULL, execution_mode TEXT NOT NULL,
  review_state TEXT NOT NULL, acknowledged INTEGER NOT NULL, assignee_id TEXT REFERENCES users(user_id),
  priority TEXT NOT NULL, version INTEGER NOT NULL, updated_at TEXT, actor_id TEXT,
  PRIMARY KEY(kind, object_id, stream_id, execution_mode)
);
CREATE TABLE IF NOT EXISTS notes (
  note_id TEXT PRIMARY KEY, incident_id TEXT NOT NULL, stream_id TEXT NOT NULL, execution_mode TEXT NOT NULL,
  note TEXT NOT NULL, actor_id TEXT NOT NULL REFERENCES users(user_id), created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS notes_scope ON notes(incident_id, stream_id, execution_mode, created_at, note_id);
CREATE TABLE IF NOT EXISTS admin_audit (
  seq INTEGER PRIMARY KEY AUTOINCREMENT, audit_id TEXT NOT NULL UNIQUE, actor_id TEXT NOT NULL,
  action TEXT NOT NULL, target_ref TEXT, outcome TEXT NOT NULL, timestamp TEXT NOT NULL,
  request_id TEXT NOT NULL, before_json TEXT, after_json TEXT
);
CREATE TABLE IF NOT EXISTS idempotency (
  actor_id TEXT NOT NULL, key_hash TEXT NOT NULL, fingerprint TEXT NOT NULL,
  result_json TEXT NOT NULL, created_at TEXT NOT NULL, PRIMARY KEY(actor_id, key_hash)
);
