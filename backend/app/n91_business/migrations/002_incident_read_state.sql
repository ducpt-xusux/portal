CREATE TABLE incident_read_state (
  incident_id TEXT NOT NULL,
  stream_id TEXT NOT NULL,
  execution_mode TEXT NOT NULL,
  user_id TEXT NOT NULL REFERENCES users(user_id),
  is_read INTEGER NOT NULL CHECK(is_read IN (0, 1)),
  version INTEGER NOT NULL CHECK(version > 0),
  updated_at TEXT NOT NULL,
  PRIMARY KEY(incident_id, stream_id, execution_mode, user_id)
);
