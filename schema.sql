-- schema.sql
DROP TABLE IF EXISTS submissions;

CREATE TABLE submissions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  submitted_at TEXT NOT NULL, -- Store as TEXT in 'YYYY-MM-DD HH:MM:SS' format
  project_id TEXT NOT NULL,
  submitted_uri TEXT NOT NULL,
  threat_types TEXT NOT NULL, -- Store as JSON string
  operation_name TEXT NOT NULL UNIQUE -- Operation name should be unique
);

-- Optional: Create an index for faster lookups if needed later
-- CREATE INDEX idx_submitted_at ON submissions (submitted_at);