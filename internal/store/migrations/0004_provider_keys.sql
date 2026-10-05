-- API keys of intelligence providers set from the web interface or the CLI.
-- The database file is created with owner-only permissions.
CREATE TABLE provider_keys (
    name       TEXT    PRIMARY KEY,
    value      TEXT    NOT NULL,
    updated_at INTEGER NOT NULL
);
