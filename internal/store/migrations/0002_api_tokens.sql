-- REST API bearer tokens. Only the SHA-256 of a token is stored.
CREATE TABLE api_tokens (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    name         TEXT    NOT NULL UNIQUE,
    hash         BLOB    NOT NULL UNIQUE,
    prefix       TEXT    NOT NULL,
    created_at   INTEGER NOT NULL,
    last_used_at INTEGER,
    revoked_at   INTEGER
);
