-- Investigations: indicators with their last search results, notes and tags.
CREATE TABLE cases (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT    NOT NULL UNIQUE,
    title       TEXT    NOT NULL DEFAULT '',
    description TEXT    NOT NULL DEFAULT '',
    tlp         TEXT    NOT NULL DEFAULT 'AMBER',
    status      TEXT    NOT NULL DEFAULT 'open',
    created_at  INTEGER NOT NULL,
    updated_at  INTEGER NOT NULL
);

CREATE TABLE case_tags (
    case_id INTEGER NOT NULL REFERENCES cases (id) ON DELETE CASCADE,
    tag     TEXT    NOT NULL,
    PRIMARY KEY (case_id, tag)
);

CREATE TABLE case_items (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id     INTEGER NOT NULL REFERENCES cases (id) ON DELETE CASCADE,
    type        TEXT    NOT NULL,
    value       TEXT    NOT NULL,
    note        TEXT    NOT NULL DEFAULT '',
    verdict     TEXT    NOT NULL DEFAULT '',
    report      BLOB,
    searched_at INTEGER,
    added_at    INTEGER NOT NULL,
    UNIQUE (case_id, type, value)
);

CREATE TABLE case_notes (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id    INTEGER NOT NULL REFERENCES cases (id) ON DELETE CASCADE,
    body       TEXT    NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE INDEX case_notes_case ON case_notes (case_id);
