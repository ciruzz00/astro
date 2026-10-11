-- Log analysis: evidence files read in place, their chain of custody, the
-- events parsed from them and the findings of the detection rules.
CREATE TABLE evidence (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id      INTEGER NOT NULL REFERENCES cases (id) ON DELETE CASCADE,
    path         TEXT    NOT NULL,
    name         TEXT    NOT NULL,
    kind         TEXT    NOT NULL,
    compressed   INTEGER NOT NULL DEFAULT 0,
    size         INTEGER NOT NULL,
    mod_time     INTEGER NOT NULL,
    sha256       TEXT    NOT NULL,
    sha1         TEXT    NOT NULL,
    md5          TEXT    NOT NULL,
    host         TEXT    NOT NULL DEFAULT '',
    events       INTEGER NOT NULL DEFAULT 0,
    parse_errors INTEGER NOT NULL DEFAULT 0,
    truncated    INTEGER NOT NULL DEFAULT 0,
    first_event  INTEGER,
    last_event   INTEGER,
    imported_at  INTEGER NOT NULL,
    UNIQUE (case_id, sha256)
);

-- Append-only: each entry stores the SHA-256 of the previous entry of the
-- same evidence, so any later change breaks the chain.
CREATE TABLE custody_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_id INTEGER NOT NULL REFERENCES evidence (id) ON DELETE CASCADE,
    at          INTEGER NOT NULL,
    action      TEXT    NOT NULL,
    actor       TEXT    NOT NULL,
    detail      TEXT    NOT NULL DEFAULT '',
    prev_hash   TEXT    NOT NULL,
    hash        TEXT    NOT NULL
);
CREATE INDEX custody_log_evidence ON custody_log (evidence_id, id);

CREATE TRIGGER custody_log_no_update BEFORE UPDATE ON custody_log
BEGIN
    SELECT RAISE(ABORT, 'custody log is append-only');
END;

-- Entries go only together with their evidence (case deletion).
CREATE TRIGGER custody_log_no_delete BEFORE DELETE ON custody_log
WHEN EXISTS (SELECT 1 FROM evidence WHERE id = OLD.evidence_id)
BEGIN
    SELECT RAISE(ABORT, 'custody log is append-only');
END;

CREATE TABLE events (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id      INTEGER NOT NULL REFERENCES cases (id) ON DELETE CASCADE,
    evidence_id  INTEGER NOT NULL REFERENCES evidence (id) ON DELETE CASCADE,
    time_ns      INTEGER NOT NULL,
    seq          INTEGER NOT NULL,
    year_guessed INTEGER NOT NULL DEFAULT 0,
    time_unknown INTEGER NOT NULL DEFAULT 0,
    host         TEXT    NOT NULL DEFAULT '',
    source       TEXT    NOT NULL,
    kind         TEXT    NOT NULL,
    event_id     INTEGER NOT NULL DEFAULT 0,
    channel      TEXT    NOT NULL DEFAULT '',
    provider     TEXT    NOT NULL DEFAULT '',
    username     TEXT    NOT NULL DEFAULT '',
    src_ip       TEXT    NOT NULL DEFAULT '',
    dst_ip       TEXT    NOT NULL DEFAULT '',
    process      TEXT    NOT NULL DEFAULT '',
    parent       TEXT    NOT NULL DEFAULT '',
    command_line TEXT    NOT NULL DEFAULT '',
    message      TEXT    NOT NULL DEFAULT '',
    fields       TEXT,
    raw          TEXT    NOT NULL DEFAULT '',
    severity     INTEGER NOT NULL DEFAULT 0,
    record       TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX events_case_time ON events (case_id, time_ns, evidence_id, seq);
CREATE INDEX events_case_host ON events (case_id, host);
CREATE INDEX events_case_user ON events (case_id, username);
CREATE INDEX events_case_src_ip ON events (case_id, src_ip);
CREATE INDEX events_case_event_id ON events (case_id, event_id);
CREATE INDEX events_case_severity ON events (case_id, severity);
CREATE INDEX events_evidence ON events (evidence_id);

CREATE TABLE findings (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id    INTEGER NOT NULL REFERENCES cases (id) ON DELETE CASCADE,
    rule_id    TEXT    NOT NULL,
    title      TEXT    NOT NULL,
    severity   INTEGER NOT NULL,
    technique  TEXT    NOT NULL DEFAULT '',
    first_ns   INTEGER NOT NULL,
    last_ns    INTEGER NOT NULL,
    host       TEXT    NOT NULL DEFAULT '',
    username   TEXT    NOT NULL DEFAULT '',
    src_ip     TEXT    NOT NULL DEFAULT '',
    summary    TEXT    NOT NULL DEFAULT '',
    event_ids  TEXT    NOT NULL DEFAULT '[]',
    created_at INTEGER NOT NULL
);
CREATE INDEX findings_case ON findings (case_id, severity);
