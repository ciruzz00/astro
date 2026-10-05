-- Provider responses cached by indicator.
CREATE TABLE cache (
    provider   TEXT    NOT NULL,
    indicator  TEXT    NOT NULL,
    data       BLOB    NOT NULL,
    fetched_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    PRIMARY KEY (provider, indicator)
);
CREATE INDEX cache_expires_at ON cache (expires_at);

-- Offline datasets bookkeeping.
CREATE TABLE datasets (
    name      TEXT    PRIMARY KEY,
    source    TEXT    NOT NULL,
    version   TEXT    NOT NULL DEFAULT '',
    records   INTEGER NOT NULL,
    synced_at INTEGER NOT NULL
);

-- MITRE ATT&CK objects keyed by external ID (T1059.001, G0032, ...).
CREATE TABLE attack_objects (
    id          TEXT    NOT NULL,
    domain      TEXT    NOT NULL,
    kind        TEXT    NOT NULL,
    subtype     TEXT    NOT NULL DEFAULT '',
    name        TEXT    NOT NULL,
    description TEXT    NOT NULL DEFAULT '',
    url         TEXT    NOT NULL DEFAULT '',
    aliases     TEXT    NOT NULL DEFAULT '[]',
    platforms   TEXT    NOT NULL DEFAULT '[]',
    tactics     TEXT    NOT NULL DEFAULT '[]',
    deprecated  INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (id, domain)
);
CREATE INDEX attack_objects_name ON attack_objects (name COLLATE NOCASE);

CREATE TABLE attack_relations (
    source_id TEXT NOT NULL,
    rel       TEXT NOT NULL,
    target_id TEXT NOT NULL,
    domain    TEXT NOT NULL,
    PRIMARY KEY (source_id, rel, target_id, domain)
);
CREATE INDEX attack_relations_target ON attack_relations (target_id, rel);

-- CISA Known Exploited Vulnerabilities.
CREATE TABLE kev (
    cve_id            TEXT PRIMARY KEY,
    vendor            TEXT NOT NULL DEFAULT '',
    product           TEXT NOT NULL DEFAULT '',
    name              TEXT NOT NULL DEFAULT '',
    date_added        TEXT NOT NULL DEFAULT '',
    due_date          TEXT NOT NULL DEFAULT '',
    short_description TEXT NOT NULL DEFAULT '',
    required_action   TEXT NOT NULL DEFAULT '',
    ransomware        TEXT NOT NULL DEFAULT '',
    notes             TEXT NOT NULL DEFAULT '',
    cwes              TEXT NOT NULL DEFAULT '[]'
);

-- IEEE MAC address block assignments (MA-L, MA-M, MA-S).
CREATE TABLE oui (
    prefix   TEXT PRIMARY KEY,
    registry TEXT NOT NULL,
    org      TEXT NOT NULL,
    address  TEXT NOT NULL DEFAULT ''
);
