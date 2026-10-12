-- How many events matched a finding (event_ids keeps only the first ones).
ALTER TABLE findings ADD COLUMN count INTEGER NOT NULL DEFAULT 0;
