-- Applied only by the migration runner after inspecting each current column.
-- Existing events, IDs, hashes, identities and checkpoints are preserved.
ALTER TABLE auth_events MODIFY COLUMN source_ip VARCHAR(45) CHARACTER SET ascii COLLATE ascii_bin NULL;
ALTER TABLE auth_events ADD COLUMN auth_method VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin NULL;
ALTER TABLE auth_events ADD COLUMN source_port SMALLINT UNSIGNED NULL;
