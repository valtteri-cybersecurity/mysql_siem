-- An unknown boot stays NULL until the first complete process observation.
ALTER TABLE collector_snapshots
    ADD COLUMN process_boot_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NULL;
