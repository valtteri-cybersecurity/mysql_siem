"""Store FIM file types and allow verified type-change events."""

from database.migration_steps import columns


def upgrade(connection):
    with connection.cursor() as cursor:
        if 'file_type' not in columns(cursor, 'filesystem_file_state'):
            cursor.execute("""
                ALTER TABLE filesystem_file_state
                    ADD COLUMN file_type VARCHAR(7) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT 'regular',
                    ADD CONSTRAINT chk_filesystem_file_state_type CHECK (
                        file_type = 'regular' OR (file_type = 'symlink' AND content_sha256 IS NULL)
                    )
            """)
        cursor.execute("""
            SELECT 1 FROM information_schema.table_constraints
            WHERE table_schema = DATABASE() AND table_name = 'filesystem_file_events'
                AND constraint_name = 'chk_filesystem_file_event_typed_state'
        """)
        if cursor.fetchone() is None:
            cursor.execute("""
                ALTER TABLE filesystem_file_events
                    DROP CHECK chk_filesystem_file_event_state,
                    ADD CONSTRAINT chk_filesystem_file_event_typed_state CHECK (
                        (previous_state IS NULL OR JSON_TYPE(previous_state) = 'OBJECT')
                        AND (current_state IS NULL OR JSON_TYPE(current_state) = 'OBJECT')
                        AND (
                            (event_type = 'CREATED' AND previous_state IS NULL AND current_state IS NOT NULL)
                            OR (event_type = 'DELETED' AND previous_state IS NOT NULL AND current_state IS NULL)
                            OR (event_type IN ('CONTENT_CHANGED', 'PERMISSION_CHANGED', 'OWNER_CHANGED')
                                AND previous_state IS NOT NULL AND current_state IS NOT NULL)
                            OR (event_type = 'TYPE_CHANGED' AND previous_state IS NOT NULL AND current_state IS NOT NULL
                                AND COALESCE(previous_state->>'$.file_type', '') IN ('regular', 'symlink')
                                AND COALESCE(current_state->>'$.file_type', '') IN ('regular', 'symlink')
                                AND NOT (previous_state->>'$.file_type' <=> current_state->>'$.file_type'))
                        )
                    )
            """)
