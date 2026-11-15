"""Allow directory metadata in the FIM baseline."""


def upgrade(connection):
    with connection.cursor() as cursor:
        cursor.execute("""
            SELECT 1 FROM information_schema.table_constraints
            WHERE table_schema = DATABASE() AND table_name = 'filesystem_file_state'
                AND constraint_name = 'chk_filesystem_file_state_directory'
        """)
        if cursor.fetchone() is None:
            cursor.execute("""
                ALTER TABLE filesystem_file_state
                    DROP CHECK chk_filesystem_file_state_type,
                    MODIFY COLUMN file_type VARCHAR(9) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT 'regular',
                    ADD CONSTRAINT chk_filesystem_file_state_directory CHECK (
                        file_type = 'regular' OR (file_type IN ('symlink', 'directory') AND content_sha256 IS NULL)
                    )
            """)
