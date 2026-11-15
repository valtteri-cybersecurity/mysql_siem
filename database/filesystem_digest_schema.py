"""Keep a verified digest during observations that exceed the per-file hash limit."""

from database.migration_steps import columns


def upgrade(connection):
    with connection.cursor() as cursor:
        if 'retained_sha256' not in columns(cursor, 'filesystem_file_state'):
            cursor.execute("""
                ALTER TABLE filesystem_file_state
                    ADD COLUMN retained_sha256 VARBINARY(32) NULL,
                    ADD CONSTRAINT chk_filesystem_file_state_retained_digest CHECK (
                        retained_sha256 IS NULL OR (
                            OCTET_LENGTH(retained_sha256) = 32
                            AND file_type = 'regular' AND content_sha256 IS NULL
                        )
                    )
            """)
