"""Preserve the measured free space and source of new mount observations."""

from database.migration_steps import columns


def upgrade(connection):
    with connection.cursor() as cursor:
        if 'free_bytes' not in columns(cursor, 'filesystem_mount_metrics'):
            cursor.execute("""
                ALTER TABLE filesystem_mount_metrics
                    ADD COLUMN free_bytes BIGINT UNSIGNED NULL,
                    ADD COLUMN mount_source BLOB NULL,
                    ADD CONSTRAINT chk_filesystem_mount_measured_capacity CHECK (
                        (free_bytes IS NULL AND mount_source IS NULL)
                        OR (free_bytes IS NOT NULL AND mount_source IS NOT NULL
                            AND available_bytes <= free_bytes AND free_bytes <= total_bytes
                            AND OCTET_LENGTH(mount_source) > 0 AND INSTR(mount_source, X'00') = 0)
                    )
            """)
