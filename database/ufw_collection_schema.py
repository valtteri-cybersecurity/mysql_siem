"""Read-only checks for the persistent collector storage contract."""


def verify(connection, *, continuity=False, filtering=False):
    from database.migrate import MigrationError

    columns = {
        'ufw_quarantine': 'id source_scope raw_sha raw_bytes reason received_at host_id source_id collector_id',
        'ufw_quarantine_origins': 'source_scope file_key byte_position quarantine_id filename file_device file_inode archive_sha',
        'ufw_archives': 'source_scope archive_sha filename file_device file_inode logical_position status checked_at',
        'ufw_archive_failures': 'source_scope source_key filename reason detected_at',
    }
    required = {
        'ufw_quarantine': (0, ('source_scope', 'raw_sha')),
        'ufw_quarantine_origins': (0, ('source_scope', 'file_key', 'byte_position', 'quarantine_id')),
        'ufw_archives': (0, ('source_scope', 'archive_sha')),
        'ufw_archive_failures': (0, ('source_scope', 'source_key')),
    }
    if continuity:
        columns.update({
            'ufw_file_checkpoints': 'id source_scope file_device file_inode filename byte_position prefix_sha observed_size observed_sha status checked_at',
            'ufw_collection_gaps': 'source_scope gap_key checkpoint_id reason detected_at resolved',
            'ufw_archive_proofs': 'source_scope archive_sha expanded_size expanded_sha',
            'ufw_collection_health': 'source_scope last_success last_failure error_class active_state pending_archives stop_reason active_lines archive_lines pass_number plain_backlog',
        })
        required.update({
            'ufw_file_checkpoints': (0, ('id',)),
            'ufw_collection_gaps': (0, ('source_scope', 'gap_key')),
            'ufw_archive_proofs': (0, ('source_scope', 'archive_sha', 'expanded_size')),
            'ufw_collection_health': (0, ('source_scope',)),
        })
    if filtering:
        columns.update({
            'ufw_filter_rules': 'source_id host_id rule_key rule_version definition enabled audit_id',
            'ufw_filter_audit': 'id source_id host_id rule_key rule_version definition enabled actor reason changed_at',
            'ufw_filter_seen': 'source_id event_hash host_id rule_key rule_version event_time recorded_at',
            'ufw_filter_stats': 'source_id host_id rule_key rule_version period_start period_end filtered_count first_event_time last_event_time recorded_at',
        })
        required.update({
            'ufw_filter_rules': (0, ('source_id', 'rule_key')),
            'ufw_filter_audit': (0, ('id',)),
            'ufw_filter_seen': (0, ('source_id', 'event_hash')),
            'ufw_filter_stats': (0, ('source_id', 'rule_key', 'rule_version', 'period_start')),
        })
    with connection.cursor() as cursor:
        for table, names in columns.items():
            cursor.execute('SELECT engine,table_type FROM information_schema.tables '
                           'WHERE table_schema=DATABASE() AND table_name=%s', (table,))
            if cursor.fetchone() != ('InnoDB', 'BASE TABLE'):
                raise MigrationError('Missing or nontransactional UFW collector storage: ' + table)
            cursor.execute('SELECT column_name FROM information_schema.columns '
                           'WHERE table_schema=DATABASE() AND table_name=%s ORDER BY ordinal_position', (table,))
            actual = []
            for row in cursor.fetchall():
                actual.append(row[0])
            if actual != names.split():
                raise MigrationError('Incompatible UFW collector columns: ' + table)
            cursor.execute('SELECT index_name,non_unique,column_name FROM information_schema.statistics '
                           'WHERE table_schema=DATABASE() AND table_name=%s ORDER BY index_name,seq_in_index', (table,))
            indexes = {}
            for name, non_unique, column in cursor.fetchall():
                if name not in indexes:
                    indexes[name] = [non_unique, []]
                indexes[name][1].append(column)
            found = False
            for non_unique, fields in indexes.values():
                if (non_unique, tuple(fields)) == required[table]:
                    found = True
            if not found:
                raise MigrationError('UFW collector replay key is missing: ' + table)
