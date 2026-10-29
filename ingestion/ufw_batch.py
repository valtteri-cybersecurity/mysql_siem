"""Bounded, strict INSERT batches; errors propagate to the checkpoint transaction."""
import hashlib

from database.identity import identity_schema_enabled
from ingestion.ufw_filters import match, record_counts

MAX_ROWS = 256
MAX_BYTES = 256 * 1024
FIELDS = 'event_time action src_ip dst_ip protocol src_port dst_port raw_line event_hash'


def event_values(line, parsed, identity):
    clean = line.strip()
    digest = hashlib.sha256(clean.encode('utf-8')).hexdigest()
    values = (parsed['event_time'], parsed['action'], parsed['src_ip'], parsed['dst_ip'], parsed['protocol'],
              parsed['src_port'], parsed['dst_port'], clean, digest)
    if identity is not None:
        values += identity.values() + (identity.source_id, parsed.get('reported_hostname'))
    return digest, values


class EventBatch:
    def __init__(self, cursor, identity, enabled, stats):
        self.cursor = cursor
        self.identity = identity
        self.enabled = enabled
        self.stats = stats
        self.rows = []
        self.byte_count = 0
        self.inserted = 0
        self.scoped = identity is not None or identity_schema_enabled(cursor.connection)

    def add(self, line, parsed):
        size = len(line.encode('utf-8'))
        if self.rows and self.byte_count + size > MAX_BYTES:
            self.flush()
        digest, values = event_values(line, parsed, self.identity)
        self.rows.append((digest, values, parsed, line))
        self.byte_count += size
        if len(self.rows) >= MAX_ROWS or self.byte_count >= MAX_BYTES:
            self.flush()

    def flush(self):
        if not self.rows:
            return
        unique = {}
        frequencies = {}
        for digest, values, parsed, line in self.rows:
            if digest not in unique:
                unique[digest] = (values, parsed, line)
                frequencies[digest] = 0
            frequencies[digest] += 1
        hashes = tuple(unique)
        placeholders = ','.join(['%s'] * len(hashes))
        sql = 'SELECT event_hash FROM ufw_log WHERE event_hash IN (' + placeholders + ')'
        parameters = hashes
        scope = 0
        if self.identity is not None:
            scope = self.identity.source_id
        if self.scoped:
            sql += ' AND source_scope=%s'
            parameters += (scope,)
        self.cursor.execute(sql, parameters)
        stored = set()
        for row in self.cursor.fetchall():
            stored.add(row[0])
        filtered = set()
        if self.identity is not None:
            binary_hashes = []
            for digest in hashes:
                binary_hashes.append(bytes.fromhex(digest))
            self.cursor.execute('SELECT event_hash FROM ufw_filter_seen WHERE source_id=%s AND event_hash IN ('
                                + placeholders + ')', (scope,) + tuple(binary_hashes))
            for row in self.cursor.fetchall():
                filtered.add(row[0].hex())
        normal = []
        excluded = []
        duplicates = 0
        for digest, (values, parsed, line) in unique.items():
            if digest in stored and digest in filtered:
                raise RuntimeError('UFW_EVENT_EXISTS_IN_RAW_AND_FILTER_HISTORY')
            if digest in stored or digest in filtered:
                duplicates += frequencies[digest]
                continue
            duplicates += frequencies[digest] - 1
            if self.enabled and match(line, parsed) == 'MATCH':
                excluded.append((digest, parsed))
            else:
                normal.append(values)
        if normal:
            fields = FIELDS
            if self.identity is not None:
                fields += ' host_id source_id collector_id sender_id source_scope reported_hostname'
            placeholders = ','.join(['%s'] * len(normal[0]))
            self.cursor.executemany('INSERT INTO ufw_log (' + ','.join(fields.split()) + ') VALUES (' + placeholders + ')', normal)
        if excluded:
            record_counts(self.cursor, self.identity, excluded)
        self.inserted += len(normal)
        self.stats['duplicates'] = self.stats.get('duplicates', 0) + duplicates
        self.stats['filtered'] = self.stats.get('filtered', 0) + len(excluded)
        self.rows.clear()
        self.byte_count = 0
