"""Bounded, strict INSERT batches; errors propagate to the checkpoint transaction."""
import hashlib

from ingestion.ufw_filters import match, record_counts

MAX_ROWS = 256
MAX_BYTES = 256 * 1024
class OccurrenceConflict(RuntimeError):
    """A source occurrence cannot be safely attributed or replayed."""


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
    def __init__(self, cursor, identity, enabled, stats, *, generation):
        if not isinstance(generation, bytes) or len(generation) != 32 or generation == bytes(32):
            raise ValueError('Invalid UFW file generation.')
        self.generation = generation
        self.cursor = cursor
        self.identity = identity
        self.enabled = enabled
        self.stats = stats
        self.rows = []
        self.byte_count = 0
        self.inserted = 0

    def add(self, line, parsed, *, position=None):
        if type(position) is not int or position < 0:
            raise ValueError('UFW occurrence requires a nonnegative byte position.')
        size = len(line.encode('utf-8'))
        if self.rows and self.byte_count + size > MAX_BYTES:
            self.flush()
        digest, values = event_values(line, parsed, self.identity)
        self.rows.append((digest, values, parsed, line, position))
        self.byte_count += size
        if len(self.rows) >= MAX_ROWS or self.byte_count >= MAX_BYTES:
            self.flush()

    def flush(self):
        """Replay by generation and offset; content alone never proves identity."""
        if not self.rows:
            return
        scope = 0
        if self.identity is not None:
            scope = self.identity.source_id
        positions = []
        hashes = []
        for digest, _values, _parsed, _line, position in self.rows:
            positions.append(position)
            hashes.append(digest)
        placeholders = ','.join(['%s'] * len(positions))
        self.cursor.execute('SELECT file_position,event_hash FROM ufw_log WHERE source_scope=%s '
                            'AND file_generation=%s AND file_position IN (' + placeholders + ')',
                            (scope, self.generation) + tuple(positions))
        stored = {}
        for position, digest in self.cursor.fetchall():
            stored[position] = digest
        filtered = {}
        if self.identity is not None:
            self.cursor.execute('SELECT file_position,event_hash FROM ufw_filter_seen WHERE source_id=%s '
                                'AND file_generation=%s AND file_position IN (' + placeholders + ')',
                                (scope, self.generation) + tuple(positions))
            for position, digest in self.cursor.fetchall():
                filtered[position] = digest.hex()
        # Another file, an unbound legacy row or a recompressed archive is not proof
        # of replay. Stop visibly rather than silently discard or double-count it.
        self.cursor.execute('SELECT event_hash FROM ufw_log WHERE source_scope=%s '
                            'AND (file_generation IS NULL OR file_generation<>%s) '
                            'AND event_hash IN (' + placeholders + ')',
                            (scope, self.generation) + tuple(hashes))
        ambiguous = set()
        for row in self.cursor.fetchall():
            ambiguous.add(row[0])
        if self.identity is not None:
            binary_hashes = []
            for digest in hashes:
                binary_hashes.append(bytes.fromhex(digest))
            self.cursor.execute('SELECT event_hash FROM ufw_filter_seen WHERE source_id=%s '
                                'AND file_generation<>%s AND event_hash IN (' + placeholders + ')',
                                (scope, self.generation) + tuple(binary_hashes))
            for row in self.cursor.fetchall():
                ambiguous.add(row[0].hex())
        normal = []
        excluded = []
        duplicates = 0
        for digest, values, parsed, _line, position in self.rows:
            if position in stored and position in filtered:
                raise OccurrenceConflict('UFW_OCCURRENCE_IN_RAW_AND_FILTER_HISTORY')
            previous = stored.get(position)
            if previous is None:
                previous = filtered.get(position)
            if previous is not None:
                if previous != digest:
                    raise OccurrenceConflict('UFW_OCCURRENCE_CONTENT_CHANGED')
                duplicates += 1
                continue
            if digest in ambiguous:
                raise OccurrenceConflict('UFW_AMBIGUOUS_OCCURRENCE_SOURCE')
            if self.enabled and match(_line, parsed) == 'MATCH':
                excluded.append((digest, parsed, self.generation, position))
                filtered[position] = digest
            else:
                normal.append(values + (self.generation, position))
                stored[position] = digest
        if normal:
            fields = FIELDS
            if self.identity is not None:
                fields += ' host_id source_id collector_id sender_id source_scope reported_hostname'
            fields += ' file_generation file_position'
            placeholders = ','.join(['%s'] * len(normal[0]))
            self.cursor.executemany('INSERT INTO ufw_log (' + ','.join(fields.split()) + ') VALUES ('
                                    + placeholders + ')', normal)
        if excluded:
            record_counts(self.cursor, self.identity, excluded)
        self.inserted += len(normal)
        self.stats['duplicates'] = self.stats.get('duplicates', 0) + duplicates
        self.stats['filtered'] = self.stats.get('filtered', 0) + len(excluded)
        self.rows.clear()
        self.byte_count = 0
