"""Content-verified Auth file generations. Names and content hashes are not event IDs."""
import hashlib
import os
import secrets
import time

CHUNK = 65536


class AuthCollectionError(RuntimeError):
    """An unverified source or checkpoint prevents safe progress."""


def hashes(infile, boundaries, deadline):
    infile.seek(0)
    digest = hashlib.sha256()
    result = {}
    position = 0
    for end in sorted(set(boundaries)):
        if end < 0:
            raise AuthCollectionError('Invalid Auth verification boundary.')
        while position < end:
            if deadline is not None and time.monotonic() >= deadline:
                raise AuthCollectionError('Auth verification time budget exhausted; checkpoint retained.')
            block = infile.read(min(CHUNK, end - position))
            if not block:
                raise AuthCollectionError('Auth source was truncated during verification.')
            digest.update(block)
            position += len(block)
        result[end] = digest.copy()
    return result


def start(infile, info, state, stats, deadline):
    position = 0
    generation = None
    boundaries = [0, info.st_size]
    if state is not None:
        if len(state) != 7:
            raise AuthCollectionError('Invalid Auth checkpoint metadata.')
        previous, _legacy_hash, generation, prefix, size, observed, mtime = state
        if type(previous) is not int or previous < 0:
            raise AuthCollectionError('Invalid auth checkpoint position.')
        if generation is None:
            if previous != 0:
                raise AuthCollectionError('Legacy Auth checkpoint has no verified file generation; manual source review required.')
            for value in (prefix, size, observed, mtime):
                if value is not None:
                    raise AuthCollectionError('Partial Auth generation metadata; checkpoint retained.')
        else:
            if (not isinstance(generation, bytes) or len(generation) != 32 or generation == bytes(32)
                    or type(size) is not int or size < previous or type(mtime) is not int
                    or not isinstance(prefix, str) or not isinstance(observed, str)):
                raise AuthCollectionError('Invalid Auth generation metadata; checkpoint retained.')
            for digest in (_legacy_hash, prefix, observed):
                if not isinstance(digest, str) or len(digest) != 64:
                    raise AuthCollectionError('Invalid Auth checkpoint digest.')
                for character in digest:
                    if character not in '0123456789abcdef':
                        raise AuthCollectionError('Invalid Auth checkpoint digest.')
            if size <= info.st_size:
                boundaries.extend((previous, size))
    verified = hashes(infile, boundaries, deadline)
    if state is not None and generation is not None:
        same = size <= info.st_size
        if same:
            same = verified[size].hexdigest() == observed
        if same:
            same = verified[previous].hexdigest() == prefix
        if same and size == info.st_size and mtime != info.st_mtime_ns:
            raise AuthCollectionError('Ambiguous Auth file generation; checkpoint retained.')
        if same:
            position = previous
        else:
            generation = None
            stats['source_resets'] += 1
            stats['coverage_gaps'] += 1
    if generation is None:
        generation = secrets.token_bytes(32)
    infile.seek(position)
    return generation, verified[position], verified[info.st_size].hexdigest()


def finish(infile, info, prefix, observed, deadline):
    position = infile.tell()
    for _attempt in range(2):
        before = os.fstat(infile.fileno())
        verified = hashes(infile, (position, info.st_size), deadline)
        if (verified[position].hexdigest() != prefix.hexdigest()
                or verified[info.st_size].hexdigest() != observed):
            raise AuthCollectionError('Auth source content changed during collection.')
        current = os.fstat(infile.fileno())
        if current.st_size == info.st_size and current.st_mtime_ns != info.st_mtime_ns:
            raise AuthCollectionError('Ambiguous Auth file generation during collection.')
        if ((before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                == (current.st_size, current.st_mtime_ns, current.st_ctime_ns)):
            infile.seek(position)
            return current.st_mtime_ns
        if current.st_size <= before.st_size:
            raise AuthCollectionError('Auth source content changed during collection.')
    raise AuthCollectionError('Auth source remained unstable during verification; checkpoint retained.')
