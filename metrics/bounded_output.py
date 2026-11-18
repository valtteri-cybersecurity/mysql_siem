"""Read the stdout of a read-only collector command under byte and time limits."""

import os
import selectors
import subprocess  # nosec B404
import time


class OutputLimitError(ValueError):
    pass


def bounded_output(command, *, env, timeout, max_bytes):
    deadline = time.monotonic() + timeout
    output = bytearray()
    # Callers supply a fixed executable and argument vector.
    with subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,  # nosec B603
                          stderr=subprocess.DEVNULL, env=env) as process:
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0 or not selector.select(remaining):
                        raise subprocess.TimeoutExpired(command, timeout)
                    chunk = os.read(process.stdout.fileno(), min(65536, max_bytes - len(output) + 1))
                    if not chunk:
                        break
                    if len(output) + len(chunk) > max_bytes:
                        raise OutputLimitError('Command output exceeds the collection limit.')
                    output.extend(chunk)
            status = process.wait(timeout=max(0, deadline - time.monotonic()))
        finally:
            if process.poll() is None:
                process.kill()
    return subprocess.CompletedProcess(command, status, output.decode('utf-8'))
