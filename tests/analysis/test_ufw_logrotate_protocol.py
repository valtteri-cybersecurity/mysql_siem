"""Exercise logrotate against temporary logs only; never load system configuration."""
import gzip
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest


@pytest.mark.skipif(shutil.which('logrotate') is None, reason='Private protocol test needs logrotate.')
def test_logrotate_supplies_source_and_output_descriptors(tmp_path):
    source = tmp_path / 'ufw.log'
    source.write_bytes(b'private rotation protocol test\n')
    source.chmod(0o600)
    command = tmp_path / 'compressor'
    report = tmp_path / 'descriptors.json'
    command.write_text('#!' + sys.executable + '\n' + '''import gzip
import json
import os
import stat
import sys
from pathlib import Path
record = {'input_regular': stat.S_ISREG(os.fstat(0).st_mode),
          'output_regular': stat.S_ISREG(os.fstat(1).st_mode),
          'input_path': os.readlink('/proc/self/fd/0'),
          'output_size': os.fstat(1).st_size, 'arguments': sys.argv[1:]}
Path(''' + repr(str(report)) + ''').write_text(json.dumps(record))
sys.stdout.buffer.write(gzip.compress(sys.stdin.buffer.read()))
''')
    command.chmod(0o700)
    config = tmp_path / 'rotation.conf'
    config.write_text('"' + str(source) + '" {\n    rotate 1\n    size 1\n    compress\n'
                      '    nodelaycompress\n    compresscmd ' + str(command) + '\n'
                      '    compressoptions -6\n    compressext .gz\n}\n')
    config.chmod(0o600)
    result = subprocess.run([shutil.which('logrotate'), '--force', '--state', str(tmp_path / 'state'), str(config)],
                            check=False, capture_output=True, timeout=10)
    assert result.returncode == 0, result.stderr.decode()
    record = json.loads(report.read_text())
    assert record['input_regular'] and record['output_regular']
    assert record['input_path'] == str(source) + '.1'
    assert record['output_size'] == 0
    assert record['arguments'] == ['-6']
    assert gzip.decompress(Path(str(source) + '.1.gz').read_bytes()) == b'private rotation protocol test\n'
    assert not Path(str(source) + '.1').exists()


def test_logrotate_retains_plain_source_when_compressor_fails(tmp_path):
    executable = shutil.which('logrotate')
    if executable is None:
        pytest.skip('Private protocol test needs logrotate.')
    source = tmp_path / 'ufw.log'
    source.write_bytes(b'preserve this raw log\n')
    source.chmod(0o600)
    command = tmp_path / 'compressor'
    command.write_text('#!/bin/sh\nprintf synthetic-compression-failure >&2\nprintf partial-output\nexit 1\n')
    command.chmod(0o700)
    config = tmp_path / 'rotation.conf'
    config.write_text('"' + str(source) + '" {\n rotate 1\n size 1\n compress\n nodelaycompress\n'
                      ' compresscmd ' + str(command) + '\n compressext .gz\n}\n')
    config.chmod(0o600)
    result = subprocess.run([executable, '--force', '--state', str(tmp_path / 'state'), str(config)],
                            check=False, capture_output=True, timeout=10)
    assert result.returncode != 0
    assert b'synthetic-compression-failure' in result.stderr
    assert Path(str(source) + '.1').read_bytes() == b'preserve this raw log\n'
    assert not Path(str(source) + '.1.gz').exists()
