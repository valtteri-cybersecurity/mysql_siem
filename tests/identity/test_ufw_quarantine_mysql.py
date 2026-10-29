"""Real mixed-pass quarantine and rollback on a private application schema."""

import pymysql
import pytest

from ingestion import ufw_to_mysql as ufw

GOOD = b'2026-10-25T13:35:58.256386+02:00 host [UFW BLOCK] SRC=192.0.2.1 DST=198.51.100.1 PROTO=TCP DPT=443\n'


def test_mixed_pass_quarantines_and_deduplicates_atomically(mysql, tmp_path, monkeypatch):
    path = tmp_path / 'ufw.log'
    bad = GOOD.replace(b'SRC=192.0.2.1', b'SRC=invalid')
    path.write_bytes(GOOD + bad + b'ordinary message\n' + b'\x00' * 3000 + GOOD)
    monkeypatch.setattr(ufw, 'LOGFILE', str(path))
    result = ufw.process_log(mysql)
    assert result['inserted'] == 1
    assert result['quarantined'] == 1
    assert result['duplicates'] == 1
    assert result['non_ufw'] == 1
    with mysql.cursor() as cursor:
        cursor.execute('SELECT byte_position FROM ufw_file_checkpoints')
        before = cursor.fetchone()[0]
        assert before == path.stat().st_size
        cursor.execute('SELECT raw_bytes,reason FROM ufw_quarantine')
        assert cursor.fetchone() == (bad, 'INVALID_SRC_IP')
    with path.open('ab') as output:
        output.write(bad)
    assert ufw.process_log(mysql)['duplicates'] == 1
    with mysql.cursor() as cursor:
        cursor.execute('SELECT COUNT(*) FROM ufw_quarantine')
        assert cursor.fetchone() == (1,)
        cursor.execute('SELECT byte_position FROM ufw_file_checkpoints')
        before = cursor.fetchone()[0]
        cursor.execute('CREATE TRIGGER reject_quarantine BEFORE INSERT ON ufw_quarantine FOR EACH ROW '
                       "SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='synthetic failure'")
    with path.open('ab') as output:
        output.write(GOOD.replace(b'DPT=443', b'DPT=444'))
        output.write(GOOD.replace(b'DPT=443', b'DPT=99999'))
    with pytest.raises(pymysql.MySQLError):
        ufw.process_log(mysql)
    with mysql.cursor() as cursor:
        cursor.execute('SELECT byte_position FROM ufw_file_checkpoints')
        assert cursor.fetchone() == (before,)
        cursor.execute('SELECT COUNT(*) FROM ufw_log')
        assert cursor.fetchone() == (1,)
