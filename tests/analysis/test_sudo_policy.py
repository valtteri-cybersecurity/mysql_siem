"""Mint sudo migration on temporary files; native policy queries are simulated."""

import os
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from config import sudo_policy as policy


def listing(commands=None, *, restricted=False):
    if commands is None:
        commands = policy.MINT_HELPERS
    text = ('Matching Defaults entries for mysql_siem on Linux:\n    env_reset, use_pty\n\n'
            'User mysql_siem may run the following commands on Linux:\n')
    for command in commands:
        text += '    (root) NOPASSWD: ' + command + '\n'
    if restricted:
        text += '    (ALL : ALL) !ALL\n'
    return text


@pytest.fixture
def environment(tmp_path, monkeypatch):
    destination = tmp_path / 'zz-mysql-siem'
    monkeypatch.setattr(policy, 'POLICY', destination)
    monkeypatch.setattr(policy, 'OWNER', os.geteuid())
    monkeypatch.setattr(policy, 'trusted_directory', Mock())
    monkeypatch.setattr(policy.journal, 'require_install_lock', Mock())
    monkeypatch.setattr(policy.os, 'fchown', Mock())
    original_fstat = os.fstat

    def fstat(descriptor):
        info = original_fstat(descriptor)
        values = list(info)
        values[5] = 0  # Model root's group only; never chown a real system file.
        return os.stat_result(values)

    def command(arguments):
        if arguments[0].endswith('visudo'):
            return SimpleNamespace(returncode=0, stdout='parsed OK\n', stderr='')
        assert arguments[:5] == ['/usr/bin/sudo', '-n', '-l', '-U', 'mysql_siem']
        if len(arguments) == 5:
            return SimpleNamespace(returncode=0, stdout=listing(restricted=destination.exists()), stderr='')
        assert arguments[5:8] == ['-u', 'root', '--']
        return SimpleNamespace(returncode=1, stdout='', stderr='')

    monkeypatch.setattr(policy.os, 'fstat', fstat)
    monkeypatch.setattr(policy, 'command', Mock(side_effect=command))
    return destination


@pytest.mark.parametrize('commands', [policy.MINT_HELPERS[:2], policy.MINT_HELPERS, policy.MINT_HELPERS[2:]])
def test_packaged_mint_helpers_are_restricted_with_native_read_only_queries(environment, commands):
    # Use the corresponding post-change listing for older/newer Mint packages.
    native = policy.command.side_effect

    def command(arguments):
        result = native(arguments)
        if arguments[0].endswith('sudo') and len(arguments) == 5:
            result.stdout = listing(commands, restricted=True)
        return result

    policy.command.side_effect = command
    policy.restrict_mint_sudo(listing(commands), 0)
    assert environment.read_text() == policy.TEXT
    assert environment.stat().st_mode & 0o777 == 0o440
    before = environment.stat().st_ino
    policy.restrict_mint_sudo(listing(commands, restricted=True), 0)
    assert environment.stat().st_ino == before
    for call in policy.command.call_args_list:
        arguments = call.args[0]
        assert arguments[0].endswith('visudo') or '-l' in arguments


@pytest.mark.parametrize('entry', ['(ALL : ALL) ALL', '(root) /bin/sh',
                                 '(root) NOPASSWD: /usr/bin/mint-refresh-cache --unexpected',
                                 '(root) NOPASSWD: /usr/bin/mint-refresh-cache, /bin/sh',
                                 '(other) NOPASSWD: /usr/bin/mint-refresh-cache'])
def test_unexpected_grants_are_not_silently_repaired(environment, entry):
    output = listing() + '    ' + entry + '\n'
    with pytest.raises(policy.InstallationError, match='unexpected sudo'):
        policy.restrict_mint_sudo(output, 0)
    assert not environment.exists()
    policy.command.assert_not_called()


def test_known_mint_restriction_never_reads_interactive_input(environment, monkeypatch):
    monkeypatch.setattr('builtins.input', Mock(side_effect=AssertionError('Unexpected interactive approval')))
    policy.restrict_mint_sudo(listing(), 0)
    assert environment.read_text() == policy.TEXT
    assert list(environment.parent.iterdir()) == [environment]


@pytest.mark.parametrize('fault', ['foreign', 'symlink', 'hardlink', 'unsafe-mode'])
def test_foreign_or_unsafe_destination_is_never_overwritten(environment, fault):
    other = environment.parent / 'other'
    other.write_text(policy.TEXT if fault != 'foreign' else 'foreign policy\n')
    other.chmod(0o440)
    if fault == 'symlink':
        environment.symlink_to(other)
    elif fault == 'hardlink':
        os.link(other, environment)
    else:
        environment.write_text(other.read_text())
        environment.chmod(0o666 if fault == 'unsafe-mode' else 0o440)
    before = other.read_bytes()
    with pytest.raises((OSError, policy.InstallationError)):
        policy.restrict_mint_sudo(listing(), 0)
    assert other.read_bytes() == before


@pytest.mark.parametrize('fault', ['syntax', 'candidate', 'post-syntax', 'query-error', 'still-allowed'])
def test_failure_stops_and_retains_published_deny_without_restoring_grants(environment, fault):
    native = policy.command.side_effect
    checks = 0

    def command(arguments):
        nonlocal checks
        result = native(arguments)
        if arguments[0].endswith('visudo'):
            checks += 1
            if (fault == 'syntax' and checks == 1 or fault == 'candidate' and checks == 2
                    or fault == 'post-syntax' and checks == 3):
                result.returncode = 1
        elif len(arguments) > 5:
            if fault == 'still-allowed':
                result.returncode = 0
            elif fault == 'query-error':
                result.stderr = 'policy failed'
        return result

    policy.command.side_effect = command
    with pytest.raises(policy.InstallationError):
        policy.restrict_mint_sudo(listing(), 0)
    assert environment.exists() == (fault not in ('syntax', 'candidate'))
    if environment.exists():
        assert environment.read_text() == policy.TEXT
        policy.command.side_effect = native
        policy.restrict_mint_sudo(listing(restricted=True), 0)


@pytest.mark.parametrize('output,status', [('', 0), ('policy failed\n', 1), (listing(), 2),
                                         ('sudo: error\n' + listing(), 0)])
def test_uncertain_listing_is_rejected_before_any_change(environment, output, status):
    with pytest.raises(policy.InstallationError):
        policy.restrict_mint_sudo(output, status)
    assert not environment.exists()



def test_existing_deny_only_policy_is_accepted_without_rewriting_it(environment):
    environment.write_text(policy.TEXT)
    environment.chmod(0o440)
    native = policy.command.side_effect

    def command(arguments):
        result = native(arguments)
        if arguments[0].endswith('sudo'):
            result.stdout = listing([], restricted=True)
        return result

    policy.command.side_effect = command
    before = environment.stat().st_ino
    policy.restrict_mint_sudo(listing([], restricted=True), 0)
    assert environment.stat().st_ino == before
