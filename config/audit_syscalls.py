"""Read-only libaudit rule construction in a fresh process, without netlink."""

import ctypes
import json
import subprocess
import sys
from pathlib import Path


def native_masks(arch, permissions, names):
    """Use the same public libaudit builders as auditctl; never submit a rule."""
    library = ctypes.CDLL('libaudit.so.1')
    library.audit_rule_create_data.restype = ctypes.c_void_p
    library.audit_rule_free_data.argtypes = [ctypes.c_void_p]
    library.audit_rule_fieldpair_data.argtypes = [ctypes.POINTER(ctypes.c_void_p), ctypes.c_char_p, ctypes.c_int]
    library.audit_determine_machine.argtypes = [ctypes.c_char_p]
    library.audit_name_to_syscall.argtypes = [ctypes.c_char_p, ctypes.c_int]
    machine = library.audit_determine_machine(arch.encode('ascii'))
    if machine < 0:
        raise ValueError('libaudit cannot resolve this syscall architecture.')
    rule = ctypes.c_void_p(library.audit_rule_create_data())
    if not rule.value:
        raise ValueError('libaudit could not allocate a rule.')
    try:
        for field in ('arch=' + arch, 'perm=' + permissions):
            # libaudit temporarily modifies this buffer while parsing it.
            buffer = ctypes.create_string_buffer(field.encode('ascii'))
            if library.audit_rule_fieldpair_data(ctypes.byref(rule), buffer, 4) != 0:
                raise ValueError('libaudit could not construct the permission rule.')
        # Linux UAPI audit_rule_data: three u32 fields followed by mask[64].
        words = ctypes.cast(rule, ctypes.POINTER(ctypes.c_uint32 * 67)).contents
        expected = list(words[3:67])
        # Audit 3 leaves the mask empty; auditctl then supplies "all".
        if not any(expected):
            expected = [0xffffffff] * 64
        actual = [0] * 64
        for name in names:
            if name == 'all':
                actual = [0xffffffff] * 64
                break
            number = int(name) if name.isdigit() else library.audit_name_to_syscall(name.encode('ascii'), machine)
            if number < 0 or number >= 2048:
                raise ValueError('Unknown syscall for the specified Audit architecture.')
            actual[number // 32] |= 1 << (number % 32)
        return expected == actual
    finally:
        library.audit_rule_free_data(rule)


def validate_syscalls(arch, permissions, names):
    # libaudit parsing uses process-global state. Each comparison starts clean.
    result = subprocess.run([sys.executable, '-I', '-B', str(Path(__file__).resolve()),
                             arch, permissions, json.dumps(names)],
                            capture_output=True, text=True, timeout=10, check=False)
    if result.returncode != 0 or result.stderr or result.stdout.strip() != 'true':
        raise ValueError('Cannot prove the Audit syscall list matches the local canonical permission rule.')


if __name__ == '__main__':
    try:
        print(json.dumps(native_masks(sys.argv[1], sys.argv[2], json.loads(sys.argv[3]))))
    except (OSError, ValueError, AttributeError):
        raise SystemExit(1) from None
