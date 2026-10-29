"""Strict UFW field validation without changing historical event fingerprints."""
from datetime import datetime, timezone
from ipaddress import ip_address

from ingestion.splitter import parse_ufw_line


class InvalidUFW(ValueError):
    """A static reason code safe for diagnostics and quarantine."""


def convert_timestamp(value):
    if not isinstance(value, str):
        raise InvalidUFW('MISSING_TIMESTAMP')
    if value.endswith('Z'):
        base = value[:-1]
    else:
        zone = value[-6:]
        if len(zone) != 6 or zone[0] not in ('+', '-') or zone[3] != ':':
            raise InvalidUFW('MISSING_TIMEZONE')
        if not zone[1:3].isascii() or not zone[1:3].isdigit() or not zone[4:].isascii() or not zone[4:].isdigit():
            raise InvalidUFW('INVALID_TIMEZONE')
        if zone == '-00:00' or int(zone[1:3]) > 23 or int(zone[4:]) > 59:
            raise InvalidUFW('AMBIGUOUS_TIMEZONE')
        base = value[:-6]
    clock, point, fraction = base.partition('.')
    if len(clock) != 19 or clock[10] != 'T':
        raise InvalidUFW('INVALID_TIMESTAMP')
    if point and (not 1 <= len(fraction) <= 6 or not fraction.isascii() or not fraction.isdigit()):
        raise InvalidUFW('INVALID_TIMESTAMP_PRECISION')
    try:
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
        utc = parsed.astimezone(timezone.utc).replace(tzinfo=None)
    except (ValueError, OverflowError):
        raise InvalidUFW('INVALID_TIMESTAMP') from None
    if utc.year < 1000:
        raise InvalidUFW('TIMESTAMP_RANGE')
    return utc


def convert_port(value):
    if value is None:
        return 0
    if not isinstance(value, str) or not value.isascii() or not value.isdigit() or len(value) > 5:
        raise InvalidUFW('INVALID_PORT')
    port = int(value)
    if not 1 <= port <= 65535:
        raise InvalidUFW('INVALID_PORT')
    return port


def validate_event(line):
    if '\x00' in line:
        raise InvalidUFW('EMBEDDED_NUL')
    if '[UFW' not in line:
        return None
    actions = []
    for action in ('BLOCK', 'ALLOW', 'AUDIT'):
        count = line.count('[UFW ' + action + ']')
        for _ in range(count):
            actions.append(action)
    if len(actions) != 1 or line.count('[UFW') != 1:
        raise InvalidUFW('INVALID_ACTION')
    seen = set()
    for part in line.split():
        name, equals, _value = part.partition('=')
        if equals and name in ('SRC', 'DST', 'PROTO', 'SPT', 'DPT'):
            if name in seen:
                raise InvalidUFW('DUPLICATE_FIELD')
            seen.add(name)
    info = parse_ufw_line(line)
    info['event_time'] = convert_timestamp(info['timestamp'])
    for field in ('src_ip', 'dst_ip'):
        value = info[field]
        if value is None:
            raise InvalidUFW('MISSING_' + field.upper())
        if '%' in value or len(value) > 45:
            raise InvalidUFW('INVALID_' + field.upper())
        try:
            ip_address(value)
        except ValueError:
            raise InvalidUFW('INVALID_' + field.upper()) from None
    proto = info['protocol']
    if proto is None:
        raise InvalidUFW('MISSING_PROTOCOL')
    if not proto.isascii() or not proto.isalnum() or not 1 <= len(proto) <= 10:
        raise InvalidUFW('INVALID_PROTOCOL')
    if proto.isdigit() and int(proto) > 255:
        raise InvalidUFW('INVALID_PROTOCOL')
    info['src_port'] = convert_port(info['src_prt'])
    info['dst_port'] = convert_port(info['dst_prt'])
    return info
