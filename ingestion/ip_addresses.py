"""Stable address text for stored observations and replay fingerprints."""

from ipaddress import ip_address


def canonical_ip(value):
    """Keep IPv4-mapped IPv6 in hexadecimal on Python 3.12 and 3.13 alike.

    Python 3.13 prints mapped addresses with a dotted IPv4 suffix. Changing the
    stored text during an upgrade would change existing DNS replay fingerprints.
    This remains an observed address, never a host identity.
    """
    address = ip_address(value)
    if address.version == 6 and address.ipv4_mapped is not None:
        mapped = int(address.ipv4_mapped)
        high = mapped >> 16
        low = mapped & 65535
        return f"::ffff:{high:x}:{low:x}"
    return str(address)
