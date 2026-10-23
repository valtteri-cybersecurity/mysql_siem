"""Exact string validation for signed DECIMAL(P,S) values; no rounding."""

import re
from decimal import Decimal


def validate_decimal_string(value: str, *, precision: int, scale: int) -> str:
    if precision < 1 or not 0 <= scale <= precision:
        raise ValueError("Invalid decimal precision or scale.")

    pattern = r"-?[0-9]+"
    if scale > 0:
        pattern += rf"\.[0-9]{{{scale}}}"
    if re.fullmatch(pattern, value) is None:
        raise ValueError("Expected a decimal string with the required number of decimal places.")

    number = Decimal(value)
    if number.is_signed() and number.is_zero():
        raise ValueError("Negative zero is not allowed.")

    maximum = "9" * (precision - scale) or "0"
    if scale > 0:
        maximum += "." + "9" * scale
    if number.copy_abs() > Decimal(maximum):
        raise ValueError("Decimal value exceeds the SQL storage range.")
    return value
