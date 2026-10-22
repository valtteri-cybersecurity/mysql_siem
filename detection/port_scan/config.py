"""Small, environment-based limits for one scheduled pass."""

import os


class DetectionRunError(RuntimeError):
    """A safe-to-log configuration, state or processing failure."""


def load_config():
    config = {}
    for name, default, minimum, maximum in (
        ("batch_size", 1000, 1, 10000),
        ("late_seconds", 600, 0, 86400),
        ("max_buffer_events", 10000, 10, 100000),
    ):
        try:
            value = int(os.getenv("PORT_SCAN_" + name.upper(), str(default)))
        except ValueError:
            raise DetectionRunError(
                "Invalid port-scan numeric configuration."
            ) from None
        if not minimum <= value <= maximum:
            raise DetectionRunError(
                "Port-scan configuration is outside supported limits."
            )
        config[name] = value
    if config["max_buffer_events"] < config["batch_size"]:
        raise DetectionRunError("Buffer limit must be at least the batch size.")
    return config
