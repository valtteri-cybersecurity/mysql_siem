"""Environment limits for one automatic SSH detection pass."""

import os

from detection.ssh_brute_force.db import SSHDetectionError


def load_config():
    config = {}
    for name, default, minimum, maximum in (
        ("batch_size", 1000, 1, 10000),
        ("late_seconds", 600, 0, 86400),
        ("max_buffer_events", 10000, 5, 100000),
    ):
        try:
            value = int(os.getenv("SSH_BRUTE_FORCE_" + name.upper(), str(default)))
        except ValueError:
            raise SSHDetectionError("Invalid SSH detection numeric configuration.") from None
        if not minimum <= value <= maximum:
            raise SSHDetectionError("SSH detection configuration is outside supported limits.")
        config[name] = value
    if config["max_buffer_events"] < config["batch_size"]:
        raise SSHDetectionError("SSH buffer limit must be at least the batch size.")
    return config
