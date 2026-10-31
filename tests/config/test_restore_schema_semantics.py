"""Protect SQL restore structure and AUTO_INCREMENT state."""

import pytest

from config.installation_backup import (
    BackupError,
    schema_digest,
    verify_restored_auto_increment,
)


class MetadataCursor:
    def __init__(self):
        self.query = ""
        self.queries = []

    def execute(self, query, values):
        self.query = query
        self.queries.append(query)

    def fetchall(self):
        if "SELECT engine,table_collation" in self.query:
            return [("InnoDB", "utf8mb4_bin", "Dynamic", "")]
        return []


def test_schema_digest_excludes_sequence_counter():
    cursor = MetadataCursor()

    digest = schema_digest(cursor, "sample")

    assert len(digest) == 64

    for query in cursor.queries:
        assert "auto_increment" not in query.lower()


@pytest.mark.parametrize(
    "original,restored",
    [
        (None, None),
        (1, 1),
        (10, 10),
        (10, 15),
        (25001, 25002),
    ],
)
def test_valid_restored_sequence(original, restored):
    verify_restored_auto_increment(
        "example",
        original,
        restored,
    )


@pytest.mark.parametrize(
    "original,restored",
    [
        (10, 9),
        (25001, 25000),
        (10, None),
        (None, 5),
        (0, 1),
        (-1, 10),
        (True, 10),
        (10, True),
        (10, "10"),
    ],
)
def test_invalid_restored_sequence_rejected(
    original, restored
):
    with pytest.raises(BackupError):
        verify_restored_auto_increment(
            "example",
            original,
            restored,
        )
