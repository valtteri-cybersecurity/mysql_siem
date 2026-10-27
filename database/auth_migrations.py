"""Resumable Auth login metadata migration; never rewrite historical rows."""

from database.schema import SchemaError


def auth_columns(cursor):
    cursor.execute(
        "SELECT column_name, column_type, is_nullable, column_default, "
        "collation_name, extra FROM information_schema.columns "
        "WHERE table_schema = DATABASE() AND table_name = 'auth_events' "
        "AND column_name IN ('source_ip', 'auth_method', 'source_port')"
    )
    result = {}
    for row in cursor.fetchall():
        result[row[0]] = tuple(row[1:])
    return result


def upgrade_auth_events(connection, path):
    """Inspect before each additive ALTER so committed DDL can safely resume.

    The old source_ip definition must match except for its NULL setting.
    New nullable fields leave historical metadata unknown; no backfill occurs.
    MySQL 8.0 and 8.4 use the same standard ALTER statements here.
    """
    expected = {
        "source_ip": ("varchar(45)", "YES", None, "ascii_bin", ""),
        "auth_method": ("varchar(32)", "YES", None, "ascii_bin", ""),
        "source_port": ("smallint unsigned", "YES", None, None, ""),
    }
    statements = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip() and not line.lstrip().startswith("--"):
            statements.append(line.strip())
    if len(statements) != len(expected):
        raise SchemaError("Unexpected Auth migration statements.")

    with connection.cursor() as cursor:
        current = auth_columns(cursor)
        for name, definition in current.items():
            allowed = [expected[name]]
            if name == "source_ip":
                allowed.append(("varchar(45)", "NO", None, "ascii_bin", ""))
            if definition not in allowed:
                raise SchemaError("Incompatible Auth columns; preserve and inspect existing data.")
        if "source_ip" not in current:
            raise SchemaError("Auth source_ip column is missing.")

        for index, name in enumerate(expected):
            if current.get(name) == expected[name]:
                continue
            cursor.execute(statements[index])
            current = auth_columns(cursor)
            if current.get(name) != expected[name]:
                raise SchemaError("Auth login metadata upgrade was not verified.")
