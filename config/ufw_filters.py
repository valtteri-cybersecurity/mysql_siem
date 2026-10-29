"""Administrator-managed UFW filtering; preview/statistics perform SELECT statements only."""
import argparse
import json
from datetime import datetime, timezone

import pymysql

from database.connection import get_connection
from ingestion import ufw_filters as filters


def utc_argument(value):
    try:
        result = datetime.fromisoformat(value.replace('Z', '+00:00'))
        if result.tzinfo is None:
            raise ValueError('Explicit UTC offset required.')
        return result.astimezone(timezone.utc).replace(tzinfo=None)
    except (ValueError, OverflowError):
        raise argparse.ArgumentTypeError('Use an ISO timestamp with an explicit timezone.') from None


def main(argv=None):
    parser = argparse.ArgumentParser(description=filters.DESCRIPTION, epilog=filters.RISK)
    parser.add_argument('operation', choices=('preview', 'enable', 'disable', 'statistics'))
    parser.add_argument('--source-id', type=int, required=True)
    parser.add_argument('--host-id', type=int, required=True)
    parser.add_argument('--start', type=utc_argument)
    parser.add_argument('--end', type=utc_argument)
    parser.add_argument('--max-rows', type=int, default=100000)
    parser.add_argument('--max-seconds', type=int, default=20)
    parser.add_argument('--actor')
    parser.add_argument('--reason')
    parser.add_argument('--acknowledge-local-evidence-loss', action='store_true')
    args = parser.parse_args(argv)
    if args.operation in ('preview', 'statistics') and (args.start is None or args.end is None):
        parser.error('Read operations require --start and --end with explicit timezones.')
    if args.operation in ('enable', 'disable') and (not args.actor or not args.reason):
        parser.error('Changes require --actor and --reason; use an administrator database account.')
    if args.operation == 'enable' and not args.acknowledge_local_evidence_loss:
        parser.error(filters.RISK + ' Use --acknowledge-local-evidence-loss only after reviewing the preview.')
    connection = get_connection(quiet=True)
    if connection is None:
        return 1
    try:
        if args.operation == 'preview':
            result = filters.preview(connection, args.source_id, args.host_id, args.start, args.end,
                                     max_rows=args.max_rows, max_seconds=args.max_seconds)
        elif args.operation == 'statistics':
            result = filters.statistics(connection, args.source_id, args.start, args.end)
        else:
            filters.change(connection, args.source_id, args.host_id, args.operation == 'enable',
                           actor=args.actor, reason=args.reason,
                           acknowledge_risk=args.acknowledge_local_evidence_loss)
            result = {'rule_key': filters.RULE_KEY, 'enabled': args.operation == 'enable', 'risk': filters.RISK}
        print(json.dumps(result, default=str, ensure_ascii=True))
        return 0
    except (ValueError, RuntimeError, pymysql.MySQLError):
        print('UFW filter operation failed; configuration, permissions or audit verification requires attention.')
        return 1
    finally:
        connection.close()


if __name__ == '__main__':
    raise SystemExit(main())
