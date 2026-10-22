"""One DNS collection run for cron. No automatic migration or scheduling."""

import argparse
import time
from datetime import datetime, timezone

from database.connection import get_connection
from ingestion.dns.adapters.adguard import AdGuardAdapter, AdGuardError
from ingestion.dns.collector import DNSCollectionError, DNSCollectionIncomplete, collect
from ingestion.dns.config import load_adguard_config, load_collector_config
from ingestion.dns.db import (
    DNSCollectionBusy,
    DNSStorageError,
    find_source,
    purge_events,
    register_source,
)


def log(message):
    print(f"{datetime.now(timezone.utc).isoformat()}:   {message}", flush=True)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Run one AdGuard Home DNS collection cycle."
    )
    parser.add_argument(
        "--register-source",
        action="store_true",
        help="Register a disabled source only; do not fetch DNS logs.",
    )
    args = parser.parse_args(argv)
    connection = None
    try:
        config = load_adguard_config()
        settings = load_collector_config()
        connection = get_connection()
        if connection is None:
            return 1
        if args.register_source:
            source_id = register_source(
                connection, config.source_name, "adguard", config.base_url
            )
            log(
                f"DNS source registered (id={source_id}); existing enablement unchanged. New sources are disabled."
            )
            return 0
        source_id = find_source(
            connection, config.source_name, "adguard", config.base_url
        )
        cleanup_deadline = time.monotonic() + settings.max_seconds
        with AdGuardAdapter(config) as adapter:
            result = collect(
                adapter, connection, source_id, settings, page_size=config.page_size
            )
        deleted = 0
        for _ in range(10):
            if time.monotonic() >= cleanup_deadline:
                break
            count = purge_events(
                connection,
                retention_days=settings.retention_days,
                batch_size=10000,
                source_id=source_id,
            )
            deleted += count
            if count < 10000:
                break
        log(
            f"DNS collection complete: inserted={result['inserted']}, pages={result['pages']}, expired_deleted={deleted}."
        )
        return 0
    except DNSCollectionBusy:
        log("DNS collection skipped: another collector holds the source lock.")
        return 0
    except DNSCollectionIncomplete as error:
        log(str(error))
        return 2
    except (AdGuardError, DNSStorageError, DNSCollectionError, ValueError) as error:
        log(str(error))
        return 1
    except Exception:  # noqa: BLE001 - CLI boundary must not expose raw exception payloads
        log("Unexpected DNS collector failure.")
        return 1
    finally:
        if connection is not None:
            connection.close()


if __name__ == "__main__":
    raise SystemExit(main())
