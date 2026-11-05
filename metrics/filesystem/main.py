import subprocess

import pymysql

from metrics.filesystem.db import save_metrics
from metrics.filesystem.get import get_all_files, get_modified_files


def main():
    try:
        total_files = get_all_files()
        modified_files = get_modified_files()
        save_metrics(modified_files, total_files)
        return 0
    except (OSError, ValueError, subprocess.SubprocessError, pymysql.MySQLError):
        print("Filesystem metric collection failed.")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
