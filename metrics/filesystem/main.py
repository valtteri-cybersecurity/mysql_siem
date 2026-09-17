from metrics.filesystem.get import get_modified_files, get_all_files
from metrics.filesystem.db import save_metrics


def main():
    total_files = get_all_files()
    modified_files = get_modified_files()

    save_metrics(
        modified_files,
        total_files
    )


if __name__ == "__main__":
    main()
