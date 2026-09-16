import subprocess
from datetime import datetime


def get_timestamp():
    date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return date

def get_modified_files():
    result = subprocess.run(["find", "/etc", "-type", 'f', '-mtime', '-1'],
                            capture_output= True,
                            text = True
                            )
    modified = len(result.stdout.splitlines())
    return modified


def get_all_files():

    result = subprocess.run(
        ["find", "/home", "-type", "f"],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True
    )

    files = result.stdout.splitlines()

    total_files = len(files)

    return total_files

