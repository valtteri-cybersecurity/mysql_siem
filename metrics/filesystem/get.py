import subprocess


def get_modified_files():
    result = subprocess.run(
        ["find", "/etc", "-type", "f", "-mtime", "-1"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True
    )

    return len(result.stdout.splitlines())

def get_all_files():
    result = subprocess.run(
        ["find", "/home", "-type", "f"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True
    )

    return len(result.stdout.splitlines())
