import os
import sys
from hashlib import blake2b

import matrix_content_scanner
from matrix_content_scanner.mcs_rust import get_rust_file_digest


def check_rust_lib_up_to_date() -> None:
    """For editable installs check if the rust library is outdated and needs to
    be rebuilt.
    """

    if not _dist_is_editable():
        return

    mcs_dir = os.path.dirname(matrix_content_scanner.__file__)
    mcs_root = os.path.abspath(os.path.join(mcs_dir, "../.."))

    # Double check we've not gone into site-packages...
    if os.path.basename(mcs_root) == "site-packages":
        return

    # ... and it looks like the root of a python project.
    if not os.path.exists("pyproject.toml"):
        return

    # Get the hash of all Rust source files
    hash = _hash_rust_files_in_directory(os.path.join(mcs_root, "rust", "src"))

    if hash != get_rust_file_digest():
        raise Exception("Rust module outdated. Please rebuild using `poetry install`")


def _hash_rust_files_in_directory(directory: str) -> str:
    """Get the hash of all files in a directory (recursively)"""

    directory = os.path.abspath(directory)

    paths = []

    dirs = [directory]
    while dirs:
        dir = dirs.pop()
        with os.scandir(dir) as d:
            for entry in d:
                if entry.is_dir():
                    dirs.append(entry.path)
                else:
                    paths.append(entry.path)

    # We sort to make sure that we get a consistent and well-defined ordering.
    paths.sort()

    hasher = blake2b()

    for path in paths:
        with open(os.path.join(directory, path), "rb") as f:
            hasher.update(f.read())

    return hasher.hexdigest()


def _dist_is_editable() -> bool:
    """Is distribution an editable install?"""
    for path_item in sys.path:
        egg_link = os.path.join(path_item, "matrix_content_scanner.pth")
        if os.path.isfile(egg_link):
            return True
    return False
