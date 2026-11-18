"""
Overwriting files before deleting them, for 'shred'.

On SSDs and copy-on-write or journaling filesystems the old blocks may
survive elsewhere on the device; this removes the data from the files PFS
controls, which is as far as a program can reach.
"""

import os


def scrub_file(path: str) -> None:
    """Overwrites a file's bytes with random data and syncs. The file itself
    is left in place."""
    size = os.path.getsize(path)
    with open(path, "r+b") as f:
        remaining = size
        while remaining > 0:
            step = min(remaining, 1 << 20)
            f.write(os.urandom(step))
            remaining -= step
        f.flush()
        os.fsync(f.fileno())


def scrub_and_remove(path: str) -> None:
    """Overwrites a file with random data, then deletes it."""
    if os.path.exists(path):
        scrub_file(path)
        os.remove(path)


def scrub_then_replace(tmp_path: str, path: str) -> None:
    """Overwrites the existing file at path (if any), then moves tmp_path
    over it: for rewriting a small vault file without leaving its old
    content behind in the old file's blocks."""
    if os.path.exists(path):
        scrub_file(path)
    os.replace(tmp_path, path)
