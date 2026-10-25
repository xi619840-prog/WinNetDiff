"""Publish complete local evidence without truncating an existing file."""
from __future__ import annotations
import os
import tempfile
from pathlib import Path


def publish_file(temporary: str | Path, target: str | Path, overwrite: bool = False) -> None:
    if overwrite:
        os.replace(temporary, target)
    elif os.name == 'nt':
        # Windows rename is an atomic move that refuses an existing target;
        # unlike hard links this also works on writable FAT/exFAT volumes.
        os.rename(temporary, target)
    else:
        # Atomic exclusive creation; a competing writer cannot be overwritten.
        os.link(temporary, target)
        os.unlink(temporary)


def atomic_write_text(path: str | Path, text: str, overwrite: bool = False) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix='.' + target.name + '.', suffix='.tmp', dir=target.parent)
    try:
        with os.fdopen(descriptor, 'w', encoding='utf-8', newline='\n') as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        publish_file(temporary, target, overwrite)
    finally:
        Path(temporary).unlink(missing_ok=True)
