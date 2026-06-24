from __future__ import annotations

import fcntl
import os
import time
from pathlib import Path
from typing import Optional


class FileLock:
    """Lock a file path using fcntl.flock(). Context manager.
    Uses a .lock sidecar file so we don't need the target file to exist.
    """

    def __init__(self, path: Path | str, timeout: float = 30.0, poll: float = 0.5):
        self._lock_path = Path(str(path) + ".lock")
        self._timeout = timeout
        self._poll = poll
        self._fd: Optional[int] = None

    def __enter__(self) -> FileLock:
        self._lock_path.parent.mkdir(parents=True, exist_ok=True)
        deadline = time.monotonic() + self._timeout
        while True:
            try:
                self._fd = os.open(str(self._lock_path), os.O_CREAT | os.O_RDWR)
                fcntl.flock(self._fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return self
            except (IOError, BlockingIOError):
                if self._fd is not None:
                    os.close(self._fd)
                    self._fd = None
                if time.monotonic() >= deadline:
                    raise TimeoutError(
                        f"Could not acquire lock on {self._lock_path} "
                        f"after {self._timeout}s"
                    )
                time.sleep(self._poll)

    def __exit__(self, *args: object) -> None:
        if self._fd is not None:
            fcntl.flock(self._fd, fcntl.LOCK_UN)
            os.close(self._fd)
            self._fd = None
        try:
            self._lock_path.unlink(missing_ok=True)
        except OSError:
            pass
