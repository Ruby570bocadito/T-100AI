"""Log rotation for T-100AI's log files.

Provides automatic log rotation with numbered backups and gzip compression.
Handles t100ai.log, audit.log, permissions.log, and any other log files.
"""

from __future__ import annotations

import gzip
import shutil
import threading
import time
from pathlib import Path
from typing import Optional


class LogRotator:
    """Rotates log files when they exceed a configurable size threshold.

    Rotation scheme:
        t100ai.log -> t100ai.log.1 (uncompressed, most recent)
        t100ai.log.1 -> t100ai.log.2.gz
        t100ai.log.2.gz -> t100ai.log.3.gz
        ... up to max_backups
    """

    def __init__(
        self,
        log_dir: str = "logs",
        max_size_mb: int = 50,
        max_backups: int = 5,
    ) -> None:
        self.log_dir = Path(log_dir).resolve()
        self.max_size = max_size_mb * 1024 * 1024  # convert MB -> bytes
        self.max_backups = max_backups
        self._threads: list[threading.Thread] = []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def rotate_if_needed(self, log_path: str) -> bool:
        """Rotate *log_path* if its size exceeds ``max_size``.

        Returns ``True`` when a rotation was performed, ``False`` otherwise.
        """
        path = Path(log_path)
        if not path.exists():
            return False
        if path.stat().st_size >= self.max_size:
            self.rotate(log_path)
            return True
        return False

    def rotate(self, log_path: str) -> str:
        """Perform a numbered rotation on *log_path*.

        Shifts existing backups up by one number, compressing with gzip
        (except the newest backup which stays uncompressed).  Creates a
        fresh empty file in place of the original.

        Returns the path of the newly created backup (``.1``).
        """
        path = Path(log_path)

        if not path.exists():
            raise FileNotFoundError(f"Log file does not exist: {log_path}")

        # Remove the oldest backup if it would exceed max_backups after shift
        oldest = Path(f"{log_path}.{self.max_backups}.gz")
        if oldest.exists():
            oldest.unlink()

        # Shift existing backups upward (.N-1 -> .N)
        for i in range(self.max_backups - 1, 1, -1):
            src = Path(f"{log_path}.{i}.gz")
            dst = Path(f"{log_path}.{i + 1}.gz")
            if src.exists():
                src.rename(dst)

        # Compress .1 -> .2.gz
        backup_one = Path(f"{log_path}.1")
        backup_two_gz = Path(f"{log_path}.2.gz")
        if backup_one.exists():
            with open(backup_one, "rb") as f_in:
                with gzip.open(backup_two_gz, "wb") as f_out:
                    shutil.copyfileobj(f_in, f_out)
            backup_one.unlink()

        # Move current log -> .1 (uncompressed for easy access)
        shutil.copy2(str(path), str(backup_one))

        # Truncate the original log file (keeps the same inode for open
        # file descriptors)
        with open(path, "w"):
            pass

        return str(backup_one)

    def cleanup_old_backups(self, log_path: str) -> int:
        """Remove backup files exceeding ``max_backups``.

        Returns the number of files removed.
        """
        removed = 0
        i = self.max_backups + 1
        while True:
            gz = Path(f"{log_path}.{i}.gz")
            plain = Path(f"{log_path}.{i}")
            found = False
            for candidate in (gz, plain):
                if candidate.exists():
                    candidate.unlink()
                    removed += 1
                    found = True
            if not found:
                break
            i += 1
        return removed

    def get_log_stats(self, log_dir: Optional[str] = None) -> dict:
        """Return statistics about log files in *log_dir*.

        Returns a dict with keys:
            ``total_files`` – number of log files found
            ``total_size`` – combined size in bytes
            ``files`` – list of per-file dicts (path, size, backups, oldest_backup)
        """
        target = Path(log_dir) if log_dir else self.log_dir
        if not target.exists():
            return {"total_files": 0, "total_size": 0, "files": []}

        # Gather base log files (files that are not numbered backups)
        base_logs: list[Path] = []
        for entry in target.iterdir():
            if entry.is_file() and entry.suffix == ".log":
                base_logs.append(entry)

        files_info: list[dict] = []
        total_size = 0

        for log_file in sorted(base_logs):
            size = log_file.stat().st_size
            total_size += size

            backups: list[str] = []
            for i in range(1, self.max_backups + 2):
                gz = Path(f"{log_file}.{i}.gz")
                plain = Path(f"{log_file}.{i}")
                if gz.exists():
                    backups.append(str(gz))
                if plain.exists():
                    backups.append(str(plain))

            oldest = backups[-1] if backups else None

            files_info.append({
                "path": str(log_file),
                "size": size,
                "backups": len(backups),
                "oldest_backup": oldest,
            })

        return {
            "total_files": len(files_info),
            "total_size": total_size,
            "files": files_info,
        }

    def setup_auto_rotation(self, log_path: str) -> None:
        """Start a background daemon thread that rotates *log_path* every 60 s."""

        def _worker() -> None:
            while True:
                try:
                    self.rotate_if_needed(log_path)
                except Exception:
                    pass  # never crash the rotation thread
                time.sleep(60)

        t = threading.Thread(target=_worker, daemon=True, name=f"log-rotator-{log_path}")
        t.start()
        self._threads.append(t)


class RotatingFileHandler:
    """File-like object that automatically rotates the underlying log file
    when a write would cause it to exceed the configured maximum size.

    Usage::

        handler = RotatingFileHandler("logs/t100ai.log", max_size_mb=50)
        handler.write("some log line\\n")
        handler.flush()
    """

    def __init__(
        self,
        log_path: str,
        max_size_mb: int = 50,
        max_backups: int = 5,
    ) -> None:
        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self.rotator = LogRotator(
            log_dir=str(self.log_path.parent),
            max_size_mb=max_size_mb,
            max_backups=max_backups,
        )
        self._file = open(str(self.log_path), "a", encoding="utf-8")
        self._closed = False

    # ------------------------------------------------------------------
    # File-like interface
    # ------------------------------------------------------------------

    def write(self, data: str) -> int:
        """Write *data*, rotating first if the file would exceed ``max_size``."""
        if self._closed:
            raise ValueError("I/O operation on closed file")

        # Check size before writing
        try:
            current_size = self.log_path.stat().st_size
        except FileNotFoundError:
            current_size = 0

        if current_size + len(data.encode("utf-8")) >= self.rotator.max_size:
            self._file.close()
            self.rotator.rotate(str(self.log_path))
            self._file = open(str(self.log_path), "a", encoding="utf-8")

        return self._file.write(data)

    def flush(self) -> None:
        if not self._closed:
            self._file.flush()

    def close(self) -> None:
        if not self._closed:
            self._file.flush()
            self._file.close()
            self._closed = True

    def __enter__(self) -> RotatingFileHandler:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    @property
    def closed(self) -> bool:
        return self._closed


def setup_rotating_logs(log_dir: str = "logs") -> None:
    """Create *log_dir* and set up auto-rotation for the standard log files.

    Starts background rotation threads for:
        - t100ai.log
        - audit.log
        - permissions.log
    """
    path = Path(log_dir)
    path.mkdir(parents=True, exist_ok=True)

    rotator = LogRotator(log_dir=str(path))

    for name in ("t100ai.log", "audit.log", "permissions.log"):
        log_file = path / name
        # Ensure the file exists so the rotation thread can monitor it
        if not log_file.exists():
            log_file.touch()
        rotator.setup_auto_rotation(str(log_file))
