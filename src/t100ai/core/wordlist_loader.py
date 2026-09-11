"""Wordlist loader for external wordlists, SecLists, and custom files."""

from __future__ import annotations

import logging
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

SECLISTS_BASE_URL = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/"

SECLIST_CATEGORIES: list[str] = [
    "Discovery/DNS/bitquark-subdomains-top100000.txt",
    "Discovery/DNS/subdomains-top1million-5000.txt",
    "Discovery/Web-Content/common.txt",
    "Discovery/Web-Content/big.txt",
    "Discovery/Web-Content/raft-small-words.txt",
    "Discovery/Web-Content/raft-medium-words.txt",
    "Discovery/Web-Content/raft-large-words.txt",
    "Discovery/Web-Content/directory-list-2.3-small.txt",
    "Discovery/Web-Content/directory-list-2.3-medium.txt",
    "Discovery/Web-Content/apache-user-enum.txt",
    "Discovery/Web-Content/CMS/joomla.txt",
    "Discovery/Web-Content/CMS/wordpress.txt",
    "Discovery/Web-Content/CMS/drupal.txt",
    "Fuzzing/LFI/LFI-LFISuite-pathtotest-huge.txt",
    "Fuzzing/SQLi/Generic-SQLi.txt",
    "Fuzzing/XSS-Fuzzing/",
    "Fuzzing/4-digits-0000-9999.txt",
    "Fuzzing/5-digits-00000-99999.txt",
    "Fuzzing/6-digits-000000-999999.txt",
    "Passwords/Leaked-Databases/rockyou.txt",
    "Passwords/Leaked-Databases/rockyou-75.txt",
    "Passwords/Leaked-Databases/phpbb.txt",
    "Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt",
    "Passwords/Default-Credentials/mysql-betterdefaultpasslist.txt",
    "Passwords/Default-Credentials/ssh-betterdefaultpasslist.txt",
    "Passwords/Default-Credentials/telnet-betterdefaultpasslist.txt",
    "Usernames/Honeypot-Captures/multiplesources-users-fabian-fingerle.de.txt",
    "Usernames/cirt-default-usernames.txt",
]


@dataclass
class WordlistSource:
    """Represents a wordlist source with metadata."""

    name: str
    path: str
    type: str  # builtin, external, downloaded
    count: int = 0
    loaded: bool = False


class WordlistLoader:
    """Load external wordlists, download SecLists, and manage wordlist collections."""

    def __init__(self, wordlists_dir: str = "wordlists/external") -> None:
        self.wordlists_dir = Path(wordlists_dir)
        self._loaded_wordlists: dict[str, list[str]] = {}
        self._sources: list[WordlistSource] = []
        self._ensure_dir()

    def _ensure_dir(self) -> None:
        """Create the wordlists directory if it doesn't exist."""
        try:
            self.wordlists_dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            logger.error("Failed to create wordlists directory %s: %s", self.wordlists_dir, exc)
            raise

    def load_external_wordlist(self, filepath: str) -> list[str]:
        """Load a wordlist file, deduplicate entries, and return as a list.

        Args:
            filepath: Path to the wordlist file (.txt, .lst, etc.).

        Returns:
            Deduplicated list of wordlist entries.

        Raises:
            FileNotFoundError: If the file does not exist.
            PermissionError: If the file cannot be read.
            ValueError: If the file is empty or contains no valid entries.
        """
        path = Path(filepath)

        if not path.exists():
            raise FileNotFoundError(f"Wordlist file not found: {filepath}")

        if not path.is_file():
            raise ValueError(f"Path is not a file: {filepath}")

        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                entries: list[str] = []
                for line in fh:
                    stripped = line.strip()
                    if stripped:
                        entries.append(stripped)
        except PermissionError as exc:
            raise PermissionError(f"Cannot read wordlist file: {filepath}") from exc
        except UnicodeDecodeError as exc:
            raise ValueError(f"Unable to decode wordlist file: {filepath}") from exc

        if not entries:
            raise ValueError(f"Wordlist file is empty or contains no valid entries: {filepath}")

        seen: set[str] = set()
        deduplicated: list[str] = []
        for entry in entries:
            if entry not in seen:
                seen.add(entry)
                deduplicated.append(entry)

        source = WordlistSource(
            name=path.name,
            path=str(path),
            type="external",
            count=len(deduplicated),
            loaded=True,
        )
        self._sources.append(source)
        self._loaded_wordlists[str(path)] = deduplicated

        logger.info(
            "Loaded wordlist '%s': %d entries (%d duplicates removed)",
            path.name,
            len(deduplicated),
            len(entries) - len(deduplicated),
        )

        return deduplicated

    def download_seclist(self, name: str) -> str:
        """Download a SecLists wordlist from GitHub.

        Args:
            name: Relative path within the SecLists repo
                  (e.g., "Discovery/Web-Content/common.txt").

        Returns:
            Local path where the file was saved.

        Raises:
            ValueError: If the name is empty or malformed.
            urllib.error.HTTPError: If the remote file is not found.
            urllib.error.URLError: If the download fails.
        """
        if not name or not name.strip():
            raise ValueError("SecList name cannot be empty")

        name = name.strip().lstrip("/")
        url = f"{SECLISTS_BASE_URL}{name}"
        dest = self.wordlists_dir / name
        dest.parent.mkdir(parents=True, exist_ok=True)

        try:
            req = urllib.request.Request(url, headers={"User-Agent": "T-100AI-WordlistLoader/1.0"})
            with urllib.request.urlopen(req, timeout=30) as response:
                data = response.read()
        except urllib.error.HTTPError as exc:
            logger.error("HTTP error downloading SecList '%s': %s", name, exc)
            raise
        except urllib.error.URLError as exc:
            logger.error("URL error downloading SecList '%s': %s", name, exc)
            raise

        try:
            content = data.decode("utf-8", errors="replace")
        except Exception as exc:
            raise ValueError(f"Failed to decode downloaded SecList: {name}") from exc

        with open(dest, "w", encoding="utf-8") as fh:
            fh.write(content)

        lines = [line.strip() for line in content.splitlines() if line.strip()]
        source = WordlistSource(
            name=Path(name).name,
            path=str(dest),
            type="downloaded",
            count=len(lines),
            loaded=True,
        )
        self._sources.append(source)

        logger.info("Downloaded SecList '%s' -> %s (%d entries)", name, dest, len(lines))

        return str(dest)

    def list_available_seclists(self) -> list[str]:
        """Return a list of known SecLists categories and paths.

        Returns:
            List of relative SecList paths available for download.
        """
        return list(SECLIST_CATEGORIES)

    def scan_directory(self, dir_path: str) -> list[WordlistSource]:
        """Scan a directory for wordlist files (.txt, .lst).

        Args:
            dir_path: Path to the directory to scan.

        Returns:
            List of WordlistSource objects for each discovered file.

        Raises:
            FileNotFoundError: If the directory does not exist.
            NotADirectoryError: If the path is not a directory.
        """
        path = Path(dir_path)

        if not path.exists():
            raise FileNotFoundError(f"Directory not found: {dir_path}")

        if not path.is_dir():
            raise NotADirectoryError(f"Path is not a directory: {dir_path}")

        sources: list[WordlistSource] = []
        wordlist_exts = {".txt", ".lst", ".wordlist", ".wl"}

        for file_path in sorted(path.rglob("*")):
            if file_path.is_file() and file_path.suffix.lower() in wordlist_exts:
                count = 0
                try:
                    with open(file_path, "r", encoding="utf-8", errors="replace") as fh:
                        count = sum(1 for line in fh if line.strip())
                except (PermissionError, OSError) as exc:
                    logger.warning("Cannot read file %s: %s", file_path, exc)

                source = WordlistSource(
                    name=file_path.name,
                    path=str(file_path),
                    type="external",
                    count=count,
                    loaded=False,
                )
                sources.append(source)

        logger.info("Scanned %s: found %d wordlist files", dir_path, len(sources))
        return sources

    def merge_wordlists(self, sources: list[str], output: str) -> str:
        """Merge multiple wordlist files into a single deduplicated output file.

        Args:
            sources: List of file paths to merge.
            output: Path for the merged output file.

        Returns:
            Path to the merged output file.

        Raises:
            ValueError: If sources list is empty.
            FileNotFoundError: If any source file does not exist.
        """
        if not sources:
            raise ValueError("No source wordlists provided for merging")

        seen: set[str] = set()
        total_entries = 0

        output_path = Path(output)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, "w", encoding="utf-8") as out_fh:
            for src in sources:
                src_path = Path(src)
                if not src_path.exists():
                    raise FileNotFoundError(f"Source wordlist not found: {src}")

                try:
                    with open(src_path, "r", encoding="utf-8", errors="replace") as in_fh:
                        for line in in_fh:
                            stripped = line.strip()
                            if stripped and stripped not in seen:
                                seen.add(stripped)
                                out_fh.write(stripped + "\n")
                                total_entries += 1
                except (PermissionError, OSError) as exc:
                    logger.warning("Skipping unreadable source %s: %s", src, exc)

        source = WordlistSource(
            name=output_path.name,
            path=str(output_path),
            type="external",
            count=total_entries,
            loaded=True,
        )
        self._sources.append(source)

        logger.info(
            "Merged %d wordlists -> %s (%d unique entries)",
            len(sources),
            output_path,
            total_entries,
        )

        return str(output_path)

    def get_stats(self) -> dict[str, Any]:
        """Return statistics about loaded wordlists.

        Returns:
            Dictionary with stats including total sources, total entries,
            entries by type, and per-source details.
        """
        total_entries = sum(s.count for s in self._sources)
        by_type: dict[str, int] = {}
        per_source: list[dict[str, Any]] = []

        for src in self._sources:
            by_type[src.type] = by_type.get(src.type, 0) + src.count
            per_source.append(
                {
                    "name": src.name,
                    "path": src.path,
                    "type": src.type,
                    "count": src.count,
                    "loaded": src.loaded,
                }
            )

        return {
            "total_sources": len(self._sources),
            "total_entries": total_entries,
            "by_type": by_type,
            "sources": per_source,
            "wordlists_dir": str(self.wordlists_dir),
        }
