"""Local filesystem helpers for the opt-in Downloads folder monitor."""

from pathlib import Path
from stat import S_ISREG
from typing import TypedDict


INCOMPLETE_DOWNLOAD_SUFFIXES = {
    ".crdownload",
    ".download",
    ".opdownload",
    ".part",
    ".partial",
    ".tmp",
}
MAX_DOWNLOAD_HISTORY = 50


class DownloadEntry(TypedDict):
    filename: str
    size_bytes: int
    modified_at: float
    suffix: str


def scan_download_folder(folder: Path) -> list[DownloadEntry]:
    """Return file metadata from one folder without opening file contents."""
    if not folder.is_dir():
        raise NotADirectoryError(f"Not a readable folder: {folder}")

    entries: list[DownloadEntry] = []
    for path in folder.iterdir():
        try:
            file_stat = path.stat()
        except FileNotFoundError:
            continue
        if not S_ISREG(file_stat.st_mode):
            continue
        entries.append(
            {
                "filename": path.name,
                "size_bytes": file_stat.st_size,
                "modified_at": file_stat.st_mtime,
                "suffix": path.suffix.lower(),
            }
        )

    entries.sort(key=lambda entry: entry["modified_at"], reverse=True)
    return entries


def update_download_history(
    entries: list[DownloadEntry],
    previous_snapshot: dict[str, int],
    history: dict[str, dict[str, object]],
    now: float,
) -> tuple[dict[str, int], dict[str, dict[str, object]]]:
    """Track detected writes after they stop changing or leave the folder."""
    current_snapshot: dict[str, int] = {}
    current_entries: dict[str, DownloadEntry] = {}
    active_names: set[str] = set()

    for entry in entries:
        filename = entry["filename"]
        size_bytes = entry["size_bytes"]
        current_snapshot[filename] = size_bytes
        current_entries[filename] = entry

        previous_size = previous_snapshot.get(filename)
        is_recent = now - entry["modified_at"] <= 5
        is_active = (
            entry["suffix"] in INCOMPLETE_DOWNLOAD_SUFFIXES
            or (previous_size is not None and previous_size != size_bytes)
            or (previous_size is None and is_recent)
        )
        if is_active:
            active_names.add(filename)
            history[filename] = {
                **entry,
                "state": (
                    "Temporary download file"
                    if entry["suffix"] in INCOMPLETE_DOWNLOAD_SUFFIXES
                    else (
                        "Writing"
                        if previous_size is not None and previous_size != size_bytes
                        else "Recently detected"
                    )
                ),
            }

    for filename, record in history.items():
        if filename in current_entries and filename not in active_names:
            record["state"] = "No longer changing"
        elif filename not in current_entries:
            record["state"] = "No longer in folder"

    retained = sorted(
        history.items(),
        key=lambda item: float(item[1]["modified_at"]),
        reverse=True,
    )[:MAX_DOWNLOAD_HISTORY]
    return current_snapshot, dict(retained)
