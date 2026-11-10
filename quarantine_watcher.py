"""
quarantine_watcher.py - scans files that Chrome saved into Downloads/LiteAudit_Quarantine.

Flow for every file in the quarantine folder:
    1. wait until Chrome has finished writing it
    2. read it into memory and scan it with scanner.py
    3. save the result to the LiteAudit database (shows up in the app)
    4. clean file   -> moved up into Downloads
       risky file   -> deleted
       review-needed -> held (default) or deleted, depending on --review

Run it from the same folder as liteaudit_app.py:
    python quarantine_watcher.py

Safety rule: it only ever touches regular files directly inside the
quarantine folder. It never deletes anything anywhere else.
"""

from __future__ import annotations

import argparse
import json
import shutil
import socket
import sqlite3
import time
from datetime import datetime
from pathlib import Path

from scanner import MAX_FILE_SIZE, scan_bytes

INCOMPLETE_SUFFIXES = {".crdownload", ".download", ".opdownload", ".part", ".partial", ".tmp"}
LOG_FILE = Path(__file__).resolve().parent / "watcher.log"
LOCK_PORT = 48621  # local port used only to make sure one watcher runs at a time
POLL_SECONDS = 1.0
STABLE_POLLS = 2  # size and mtime must be unchanged for this many polls in a row


def log(message: str) -> None:
    line = f"[{datetime.now():%Y-%m-%d %H:%M:%S}] {message}"
    print(line, flush=True)
    try:
        with LOG_FILE.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")
    except OSError:
        pass  # logging must never stop the watcher


def acquire_single_instance_lock() -> socket.socket | None:
    """Return a bound socket if we are the only watcher, otherwise None."""
    lock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        lock.bind(("127.0.0.1", LOCK_PORT))
    except OSError:
        lock.close()
        return None
    return lock


def unique_destination(folder: Path, name: str) -> Path:
    """Return a path in folder that does not overwrite an existing file."""
    candidate = folder / name
    stem, suffix = Path(name).stem, Path(name).suffix
    counter = 1
    while candidate.exists():
        candidate = folder / f"{stem} ({counter}){suffix}"
        counter += 1
    return candidate


def save_result(db_path: Path, filename: str, result: dict, size_bytes: int) -> None:
    """Insert one row into the same scans table the Streamlit app reads."""
    connection = sqlite3.connect(db_path, timeout=30)
    try:
        connection.execute(
            """
            INSERT INTO scans (
                filename, verdict, score, sha256, tone, scan_date,
                findings_json, file_size_bytes
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?);
            """,
            (
                filename,
                result["verdict"],
                int(result["score"]),
                result["sha256"],
                result["tone"],
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                json.dumps(result["findings"]),
                max(0, int(size_bytes)),
            ),
        )
        connection.commit()
    finally:
        connection.close()


def process_file(
    path: Path,
    quarantine: Path,
    downloads: Path,
    db_path: Path,
    review_action: str,
) -> str:
    """
    Scan and dispose of one file.
    Returns 'done' (finished), 'retry' (try again next poll) or 'skipped'.
    """
    if path.parent.resolve() != quarantine.resolve():
        return "skipped"

    try:
        size = path.stat().st_size
        if size > MAX_FILE_SIZE:
            log(f"SKIPPED {path.name}: larger than the scan limit; left in quarantine.")
            return "skipped"
        data = path.read_bytes()
    except OSError as error:
        log(f"Could not read {path.name} yet ({error}); will retry.")
        return "retry"

    clean, result = scan_bytes(data, path.name)
    tone = result["tone"]

    try:
        save_result(db_path, path.name, result, len(data))
    except sqlite3.Error as error:
        # Logging must never block the security decision.
        log(f"WARNING: could not save scan result to the database: {error}")

    try:
        if clean:
            destination = unique_destination(downloads, path.name)
            shutil.move(str(path), str(destination))
            log(f"CLEAN   {path.name} -> moved to {destination}")
        elif tone == "warn" and review_action == "hold":
            log(f"REVIEW  {path.name} (score {result['score']}) -> held in quarantine")
            return "skipped"
        else:
            path.unlink()
            log(f"BLOCKED {path.name} (score {result['score']}, {result['verdict']}) -> deleted")
    except OSError as error:
        log(f"Could not move/delete {path.name} ({error}); will retry.")
        return "retry"
    return "done"


def main() -> None:
    parser = argparse.ArgumentParser(description="Scan files in Downloads/LiteAudit_Quarantine.")
    parser.add_argument("--downloads", type=Path, default=Path.home() / "Downloads")
    parser.add_argument(
        "--db",
        type=Path,
        default=Path(__file__).resolve().parent / "my_data.db",
        help="LiteAudit database (default: my_data.db next to this script)",
    )
    parser.add_argument(
        "--review",
        choices=["delete", "hold"],
        default="hold",
        help="what to do with 'Review needed' files (default: hold)",
    )
    args = parser.parse_args()

    lock = acquire_single_instance_lock()
    if lock is None:
        log("Another quarantine watcher is already running; exiting.")
        return
    try:
        if LOG_FILE.exists() and LOG_FILE.stat().st_size > 1_000_000:
            LOG_FILE.replace(LOG_FILE.with_suffix(".old"))
    except OSError:
        pass

    downloads = args.downloads.expanduser().resolve()
    quarantine = downloads / "LiteAudit_Quarantine"
    quarantine.mkdir(parents=True, exist_ok=True)

    log(f"Watching   : {quarantine}")
    log(f"Clean files: moved to {downloads}")
    log(f"Database   : {args.db}" + ("" if args.db.exists() else "  (not found yet - run the app once first)"))
    log(f"Review mode: {args.review}")
    log("Press Ctrl+C to stop.")

    seen: dict[str, tuple[tuple[int, int], int]] = {}
    ignored: set[str] = set()

    try:
        while True:
            present: set[str] = set()
            for path in quarantine.iterdir():
                if path.is_symlink() or not path.is_file():
                    continue
                if path.suffix.lower() in INCOMPLETE_SUFFIXES or path.name.startswith("."):
                    continue
                if path.name in ignored:
                    continue
                present.add(path.name)
                try:
                    stat = path.stat()
                except OSError:
                    continue
                signature = (stat.st_size, stat.st_mtime_ns)
                previous = seen.get(path.name)
                count = previous[1] + 1 if previous and previous[0] == signature else 1
                seen[path.name] = (signature, count)

                if count >= STABLE_POLLS:
                    outcome = process_file(path, quarantine, downloads, args.db, args.review)
                    if outcome == "done":
                        seen.pop(path.name, None)
                    elif outcome == "skipped":
                        ignored.add(path.name)
                    else:
                        seen[path.name] = (signature, 0)

            for name in list(seen):
                if name not in present:
                    seen.pop(name, None)
            ignored.intersection_update(
                {p.name for p in quarantine.iterdir()} if quarantine.exists() else set()
            )
            time.sleep(POLL_SECONDS)
    except KeyboardInterrupt:
        log("Stopped.")


if __name__ == "__main__":
    main()
