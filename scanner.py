"""
scanner.py - scanning logic shared by liteaudit_app.py and the quarantine watcher.

No Streamlit imports here, so it can run in any process.
This is the same scan_document the app uses today (with the three scan-option
flags), plus CSV support and a scan_bytes() wrapper for the watcher/API.
"""

from __future__ import annotations

import csv
import hashlib
import io
import re
from pathlib import Path

MAX_FILE_SIZE = 25 * 1024 * 1024  # default limit for the watcher (app has its own setting)

# Byte signatures used to flag common document and script indicators.
SIGNATURES = [
    (rb"/JavaScript\b|/JS\b", "Embedded JavaScript action", 35),
    (rb"/OpenAction\b|/AA\b", "Automatic document action", 25),
    (rb"/Launch\b", "External launch instruction", 35),
    (rb"/EmbeddedFile\b|/Filespec\b", "Embedded file payload", 20),
    (rb"/URI\s*\(", "External URI action", 10),
    (rb"<script\b|javascript\s*:", "Script injection pattern", 35),
    (rb"powershell(?:\.exe)?|cmd(?:\.exe)?|/bin/(?:ba)?sh", "Shell command reference", 30),
    (rb"eval\s*\(|exec\s*\(", "Dynamic code execution pattern", 25),
    (rb"(?:https?|ftp)://[^\s<>'\"]+", "External network reference", 8),
]

# Numbers like -15.50 or +1 555-123-4567 are normal CSV values, not formulas.
NUMBER_LIKE = re.compile(r"^[+-]?\d[\d.,\s()-]*%?$")


def _count_csv_formula_cells(data: bytes) -> int:
    """Count CSV cells that Excel/Sheets would treat as formulas."""
    hits = 0
    try:
        text = data.decode("utf-8", errors="replace")
        for row in csv.reader(io.StringIO(text)):
            for cell in row:
                c = cell.strip()
                if c and c[0] in "=+-@" and not NUMBER_LIKE.match(c):
                    hits += 1
    except csv.Error:
        pass
    return hits


def scan_document(
    file_name: str,
    data: bytes,
    check_signatures: bool = True,
    check_injections: bool = True,
    check_file_integrity: bool = True,
) -> dict:
    """Check file bytes for known indicators and return a simple risk report."""
    findings: list[dict] = []
    score = 0
    extension = Path(file_name).suffix.lower()

    if check_signatures or check_injections:
        for pattern, label, weight in SIGNATURES:
            if label == "Embedded file payload":
                continue
            is_injection_indicator = label in {
                "Script injection pattern",
                "Dynamic code execution pattern",
            }
            if is_injection_indicator and not check_injections:
                continue
            if not is_injection_indicator and not check_signatures:
                continue
            count = len(re.findall(pattern, data, flags=re.IGNORECASE))
            if count:
                findings.append({"indicator": label, "matches": count, "weight": weight})
                score += min(weight + max(0, count - 1) * 2, weight + 10)

    if check_injections and extension == ".csv":
        formula_hits = _count_csv_formula_cells(data)
        if formula_hits:
            findings.append(
                {
                    "indicator": "Spreadsheet formula injection pattern",
                    "matches": formula_hits,
                    "weight": 30,
                }
            )
            score += min(30 + max(0, formula_hits - 1) * 2, 40)

    if check_file_integrity:
        if extension == ".pdf":
            embedded_count = len(
                re.findall(rb"/EmbeddedFile\b|/Filespec\b", data, flags=re.IGNORECASE)
            )
            if embedded_count:
                findings.append(
                    {
                        "indicator": "Embedded file payload",
                        "matches": embedded_count,
                        "weight": 20,
                    }
                )
                score += min(20 + max(0, embedded_count - 1) * 2, 30)
        if extension == ".pdf" and not data.startswith(b"%PDF-"):
            findings.append(
                {
                    "indicator": "File extension and header do not match",
                    "matches": 1,
                    "weight": 40,
                }
            )
            score += 40
        if extension in {".txt", ".csv"} and b"\x00" in data:
            findings.append(
                {
                    "indicator": "Unexpected binary content in text file",
                    "matches": 1,
                    "weight": 20,
                }
            )
            score += 20

    score = min(score, 100)
    if score >= 50:
        verdict, tone = "High risk", "danger"
    elif score >= 15:
        verdict, tone = "Review needed", "warn"
    else:
        verdict, tone = "No known indicators", "safe"

    return {
        "verdict": verdict,
        "tone": tone,
        "score": score,
        "findings": findings,
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def scan_bytes(data: bytes, filename: str = ""):
    """
    Wrapper for the quarantine watcher / API.
    Returns (clean, result). clean is True only when the verdict is 'safe'.
    """
    if len(data) > MAX_FILE_SIZE:
        result = {
            "verdict": "High risk",
            "tone": "danger",
            "score": 100,
            "findings": [{"indicator": "File exceeds scan size limit", "matches": 1, "weight": 100}],
            "sha256": hashlib.sha256(data).hexdigest(),
        }
        return False, result
    result = scan_document(filename, data)
    return result["tone"] == "safe", result


if __name__ == "__main__":
    tests = {
        "safe.txt": b"Hello, normal file.",
        "bad.txt": b"<script>eval(atob('x'))</script>",
        "bad.csv": b"name,value\nAlice,=HYPERLINK(\"http://evil.test\",\"x\")\nBob,42",
        "ok.csv": b"name,balance\nAlice,-15.50\nBob,42",
    }
    for name, content in tests.items():
        ok, res = scan_bytes(content, name)
        print(f"{name}: {'CLEAN' if ok else 'BLOCKED'} score={res['score']} findings={len(res['findings'])}")
