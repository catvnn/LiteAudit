"""
scanner.py - shared scanning logic for the Streamlit app and the extension API.

No Streamlit or FastAPI imports here, so it can be used from anywhere.

Usage:
    from scanner import scan_bytes
    clean, findings = scan_bytes(file_bytes, "data.csv")
"""

import csv
import io
import math
import re
from collections import Counter

MAX_BYTES = 10 * 1024 * 1024          # refuse to scan files over 10 MB
BLOCK_SEVERITIES = {"high", "medium"}  # findings at these levels mark a file unsafe

# (rule name, regex, severity, description)
JS_PATTERNS = [
    ("script_tag", r"<\s*script\b", "high", "HTML <script> tag"),
    ("javascript_uri", r"javascript\s*:", "high", "javascript: URI"),
    ("eval_call", r"\beval\s*\(", "high", "eval() call"),
    ("function_constructor", r"\bnew\s+Function\s*\(", "high", "Function constructor"),
    ("document_write", r"document\s*\.\s*write(ln)?\s*\(", "high", "document.write()"),
    ("event_handler", r"\bon(error|load|click|mouseover|focus)\s*=", "high", "Inline event handler"),
    ("iframe_tag", r"<\s*iframe\b", "medium", "iframe tag"),
    ("string_timer", r"\bset(Timeout|Interval)\s*\(\s*['\"]", "medium", "Timer executing a string"),
    ("atob_call", r"\batob\s*\(", "medium", "Base64 decode (atob)"),
    ("unescape_call", r"\bunescape\s*\(", "medium", "unescape() call"),
    ("from_char_code", r"String\s*\.\s*fromCharCode", "medium", "fromCharCode (common in obfuscation)"),
    ("network_call", r"\b(XMLHttpRequest|fetch\s*\(|WebSocket)\b", "medium", "Network request from script"),
    ("redirect", r"(window|document)\s*\.\s*location\s*(\.href)?\s*=", "medium", "Page redirect"),
    ("webassembly", r"\bWebAssembly\b", "medium", "WebAssembly usage"),
    ("js_crypto", r"\b(CryptoJS|crypto\.subtle|AES\.encrypt|AES\.decrypt|sjcl)\b", "medium", "JavaScript encryption library/API"),
    ("cookie_access", r"document\s*\.\s*cookie", "medium", "Cookie access"),
]

OBFUSCATION_PATTERNS = [
    ("hex_escapes", r"(?:\\x[0-9a-fA-F]{2}){8,}", "medium", "Long run of \\x escapes"),
    ("unicode_escapes", r"(?:\\u[0-9a-fA-F]{4}){6,}", "medium", "Long run of \\u escapes"),
    ("base64_blob", r"[A-Za-z0-9+/]{200,}={0,2}", "medium", "Very long Base64-like string"),
]

# CSV cells that start with these can run as formulas when opened in Excel/Sheets
CSV_FORMULA_START = ("=", "+", "-", "@", "\t", "\r")
CSV_DANGEROUS = re.compile(
    r"(cmd\s*\||powershell|HYPERLINK\s*\(|IMPORTXML|IMPORTDATA|DDE\s*\(|WEBSERVICE\s*\()",
    re.IGNORECASE,
)
NUMBER_LIKE = re.compile(r"^[+-]?\d+([.,]\d+)*([eE][+-]?\d+)?%?$")


def _finding(rule, severity, description, line=None, snippet=None):
    return {
        "rule": rule,
        "severity": severity,
        "description": description,
        "line": line,
        "snippet": (snippet[:80] + "...") if snippet and len(snippet) > 80 else snippet,
    }


def _entropy(s):
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _scan_patterns(text):
    findings = []
    lines = text.splitlines()
    for rule, pattern, severity, desc in JS_PATTERNS + OBFUSCATION_PATTERNS:
        regex = re.compile(pattern, re.IGNORECASE)
        for i, line in enumerate(lines, start=1):
            m = regex.search(line)
            if m:
                findings.append(_finding(rule, severity, desc, i, m.group(0)))
                break  # one finding per rule is enough
    return findings


def _scan_entropy(text):
    """Flag very long, high-entropy lines (packed/encrypted payloads)."""
    findings = []
    for i, line in enumerate(text.splitlines(), start=1):
        if len(line) > 300 and _entropy(line) > 5.0:
            findings.append(_finding(
                "high_entropy_line", "medium",
                "Long high-entropy line (possible packed or encrypted payload)",
                i, line,
            ))
            break
    return findings


def _scan_csv(text):
    findings = []
    try:
        reader = csv.reader(io.StringIO(text))
        for row_num, row in enumerate(reader, start=1):
            for cell in row:
                c = cell.strip()
                if not c:
                    continue
                if c.startswith(CSV_FORMULA_START) and not NUMBER_LIKE.match(c):
                    sev = "high" if CSV_DANGEROUS.search(c) else "medium"
                    findings.append(_finding(
                        "csv_formula", sev,
                        "CSV cell starts like a spreadsheet formula (formula injection)",
                        row_num, c,
                    ))
                    return findings  # one is enough to flag the file
    except csv.Error as e:
        findings.append(_finding("csv_parse_error", "low", f"CSV could not be parsed: {e}"))
    return findings


def scan_bytes(data: bytes, filename: str = ""):
    """
    Scan file contents.

    Returns (clean, findings):
      clean    - True if nothing at a blocking severity was found
      findings - list of dicts: rule, severity, description, line, snippet
    """
    if len(data) > MAX_BYTES:
        return False, [_finding("too_large", "high", f"File exceeds {MAX_BYTES // (1024 * 1024)} MB scan limit")]

    # A NUL byte in a .txt/.csv usually means it is not really text
    if b"\x00" in data:
        return False, [_finding("binary_content", "high", "File contains binary data but claims to be text/CSV")]

    text = data.decode("utf-8", errors="replace")

    findings = []
    findings += _scan_patterns(text)
    findings += _scan_entropy(text)
    if filename.lower().endswith(".csv"):
        findings += _scan_csv(text)

    clean = not any(f["severity"] in BLOCK_SEVERITIES for f in findings)
    return clean, findings


if __name__ == "__main__":
    # Quick self-test: python scanner.py
    samples = {
        "safe.txt": b"Hello, this is a normal file.\nNothing to see here.",
        "bad.txt": b"<script>eval(atob('ZG9jdW1lbnQuY29va2ll'))</script>",
        "bad.csv": b"name,value\nAlice,=HYPERLINK(\"http://evil.test\",\"click\")\nBob,42",
        "ok.csv": b"name,balance\nAlice,-15.50\nBob,42",
    }
    for name, content in samples.items():
        ok, found = scan_bytes(content, name)
        print(f"{name}: {'CLEAN' if ok else 'BLOCKED'} ({len(found)} findings)")
