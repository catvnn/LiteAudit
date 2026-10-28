"""LiteAudit — a polished Streamlit UI prototype for document verification.

Run with:
    pip install streamlit pandas
    streamlit run liteaudit_app.py

Enable the local Downloads folder monitor only when running LiteAudit on your
own computer:
    $env:LITEAUDIT_ENABLE_LOCAL_DOWNLOAD_MONITOR = "1"
    streamlit run liteaudit_app.py

This is a demonstration scanner, not a replacement for a production malware
analysis engine. Uploaded files are read into memory and are not written to disk.
"""

from __future__ import annotations

import hashlib
import os
import re
from datetime import datetime
from html import escape
from pathlib import Path

import pandas as pd
import streamlit as st

from database import get_db_connection, insert_scan_result
from download_monitor import scan_download_folder, update_download_history


def load_scan_history() -> pd.DataFrame:
    """Load scan records with IDs for individual selection and deletion."""
    query = """
    SELECT id, filename, verdict, score, sha256, tone, scan_date
    FROM scans
    ORDER BY scan_date DESC;
    """
    return pd.read_sql_query(query, get_db_connection())


def delete_scans(scan_ids: list[int]) -> int:
    """Delete selected scan records and clear cached query results."""
    if not scan_ids:
        return 0

    unique_ids = tuple(dict.fromkeys(scan_ids))
    placeholders = ", ".join("?" for _ in unique_ids)
    cursor = get_db_connection().cursor()
    cursor.execute(
        f"DELETE FROM scans WHERE id IN ({placeholders});",
        unique_ids,
    )
    cursor.connection.commit()
    st.cache_data.clear()
    return cursor.rowcount


# Configure the page before rendering any Streamlit elements.
st.set_page_config(
    page_title="LiteAudit · Document verification",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


# Apply the app's visual theme and component styles.
st.markdown(
    """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=Space+Mono:wght@400;700&display=swap');

    :root {
        --ink: #edf4f2;
        --muted: #8fa5a0;
        --panel: #111c1b;
        --panel-2: #162321;
        --line: #263a36;
        --mint: #4ee6b1;
        --amber: #f4b860;
        --red: #ff6b78;
    }

    html, body, [class*="css"] {
        font-family: "DM Sans", sans-serif;
    }

    .stApp {
        background: #091210;
        color: var(--ink);
    }

    [data-testid="stHeader"] {
        background: transparent;
    }

    [data-testid="stSidebar"] {
        background: #0d1715;
        border-right: 1px solid var(--line);
    }

    [data-testid="stSidebar"] > div:first-child {
        padding-top: 1.4rem;
    }

    .block-container {
        padding-top: 2.1rem;
        max-width: 1380px;
    }

    .brand {
        display: flex;
        align-items: center;
        gap: .75rem;
        margin-bottom: 2.2rem;
    }

    .brand-mark {
        width: 40px;
        height: 40px;
        border-radius: 12px;
        display: grid;
        place-items: center;
        background: linear-gradient(145deg, #62f3bf, #23b98a);
        color: #06120e;
        font-size: 20px;
        box-shadow: 0 0 24px rgba(78, 230, 177, .18);
    }

    .brand-name {
        font: 700 1.18rem "Space Mono";
        letter-spacing: -.04em;
    }

    .brand-name span {
        color: var(--mint);
    }

    .eyebrow {
        color: var(--mint);
        font: 700 .70rem "Space Mono";
        letter-spacing: .15em;
        text-transform: uppercase;
        margin-bottom: .55rem;
    }

    .hero-title {
        color: var(--ink);
        font-size: clamp(2rem, 4vw, 3.4rem);
        line-height: 1.03;
        letter-spacing: -.055em;
        font-weight: 700;
        max-width: 760px;
        margin: 0 0 .8rem;
    }

    .hero-copy {
        color: var(--muted);
        font-size: 1.02rem;
        line-height: 1.65;
        max-width: 720px;
        margin: 0;
    }

    .status-chip {
        display: inline-flex;
        gap: .5rem;
        align-items: center;
        color: #a8bdb8;
        background: #101c19;
        border: 1px solid var(--line);
        border-radius: 999px;
        padding: .45rem .75rem;
        font: 500 .72rem "Space Mono";
    }

    .status-dot {
        width: 7px;
        height: 7px;
        border-radius: 50%;
        background: var(--mint);
        box-shadow: 0 0 10px var(--mint);
    }

    .section-label {
        color: var(--ink);
        font-weight: 650;
        font-size: 1.05rem;
        margin: .4rem 0 .2rem;
    }

    .section-help {
        color: var(--muted);
        font-size: .83rem;
        margin-bottom: .7rem;
    }

    .trust-strip {
        margin: 1.3rem 0 1.6rem;
        display: flex;
        gap: 1.1rem;
        flex-wrap: wrap;
        color: #9eb1ad;
        font: 500 .72rem "Space Mono";
    }

    .trust-strip b {
        color: var(--mint);
    }

    [data-testid="stFileUploader"] {
        background: var(--panel);
        border: 1px solid var(--line);
        border-radius: 16px;
        padding: .4rem;
    }

    [data-testid="stFileUploader"] section {
        background: transparent;
        border: 1px dashed #38564f;
        border-radius: 12px;
        min-height: 180px;
    }

    [data-testid="stFileUploader"] section:hover {
        border-color: var(--mint);
        background: #12211d;
    }

    [data-testid="stFileUploaderDropzoneInstructions"] span {
        color: var(--ink);
    }

    [data-testid="stFileUploaderDropzoneInstructions"] small {
        color: var(--muted);
    }

    .metric-grid {
        display: grid;
        grid-template-columns: repeat(3, 1fr);
        gap: .65rem;
        margin: .8rem 0 1rem;
    }

    .metric-card {
        background: var(--panel-2);
        border: 1px solid var(--line);
        border-radius: 12px;
        padding: .8rem;
    }

    .metric-card small {
        color: var(--muted);
        font: 500 .62rem "Space Mono";
        text-transform: uppercase;
    }

    .metric-card strong {
        display: block;
        color: var(--ink);
        margin-top: .3rem;
        font-size: .92rem;
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
    }

    .result {
        border-radius: 16px;
        padding: 1.05rem 1.15rem;
        margin: .8rem 0;
        border: 1px solid;
    }

    .result.safe {
        background: #10231d;
        border-color: #285c4a;
    }

    .result.warn {
        background: #282014;
        border-color: #76552a;
    }

    .result.danger {
        background: #29171a;
        border-color: #76333b;
    }

    .result-head {
        display: flex;
        justify-content: space-between;
        align-items: center;
        gap: 1rem;
    }

    .result-title {
        font-weight: 700;
        font-size: 1.05rem;
    }

    .result-score {
        font: 700 .72rem "Space Mono";
        padding: .3rem .55rem;
        border-radius: 7px;
        background: rgba(0, 0, 0, .2);
    }

    .result-copy {
        color: #aabbb7;
        font-size: .83rem;
        margin-top: .45rem;
    }

    .history-head {
        display: flex;
        justify-content: space-between;
        align-items: end;
        margin-top: 1.5rem;
    }

    .history-count {
        color: var(--muted);
        font: 500 .72rem "Space Mono";
    }

    [data-testid="stDataFrame"] {
        border: 1px solid var(--line);
        border-radius: 14px;
        overflow: hidden;
    }

    div.stButton > button {
        border-radius: 10px;
        border: 1px solid #3e665b;
        background: #19332c;
        color: #a6f3d7;
        font-weight: 650;
        min-height: 2.75rem;
    }

    div.stButton > button:hover {
        border-color: var(--mint);
        color: #06120e;
        background: var(--mint);
    }

    div.stButton > button[kind="primary"] {
        background: var(--mint);
        border-color: var(--mint);
        color: #071511;
    }

    div.stButton > button[kind="primary"]:hover {
        background: #77f5c9;
        border-color: #77f5c9;
    }

    .side-label {
        color: #71847f;
        font: 700 .64rem "Space Mono";
        letter-spacing: .12em;
        text-transform: uppercase;
        margin: 1.25rem 0 .45rem;
    }

    .side-item {
        color: #c0ceca;
        padding: .62rem .75rem;
        border-radius: 9px;
        margin: .15rem 0;
        font-size: .86rem;
    }

    .side-item.active {
        background: #173028;
        color: #70efc3;
        border: 1px solid #28493f;
    }

    .side-card {
        border: 1px solid var(--line);
        background: #111d1a;
        border-radius: 12px;
        padding: .85rem;
        margin-top: 1.8rem;
        color: #96aaa5;
        font-size: .75rem;
        line-height: 1.5;
    }

    .side-card strong {
        color: var(--ink);
        display: block;
        margin-bottom: .25rem;
    }

    .footer-note {
        color: #667a75;
        font-size: .72rem;
        margin-top: 1rem;
        line-height: 1.5;
    }

    @media (max-width: 800px) {
        .metric-grid {
            grid-template-columns: 1fr;
        }

        .hero-title {
            font-size: 2.25rem;
        }
    }
    </style>
    """,
    unsafe_allow_html=True,
)


# Maximum file size accepted by the uploader (25 MiB).
MAX_FILE_SIZE = 25 * 1024 * 1024
LOCAL_DOWNLOAD_MONITOR_ENABLED = (
    os.environ.get("LITEAUDIT_ENABLE_LOCAL_DOWNLOAD_MONITOR") == "1"
)

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


def human_size(size: int) -> str:
    """Format a byte count as a readable file size."""
    value = float(size)
    for unit in ("B", "KB", "MB", "GB"):
        if value < 1024 or unit == "GB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{size} B"


def scan_document(file_name: str, data: bytes) -> dict:
    """Check file bytes for known indicators and return a simple risk report."""
    findings: list[dict] = []
    score = 0

    for pattern, label, weight in SIGNATURES:
        count = len(re.findall(pattern, data, flags=re.IGNORECASE))
        if count:
            findings.append({"indicator": label, "matches": count, "weight": weight})
            score += min(weight + max(0, count - 1) * 2, weight + 10)

    extension = Path(file_name).suffix.lower()
    if extension == ".pdf" and not data.startswith(b"%PDF-"):
        findings.append(
            {
                "indicator": "File extension and header do not match",
                "matches": 1,
                "weight": 40,
            }
        )
        score += 40
    if extension == ".txt" and b"\x00" in data:
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


# Render the application identity and status panel.
with st.sidebar:
    st.markdown(
        """
        <div class="brand">
            <div class="brand-mark">◇</div>
            <div class="brand-name">Lite<span>Audit</span></div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    st.markdown('<div class="side-label">Workspace</div>', unsafe_allow_html=True)
    if "selected_section" not in st.session_state:
        st.session_state.selected_section = "Document scanner"

    navigation_items = [
        ("◈", "Document scanner"),
        ("◷", "Audit history"),
        ("⌁", "Detection rules"),
    ]
    for icon, section in navigation_items:
        if st.button(
            f"{icon}  {section}",
            key=f"nav_{section}",
            type=(
                "primary"
                if st.session_state.selected_section == section
                else "secondary"
            ),
            use_container_width=True,
        ):
            st.session_state.selected_section = section
            st.rerun()

    selected_section = st.session_state.selected_section
    st.markdown(
        """
        <div class="side-card">
            <strong>Local-first protection</strong>
            Files are inspected in memory. Scan metadata is saved to the local audit database.
        </div>
        <div class="footer-note">Prototype engine · v0.8.2<br>Signature set updated today</div>
        """,
        unsafe_allow_html=True,
    )

if selected_section == "Document scanner":
    # Introduce the scanner and communicate its current status.
    top_left, top_right = st.columns([4, 1], vertical_alignment="top")
    with top_left:
        st.markdown(
            '<div class="eyebrow">Document verification</div>',
            unsafe_allow_html=True,
        )
        st.markdown(
            '<h1 class="hero-title">Inspect files before they enter your environment.</h1>',
            unsafe_allow_html=True,
        )
        st.markdown(
            '<p class="hero-copy">Upload a PDF or text document directly from your device. '
            "LiteAudit checks for suspicious scripts, automatic actions, embedded payloads, "
            "and unsafe links.</p>",
            unsafe_allow_html=True,
        )
    with top_right:
        st.markdown(
            '<div style="height:.25rem"></div><div class="status-chip">'
            '<span class="status-dot"></span> Scanner operational</div>',
            unsafe_allow_html=True,
        )

    # List the scanner's basic operating guarantees.
    st.markdown(
        '<div class="trust-strip">'
        "<span><b>✓</b> In-memory analysis</span>"
        "<span><b>✓</b> No file execution</span>"
        "<span><b>✓</b> PDF + TXT support</span>"
        "<span><b>✓</b> 200 MB maximum</span>"
        "</div>",
        unsafe_allow_html=True,
    )

    upload_col, result_col = st.columns([1.12, 0.88], gap="large")

    # Collect the document and show its basic metadata before scanning.
    with upload_col:
        st.markdown(
            '<div class="section-label">Upload a document</div>',
            unsafe_allow_html=True,
        )
        st.markdown(
            '<div class="section-help">The file is inspected directly—no prior download '
            "or local opening required.</div>",
            unsafe_allow_html=True,
        )
        uploaded_file = st.file_uploader(
            "Choose a PDF or TXT document",
            type=["pdf", "txt"],
            label_visibility="collapsed",
            help="Supported formats: PDF and plain text. Maximum file size: 200 MB.",
        )

        if uploaded_file:
            uploaded_bytes = uploaded_file.getvalue()
            safe_file_name = escape(uploaded_file.name)
            st.markdown(
                f"""
                <div class="metric-grid">
                    <div class="metric-card">
                        <small>File name</small><strong>{safe_file_name}</strong>
                    </div>
                    <div class="metric-card">
                        <small>File type</small>
                        <strong>{Path(uploaded_file.name).suffix[1:].upper()}</strong>
                    </div>
                    <div class="metric-card">
                        <small>File size</small>
                        <strong>{human_size(len(uploaded_bytes))}</strong>
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )
            scan_clicked = st.button(
                "Run secure scan  →",
                type="primary",
                use_container_width=True,
            )
        else:
            uploaded_bytes = b""
            scan_clicked = False

    # Run the static scan, save its metadata, and show its results.
    with result_col:
        st.markdown(
            '<div class="section-label">Verification result</div>',
            unsafe_allow_html=True,
        )
        st.markdown(
            '<div class="section-help">Results appear here after the static analysis completes.</div>',
            unsafe_allow_html=True,
        )

        if scan_clicked and uploaded_file:
            if len(uploaded_bytes) > MAX_FILE_SIZE:
                st.error("This file is larger than the 200 MB prototype limit.")
            else:
                result = scan_document(uploaded_file.name, uploaded_bytes)
                scan_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                insert_scan_result(
                    filename=uploaded_file.name,
                    verdict=result["verdict"],
                    score=result["score"],
                    sha256=result["sha256"],
                    tone=result["tone"],
                    scan_date=scan_date,
                )

                icon = {"safe": "✓", "warn": "!", "danger": "×"}[result["tone"]]
                copy = {
                    "safe": "No suspicious signatures were detected by the prototype rules.",
                    "warn": "One or more indicators should be reviewed before the document is trusted.",
                    "danger": "Multiple or high-severity indicators were found. Keep this file isolated.",
                }[result["tone"]]
                st.markdown(
                    f"""
                    <div class="result {result['tone']}">
                        <div class="result-head">
                            <div class="result-title">
                                {icon} &nbsp;{result['verdict']}
                            </div>
                            <div class="result-score">
                                RISK {result['score']:02d}/100
                            </div>
                        </div>
                        <div class="result-copy">{copy}</div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

                if result["findings"]:
                    with st.expander(
                        f"View {len(result['findings'])} detected indicator(s)",
                        expanded=True,
                    ):
                        for finding in result["findings"]:
                            st.write(
                                f"• {finding['indicator']} — "
                                f"{finding['matches']} match(es)"
                            )
                else:
                    st.success("Static signature checks completed successfully.")

                with st.expander("File fingerprint"):
                    st.code(result["sha256"], language=None)
        else:
            st.markdown(
                """
                <div style="height:260px;border:1px solid #263a36;border-radius:16px;background:#101a18;
                    display:grid;place-items:center;text-align:center;padding:2rem;color:#728782;">
                    <div><div style="font-size:2rem;color:#3e5b54;margin-bottom:.7rem;">⌁</div>
                    Waiting for a document<br><span style="font-size:.76rem;">Upload a file and start the scan</span></div>
                </div>
                """,
                unsafe_allow_html=True,
            )

    @st.fragment(run_every="2s")
    def render_background_downloads() -> None:
        st.markdown(
            '<div class="section-label">Background downloads</div>',
            unsafe_allow_html=True,
        )
        st.markdown(
            '<div class="section-help">Optional local monitoring for files being written '
            'to a folder path on the computer running LiteAudit.</div>',
            unsafe_allow_html=True,
        )
        st.markdown(
            '<div id="liteaudit-downloads-monitor"></div>',
            unsafe_allow_html=True,
        )
        monitoring_enabled = st.toggle(
            "Monitor this folder path",
            key="local_download_monitor_enabled",
            disabled=not LOCAL_DOWNLOAD_MONITOR_ENABLED,
            help="Monitors files in the path below only when LiteAudit is running "
            "on the computer that owns that path.",
        )
        downloads_folder = st.text_input(
            "Folder path to monitor",
            value=str(Path.home() / "Downloads"),
            key="local_download_folder",
            help="Enter an absolute path, such as C:\\Users\\you\\Downloads.",
            disabled=not LOCAL_DOWNLOAD_MONITOR_ENABLED,
        )

        if not LOCAL_DOWNLOAD_MONITOR_ENABLED:
            st.info(
                "Typed paths can only be monitored when LiteAudit runs locally on "
                "the computer that owns the folder. The hosted app cannot access "
                "your computer’s paths."
            )
            st.code(
                '$env:LITEAUDIT_ENABLE_LOCAL_DOWNLOAD_MONITOR = "1"\n'
                "streamlit run liteaudit_app.py",
                language="powershell",
            )
            return

        folder = Path(downloads_folder).expanduser()
        try:
            folder_key = str(folder.resolve())
        except OSError as error:
            st.error(f"Could not resolve this folder path: {error}")
            return

        histories = st.session_state.setdefault("local_download_history", {})
        folder_history = histories.get(folder_key, {})
        if st.button(
            "Clear detected files",
            key="clear_download_history",
            disabled=not folder_history,
        ):
            histories[folder_key] = {}
            st.session_state.setdefault("local_download_snapshots", {})[
                folder_key
            ] = {}
            st.rerun()

        if not monitoring_enabled:
            st.info("Monitoring is off. Turn it on to watch the folder path above.")
            if folder_history:
                display_history = [
                    {
                        "File": record["filename"],
                        "Size": human_size(int(record["size_bytes"])),
                        "Status": record["state"],
                        "Last changed": datetime.fromtimestamp(
                            float(record["modified_at"])
                        ).strftime("%Y-%m-%d %H:%M:%S"),
                    }
                    for record in folder_history.values()
                ]
                st.dataframe(
                    pd.DataFrame(display_history),
                    width="stretch",
                    hide_index=True,
                )
            return

        try:
            entries = scan_download_folder(folder)
        except OSError as error:
            st.error(f"Could not monitor this folder: {error}")
            return

        snapshots = st.session_state.setdefault("local_download_snapshots", {})
        previous_snapshot = snapshots.get(folder_key, {})
        now = datetime.now().timestamp()
        current_snapshot, folder_history = update_download_history(
            entries,
            previous_snapshot,
            folder_history,
            now,
        )
        snapshots[folder_key] = current_snapshot
        histories[folder_key] = folder_history

        if folder_history:
            display_entries = [
                {
                    "File": record["filename"],
                    "Size": human_size(int(record["size_bytes"])),
                    "Status": record["state"],
                    "Last changed": datetime.fromtimestamp(
                        float(record["modified_at"])
                    ).strftime("%Y-%m-%d %H:%M:%S"),
                }
                for record in folder_history.values()
            ]
            st.dataframe(
                pd.DataFrame(display_entries),
                width="stretch",
                hide_index=True,
            )
        else:
            st.info("No files have been detected yet.")
        st.caption(
            "Checks every 2 seconds while this page is open. File names and sizes are "
            "shown; file contents are never read. Detected files remain in this list "
            "after they stop changing. Use Clear detected files to clear the history. "
            "Any app writing to this folder may appear. Up to 50 recent files are kept."
        )

    render_background_downloads()

elif selected_section == "Audit history":
    # Display persisted scan metadata from the local SQLite database.
    st.markdown(
        '<div class="section-label">Audit history</div>',
        unsafe_allow_html=True,
    )
    st.markdown(
        '<div class="section-help">Saved scan results from the local database.</div>',
        unsafe_allow_html=True,
    )
    if "delete_selection_version" not in st.session_state:
        st.session_state.delete_selection_version = 0
    if "deleted_scans_notice" in st.session_state:
        st.success(st.session_state.pop("deleted_scans_notice"))

    history_df = load_scan_history()
    if history_df.empty:
        st.info("No scans have been saved yet. Scan a document to create the first record.")
    else:
        scan_labels = {
            int(row.id): (
                f"{row.filename} — {row.scan_date} — {row.verdict} "
                f"(record #{row.id})"
            )
            for row in history_df.itertuples(index=False)
        }
        selection_version = st.session_state.delete_selection_version
        selected_scan_ids = st.multiselect(
            "Select entries to delete",
            options=list(scan_labels),
            format_func=scan_labels.__getitem__,
            key=f"selected_scan_ids_{selection_version}",
            help="Each entry is selected by its unique database record ID.",
        )
        confirm_delete = st.checkbox(
            "I confirm deleting the selected database entries.",
            key=f"confirm_delete_scans_{selection_version}",
            disabled=not selected_scan_ids,
        )
        if st.button(
            "Delete selected entries",
            type="secondary",
            disabled=not selected_scan_ids or not confirm_delete,
        ):
            deleted_count = delete_scans(selected_scan_ids)
            st.session_state.deleted_scans_notice = (
                f"Deleted {deleted_count} database entr"
                f"{'y' if deleted_count == 1 else 'ies'}."
            )
            st.session_state.delete_selection_version += 1
            st.rerun()

        st.dataframe(
            history_df,
            use_container_width=True,
            hide_index=True,
            height=420,
            column_order=[
                "filename",
                "verdict",
                "score",
                "sha256",
                "tone",
                "scan_date",
            ],
            column_config={
                "filename": st.column_config.TextColumn("FILE NAME", width="large"),
                "verdict": st.column_config.TextColumn("VERDICT", width="medium"),
                "score": st.column_config.NumberColumn("RISK SCORE", width="small"),
                "sha256": st.column_config.TextColumn("SHA-256", width="large"),
                "tone": st.column_config.TextColumn("STATUS", width="small"),
                "scan_date": st.column_config.TextColumn("SCAN DATE", width="medium"),
            },
        )

else:
    # Explain the currently active byte-pattern checks and risk thresholds.
    st.markdown(
        '<div class="section-label">Detection rules</div>',
        unsafe_allow_html=True,
    )
    st.markdown(
        '<div class="section-help">Static indicators used by the document scanner.</div>',
        unsafe_allow_html=True,
    )
    rules_df = pd.DataFrame(
        [
            {
                "Indicator": label,
                "Pattern": pattern.decode("ascii"),
                "Weight": weight,
            }
            for pattern, label, weight in SIGNATURES
        ]
    )
    st.dataframe(
        rules_df,
        use_container_width=True,
        hide_index=True,
        column_config={
            "Indicator": st.column_config.TextColumn("INDICATOR", width="medium"),
            "Pattern": st.column_config.TextColumn("BYTE PATTERN", width="large"),
            "Weight": st.column_config.NumberColumn("RISK WEIGHT", width="small"),
        },
    )
    st.markdown("#### Additional file checks")
    st.markdown(
        "- PDF files are checked for a matching `%PDF-` header.\n"
        "- Text files are checked for unexpected null bytes.\n"
        "- Each indicator contributes to the score; the final score is capped at 100."
    )
    st.markdown("#### Result thresholds")
    st.markdown(
        "- **0–14:** No known indicators\n"
        "- **15–49:** Review needed\n"
        "- **50–100:** High risk"
    )

st.caption("LiteAudit prototype yayyyyyy")
