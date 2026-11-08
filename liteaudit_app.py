"""LiteAudit — a polished Streamlit UI prototype for document verification.

Run with:
    pip install streamlit pandas
    streamlit run liteaudit_app.py

Enable the local Downloads folder monitor only when running LiteAudit on your
own computer:
    $env:LITEAUDIT_ENABLE_LOCAL_DOWNLOAD_MONITOR = "1"
    streamlit run liteaudit_app.py --server.address 127.0.0.1 --server.port 8501

The Chrome extension popup embeds this local app at:
    http://127.0.0.1:8501/?embed=true&embed_options=show_toolbar

This is a demonstration scanner, not a replacement for a production malware
analysis engine. Uploaded files are read into memory and are not written to disk.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
from datetime import datetime
from html import escape
from pathlib import Path

import altair as alt
import pandas as pd
import streamlit as st

from database import (
    delete_users,
    delete_scans_before,
    get_all_scans,
    get_app_setting,
    get_critical_threats,
    get_daily_scan_metrics,
    get_db_connection,
    get_duplicate_uploads,
    get_executable_scans,
    get_recent_scans,
    get_suspicious_scans,
    get_users,
    get_verdict_metrics,
    insert_scan_result,
    insert_user,
    lookup_file_hash,
    search_executables,
    set_app_setting,
    update_user,
)
from download_monitor import scan_download_folder, update_download_history


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

st.session_state.setdefault(
    "light_mode",
    get_app_setting("theme", "dark") == "light",
)
st.session_state.setdefault(
    "local_download_monitor_enabled",
    get_app_setting("download_monitor_enabled", "false") == "true",
)
st.session_state.setdefault(
    "local_download_folder",
    get_app_setting("download_monitor_folder", str(Path.home() / "Downloads")),
)
configured_max_file_size = get_app_setting("max_file_size_mb", "25")
try:
    MAX_FILE_SIZE_MB = max(1, min(25, int(configured_max_file_size)))
except ValueError:
    MAX_FILE_SIZE_MB = 25
MAX_FILE_SIZE = MAX_FILE_SIZE_MB * 1024 * 1024


def record_workspace_notification(
    title: str,
    detail: str,
    destination: str,
    notification_id: str | None = None,
) -> None:
    """Persist one local notification event without duplicating stable event IDs."""
    events_setting = get_app_setting("notification_events", "[]")
    try:
        events = json.loads(events_setting)
    except json.JSONDecodeError as error:
        raise ValueError("Saved notification events are not valid JSON.") from error
    if not isinstance(events, list) or any(
        not isinstance(event, dict)
        or not all(
            isinstance(event.get(field), str)
            for field in ("id", "title", "detail", "destination", "created_at")
        )
        for event in events
    ):
        raise ValueError("Saved notification events have an invalid format.")

    event_id = notification_id or hashlib.sha256(
        (
            f"{datetime.now().isoformat(timespec='microseconds')}|"
            f"{title}|{detail}|{destination}"
        ).encode("utf-8")
    ).hexdigest()
    if any(event["id"] == event_id for event in events):
        return

    events.append(
        {
            "id": event_id,
            "title": title,
            "detail": detail,
            "destination": destination,
            "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }
    )
    set_app_setting("notification_events", json.dumps(events[-100:]))


def record_settings_change(detail: str) -> None:
    """Record a meaningful settings update for the shared notification center."""
    record_workspace_notification(
        "Settings updated",
        detail,
        "Settings",
    )


def save_theme_preference() -> None:
    """Persist the sidebar theme selection."""
    selected_theme = "light" if st.session_state.light_mode else "dark"
    saved_theme = get_app_setting("theme", "dark")
    if selected_theme != saved_theme:
        set_app_setting("theme", selected_theme)
        record_settings_change(
            f"Appearance theme changed to {selected_theme} mode."
        )


def save_settings_theme_preference() -> None:
    """Keep the Settings theme choice synchronized with the shared app theme."""
    light_mode_selected = (
        st.session_state["settings-theme-choice"] == "Light Mode"
    )
    st.session_state["light_mode"] = light_mode_selected
    selected_theme = "light" if light_mode_selected else "dark"
    saved_theme = get_app_setting("theme", "dark")
    if selected_theme != saved_theme:
        set_app_setting("theme", selected_theme)
        record_settings_change(
            f"Appearance theme changed to {selected_theme} mode."
        )


def save_download_monitor_settings() -> None:
    """Persist local download-monitor preferences and record real changes."""
    enabled = bool(st.session_state.local_download_monitor_enabled)
    folder = str(st.session_state.local_download_folder).strip()
    if not folder:
        st.error("Choose a folder path before saving download-monitor settings.")
        st.session_state.local_download_folder = get_app_setting(
            "download_monitor_folder",
            str(Path.home() / "Downloads"),
        )
        return

    saved_enabled = get_app_setting("download_monitor_enabled", "false") == "true"
    saved_folder = get_app_setting(
        "download_monitor_folder",
        str(Path.home() / "Downloads"),
    )
    changes: list[str] = []
    if enabled != saved_enabled:
        changes.append(
            f"Local folder monitoring {'enabled' if enabled else 'disabled'}."
        )
        set_app_setting("download_monitor_enabled", "true" if enabled else "false")
    if folder != saved_folder:
        changes.append("Monitored folder path updated.")
        set_app_setting("download_monitor_folder", folder)
    if changes:
        record_settings_change(" ".join(changes))


theme_colors = {
    "page": "#eef4fc" if st.session_state.light_mode else "#071326",
    "sidebar": "#e4edfa" if st.session_state.light_mode else "#081a33",
    "ink": "#102341" if st.session_state.light_mode else "#e8f0ff",
    "muted": "#536987" if st.session_state.light_mode else "#9aaccb",
    "panel": "#ffffff" if st.session_state.light_mode else "#0d1f3a",
    "panel_2": "#f3f7fd" if st.session_state.light_mode else "#10284a",
    "line": "#c9d8ee" if st.session_state.light_mode else "#203b63",
    "accent": "#1769d2" if st.session_state.light_mode else "#2f8cff",
    "accent_hover": "#0c54b5" if st.session_state.light_mode else "#57a3ff",
    "accent_soft": "#dceaff" if st.session_state.light_mode else "#102f57",
    "button_text": "#ffffff",
    "note_bg": "#fff7e8" if st.session_state.light_mode else "#25233a",
    "note_line": "#e6c77e" if st.session_state.light_mode else "#55507f",
    "note_text": "#664e20" if st.session_state.light_mode else "#ddd5ff",
    "safe_bg": "#e7f8f0" if st.session_state.light_mode else "#0d302d",
    "safe_line": "#93d5b6" if st.session_state.light_mode else "#23635a",
    "warn_bg": "#fff5df" if st.session_state.light_mode else "#302a1e",
    "warn_line": "#e8c67b" if st.session_state.light_mode else "#705b32",
    "danger_bg": "#fff0f1" if st.session_state.light_mode else "#321e2b",
    "danger_line": "#e6a3ac" if st.session_state.light_mode else "#753a50",
    "trust": "#405878" if st.session_state.light_mode else "#a9bbd8",
}
theme_css_vars = "\n".join(
    f"--{name.replace('_', '-')}: {value};" for name, value in theme_colors.items()
)
st.markdown(
    f"<style>:root {{ {theme_css_vars} }}</style>",
    unsafe_allow_html=True,
)


# Apply the app's visual theme and component styles.
st.markdown(
    """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=Space+Mono:wght@400;700&display=swap');

    html, body, [class*="css"] {
        font-family: "DM Sans", sans-serif;
    }

    .stApp {
        background:
            radial-gradient(ellipse at top right, var(--accent-soft), transparent 42%),
            var(--page);
        color: var(--ink);
    }

    [data-testid="stAppViewContainer"] {
        background: transparent;
    }

    [data-testid="stHeader"] {
        background: transparent;
    }

    [data-testid="stSidebar"] [data-testid="stBaseButton-headerNoPadding"],
    [data-testid="stExpandSidebarButton"] {
        display: flex !important;
        width: 2.35rem !important;
        height: 2.35rem !important;
        align-items: center;
        justify-content: center;
        border: 1px solid rgba(75, 137, 245, .3) !important;
        border-radius: 999px !important;
        background: var(--panel) !important;
        color: #315e9d !important;
        box-shadow: 0 2px 8px rgba(8, 26, 51, .12) !important;
        opacity: 1 !important;
        visibility: visible !important;
    }

    [data-testid="stSidebar"] [data-testid="stBaseButton-headerNoPadding"]:hover,
    [data-testid="stExpandSidebarButton"]:hover {
        background: var(--accent-soft);
        color: var(--accent);
    }

    [data-testid="stSidebar"] {
        background: var(--sidebar);
        border-right: 1px solid var(--line);
    }

    [data-testid="stSidebar"] > div:first-child {
        padding: 1.25rem .85rem 1rem;
    }

    .block-container {
        padding-top: 1.65rem;
        padding-bottom: 2.5rem;
        max-width: 1440px;
    }

    .brand {
        display: flex;
        align-items: center;
        gap: .7rem;
        margin: 0 .35rem 1.4rem;
        padding: 0 0 1.15rem;
        border-bottom: 1px solid var(--line);
    }

    .brand-mark {
        width: 38px;
        height: 38px;
        display: grid;
        place-items: center;
        color: #65b5ff;
        flex: 0 0 auto;
    }

    .brand-mark svg {
        width: 36px;
        height: 36px;
    }

    .brand-name {
        color: var(--ink);
        font: 700 1.08rem "DM Sans", sans-serif;
        letter-spacing: -.04em;
    }

    .brand-name span {
        color: var(--accent);
    }

    .brand-tagline {
        margin-top: -.1rem;
        color: var(--muted);
        font-size: .58rem;
        letter-spacing: .01em;
    }

    .eyebrow {
        color: var(--accent);
        font: 700 .70rem "Space Mono";
        letter-spacing: .15em;
        text-transform: uppercase;
        margin-bottom: .45rem;
    }

    .hero-title {
        color: var(--ink);
        font-size: clamp(1.8rem, 3vw, 2.65rem);
        line-height: 1.12;
        letter-spacing: -.04em;
        font-weight: 700;
        max-width: 900px;
        margin: 0 0 .55rem;
    }

    .hero-copy {
        color: var(--muted);
        font-size: .96rem;
        line-height: 1.6;
        max-width: 800px;
        margin: 0;
    }

    .guide-card {
        height: 100%;
        min-height: 180px;
        background: var(--panel);
        border: 1px solid var(--line);
        border-radius: 12px;
        padding: 1.1rem;
        box-shadow: 0 8px 22px rgba(2, 12, 28, .08);
    }

    .guide-number {
        color: var(--accent);
        font: 700 .72rem "Space Mono";
        letter-spacing: .12em;
        text-transform: uppercase;
        margin-bottom: .85rem;
    }

    .guide-card h3 {
        color: var(--ink);
        font-size: 1.05rem;
        margin: 0 0 .45rem;
    }

    .guide-card p {
        color: var(--muted);
        font-size: .86rem;
        line-height: 1.6;
        margin: 0;
    }

    .guide-note {
        border: 1px solid var(--note-line);
        background: var(--note-bg);
        border-radius: 10px;
        color: var(--note-text);
        padding: 1rem 1.1rem;
        line-height: 1.6;
        margin: 1.2rem 0;
    }

    .status-chip {
        display: inline-flex;
        gap: .5rem;
        align-items: center;
        color: var(--muted);
        background: var(--panel);
        border: 1px solid var(--line);
        border-radius: 8px;
        padding: .4rem .65rem;
        font: 500 .72rem "Space Mono";
    }

    .status-dot {
        width: 7px;
        height: 7px;
        border-radius: 50%;
        background: #22c55e;
        box-shadow: 0 0 10px #22c55e;
    }

    .section-label {
        color: var(--ink);
        font-weight: 650;
        font-size: 1.12rem;
        margin: .4rem 0 .2rem;
    }

    .section-help {
        color: var(--muted);
        font-size: .83rem;
        margin-bottom: .7rem;
    }

    .rules-table {
        width: 100%;
        border-collapse: collapse;
        color: var(--ink);
        font-size: .9rem;
    }

    .rules-table th,
    .rules-table td {
        padding: .65rem .75rem;
        border-bottom: 1px solid var(--line);
        text-align: left;
    }

    .rules-table th {
        color: var(--muted);
        font: 700 .7rem "Space Mono";
        letter-spacing: .06em;
    }

    .rules-table td:nth-child(2) {
        overflow-wrap: anywhere;
        font: .78rem "Space Mono";
    }

    .rule-indicator {
        text-decoration: underline dotted var(--muted);
        text-underline-offset: .2em;
        cursor: help;
    }

    .rule-indicator:focus-visible {
        outline: 2px solid var(--accent);
        outline-offset: 3px;
    }

    .trust-strip {
        margin: 1.3rem 0 1.6rem;
        display: flex;
        gap: 1.1rem;
        flex-wrap: wrap;
        color: var(--trust);
        font: 500 .72rem "Space Mono";
    }

    .trust-strip b {
        color: var(--accent);
    }

    [data-testid="stFileUploader"] {
        background: var(--panel);
        border: 1px solid var(--line);
        border-radius: 16px;
        padding: .4rem;
    }

    [data-testid="stFileUploader"] section {
        background: transparent;
        border: 1px dashed var(--line);
        border-radius: 12px;
        min-height: 180px;
    }

    [data-testid="stFileUploader"] section:hover {
        border-color: var(--accent);
        background: var(--accent-soft);
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

    .dashboard-table-wrap {
        overflow-x: auto;
        border: 1px solid var(--line);
        border-radius: 10px;
        background: var(--panel);
    }

    .dashboard-table {
        width: 100%;
        border-collapse: collapse;
        color: var(--ink);
        font-size: .84rem;
    }

    .dashboard-table th {
        padding: .8rem .85rem;
        background: var(--panel-2);
        color: var(--muted);
        font: 700 .66rem "Space Mono";
        letter-spacing: .06em;
        text-align: left;
        white-space: nowrap;
    }

    .dashboard-table td {
        padding: .75rem .85rem;
        border-top: 1px solid var(--line);
        color: var(--ink);
        vertical-align: middle;
    }

    .dashboard-table tbody tr:hover {
        background: var(--accent-soft);
    }

    .dashboard-table td:first-child {
        max-width: 28rem;
        overflow-wrap: anywhere;
    }

    .verdict-badge {
        display: inline-block;
        padding: .2rem .48rem;
        border-radius: 999px;
        font-size: .72rem;
        font-weight: 650;
        white-space: nowrap;
    }

    .verdict-badge.safe {
        color: #16794c;
        background: #dff5e9;
    }

    .verdict-badge.warn {
        color: #8a5b08;
        background: #fff0c9;
    }

    .verdict-badge.danger {
        color: #a42f43;
        background: #fde1e5;
    }

    .page-panel {
        height: 100%;
        padding: 1rem;
        border: 1px solid var(--line);
        border-radius: 11px;
        background: var(--panel);
    }

    .result {
        border-radius: 16px;
        padding: 1.05rem 1.15rem;
        margin: .8rem 0;
        border: 1px solid;
    }

    .result.safe {
        background: var(--safe-bg);
        border-color: var(--safe-line);
    }

    .result.warn {
        background: var(--warn-bg);
        border-color: var(--warn-line);
    }

    .result.danger {
        background: var(--danger-bg);
        border-color: var(--danger-line);
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
        background: color-mix(in srgb, var(--ink) 8%, transparent);
    }

    .result-copy {
        color: var(--muted);
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
        border-radius: 10px;
        overflow: hidden;
    }

    div.stButton > button {
        border-radius: 8px;
        border: 1px solid var(--line);
        background: var(--panel);
        color: var(--ink);
        font-weight: 650;
        min-height: 2.55rem;
        transition: border-color .15s ease, background .15s ease, box-shadow .15s ease;
    }

    div.stButton > button:hover {
        border-color: var(--accent);
        color: var(--button-text);
        background: var(--accent);
        box-shadow: 0 4px 12px rgba(20, 91, 190, .16);
    }

    div.stButton > button[kind="primary"] {
        background: var(--accent);
        border-color: var(--accent);
        color: var(--button-text);
        box-shadow: 0 6px 16px rgba(20, 91, 190, .18);
    }

    div.stButton > button[kind="primary"]:hover {
        background: var(--accent-hover);
        border-color: var(--accent-hover);
    }

    .side-label {
        color: var(--muted);
        font: 700 .64rem "Space Mono";
        letter-spacing: .12em;
        text-transform: uppercase;
        margin: 1.05rem .35rem .4rem;
    }

    .side-item {
        color: var(--ink);
        padding: .62rem .75rem;
        border-radius: 9px;
        margin: .15rem 0;
        font-size: .86rem;
    }

    .side-item.active {
        background: var(--accent-soft);
        color: var(--accent);
        border: 1px solid var(--line);
    }

    .side-card {
        border: 1px solid var(--line);
        background: var(--panel);
        border-radius: 12px;
        padding: .85rem;
        margin-top: 1.8rem;
        color: var(--muted);
        font-size: .75rem;
        line-height: 1.5;
    }

    .side-card strong {
        color: var(--ink);
        display: block;
        margin-bottom: .25rem;
    }

    .footer-note {
        color: var(--muted);
        font-size: .72rem;
        margin-top: 1rem;
        line-height: 1.5;
    }

    [class*="st-key-nav_"] {
        margin: .12rem 0;
    }

    [class*="st-key-nav_"] button {
        justify-content: flex-start;
        text-align: left;
        padding-left: .85rem;
        font-weight: 550;
    }

    [class*="st-key-nav_"] button > div {
        width: 100%;
        justify-content: flex-start;
    }

    [data-testid="stMetric"] {
        height: 100%;
        padding: 1rem 1.05rem;
        border: 1px solid var(--line);
        border-radius: 11px;
        background: var(--panel);
        box-shadow: 0 7px 20px rgba(2, 12, 28, .08);
    }

    [data-testid="stMetricLabel"] {
        color: var(--muted);
        font-size: .78rem;
        font-weight: 600;
    }

    [data-testid="stMetricValue"] {
        color: var(--ink);
        font-weight: 700;
    }

    [data-testid="stTabs"] [role="tab"] {
        color: var(--muted);
        font-weight: 600;
    }

    [data-testid="stTabs"] [role="tab"][aria-selected="true"] {
        color: var(--accent);
    }

    [data-testid="stExpander"] {
        border: 1px solid var(--line);
        border-radius: 10px;
        background: var(--panel);
    }

    [data-testid="stAlert"] {
        border-radius: 10px;
    }

    [data-testid="stCaptionContainer"] {
        color: var(--muted);
    }

    [data-testid="stTextInput"] input,
    [data-testid="stNumberInput"] input,
    [data-testid="stSelectbox"] [role="combobox"],
    [data-testid="stMultiSelect"] [role="combobox"],
    [data-testid="stTextArea"] textarea {
        background: var(--panel);
        color: var(--ink);
        border-color: var(--line);
    }

    [data-testid="stToggle"] label,
    [data-testid="stRadio"] label {
        color: var(--ink);
    }

    [data-testid="stToggle"] {
        padding: .55rem .7rem;
        margin: .35rem 0 1rem;
        border: 1px solid var(--line);
        border-radius: 10px;
        background: var(--panel);
    }

    [data-testid="stDataFrame"] {
        border: 1px solid var(--line);
        border-radius: 12px;
        overflow: hidden;
    }

    .stApp:has(.file-scanner-root) .block-container {
        padding-top: .75rem;
        max-width: 1440px;
    }

    .stApp:has(.file-scanner-root) [data-testid="stSidebar"] {
        --sidebar: #0c1932;
        --ink: #edf4ff;
        --muted: #a8bbd8;
        --panel: #132849;
        --line: #233d65;
        --accent: #4b89f5;
        --accent-soft: #1d3965;
        background: #0c1932;
    }

    .file-scanner-header {
        display: flex;
        align-items: flex-start;
        justify-content: space-between;
        gap: 1.25rem;
        margin: .15rem 0 1.2rem;
    }

    .file-scanner-title {
        margin: 0;
        color: var(--ink);
        font-size: clamp(1.9rem, 3vw, 2.45rem);
        font-weight: 750;
        letter-spacing: -.045em;
        line-height: 1.08;
    }

    .file-scanner-subtitle {
        margin: .35rem 0 0;
        color: var(--muted);
        font-size: .98rem;
    }

    .file-scanner-header-tools {
        display: flex;
        align-items: center;
        gap: .75rem;
        padding-top: .15rem;
        color: var(--ink);
        white-space: nowrap;
    }

    .file-scanner-header-alert {
        position: relative;
        font-size: 1.2rem;
    }

    .file-scanner-header-alert span {
        position: absolute;
        top: -.35rem;
        right: -.5rem;
        display: grid;
        min-width: 1rem;
        height: 1rem;
        place-items: center;
        padding: 0 .15rem;
        border-radius: 999px;
        background: #e34747;
        color: #fff;
        font-size: .6rem;
        font-weight: 700;
    }

    .file-scanner-header-user {
        color: var(--ink);
        font-size: .75rem;
        font-weight: 650;
    }

    .file-scanner-workspace {
        display: grid;
        grid-template-columns: minmax(0, 1.65fr) minmax(255px, .85fr);
        gap: 1rem;
        align-items: stretch;
    }

    .stApp:has(.file-scanner-root) .st-key-file-upload-card,
    .stApp:has(.file-scanner-root) .st-key-file-options-card {
        min-height: 17rem;
        padding: 1.1rem;
        border: 1px solid var(--line);
        border-radius: 14px;
        background: var(--panel);
        box-shadow: 0 5px 16px rgba(13, 46, 92, .07);
    }

    .file-scanner-upload-heading {
        margin: 0 0 .25rem;
        color: var(--ink);
        font-size: 1.05rem;
        font-weight: 750;
    }

    .file-scanner-upload-help {
        margin: 0 0 .75rem;
        color: var(--muted);
        font-size: .78rem;
    }

    .file-scanner-selected-list {
        display: grid;
        gap: .35rem;
        margin-top: .65rem;
    }

    .file-scanner-selected-heading {
        margin-bottom: .1rem;
        color: var(--ink);
        font-size: .78rem;
        font-weight: 750;
    }

    .file-scanner-selected-row {
        display: flex;
        min-width: 0;
        align-items: center;
        gap: .6rem;
        padding: .4rem .55rem;
        border: 1px solid var(--line);
        border-radius: 8px;
        background: var(--panel);
    }

    .file-scanner-selected-icon {
        display: grid;
        width: 1.65rem;
        height: 1.65rem;
        flex: 0 0 auto;
        place-items: center;
        border-radius: 6px;
        background: var(--accent-soft);
        color: var(--accent);
        font-size: .8rem;
        font-weight: 750;
    }

    .file-scanner-selected-meta {
        display: flex;
        min-width: 0;
        flex: 1;
        align-items: baseline;
        justify-content: space-between;
        gap: .5rem;
    }

    .file-scanner-selected-name {
        overflow: hidden;
        color: var(--ink);
        font-size: .75rem;
        font-weight: 650;
        text-overflow: ellipsis;
        white-space: nowrap;
    }

    .file-scanner-selected-size {
        flex: 0 0 auto;
        color: var(--muted);
        font-size: .68rem;
    }

    .file-scanner-selected-total {
        color: var(--muted);
        font-size: .68rem;
    }

    .stApp:has(.file-scanner-root) .st-key-file-upload-card [data-testid="stFileUploader"] {
        min-height: 12rem;
        padding: .4rem;
        border: 2px dashed #7ba7fa;
        border-radius: 12px;
        background: var(--panel-2);
    }

    .stApp:has(.file-scanner-root) .st-key-file-upload-card [data-testid="stFileUploader"] section {
        min-height: 10.7rem;
        border: 0;
        background: transparent;
    }

    .stApp:has(.file-scanner-root) .st-key-file-upload-card [data-testid="stFileUploaderDropzone"] {
        display: flex;
        flex-direction: column;
        justify-content: center;
        gap: .3rem;
        padding: .8rem;
    }

    .stApp:has(.file-scanner-root) .st-key-file-upload-card [data-testid="stFileUploaderDropzone"]::before {
        content: "☁";
        color: #4a80ec;
        font-size: 3rem;
        font-weight: 700;
        line-height: 1;
    }

    .stApp:has(.file-scanner-root) .st-key-file-upload-card [data-testid="stFileUploaderDropzone"]::after {
        content: "Drag and drop files here or click to browse";
        color: var(--ink);
        font-size: .9rem;
        font-weight: 700;
    }

    .stApp:has(.file-scanner-root) [data-testid="stFileUploaderDropzoneInstructions"] span {
        color: var(--ink);
    }

    .stApp:has(.file-scanner-root) [data-testid="stFileUploaderDropzoneInstructions"] small {
        color: var(--muted);
    }

    .file-scanner-options-heading {
        margin: 0 0 .65rem;
        color: var(--ink);
        font-size: 1.05rem;
        font-weight: 750;
    }

    .stApp:has(.file-scanner-root) .st-key-file-options-card [data-testid="stCheckbox"] {
        margin: .15rem 0;
    }

    .file-scanner-section-heading {
        margin: .3rem 0 .75rem;
        color: var(--ink);
        font-size: 1.12rem;
        font-weight: 750;
    }

    .file-scanner-results {
        overflow: hidden;
        border: 1px solid var(--line);
        border-radius: 13px;
        background: var(--panel);
    }

    .file-scanner-table-header,
    .file-scanner-table-row {
        display: grid;
        grid-template-columns: minmax(135px, 2.1fr) minmax(48px, .65fr)
            minmax(70px, .8fr) minmax(90px, 1fr) minmax(70px, .8fr) 4rem;
        gap: .45rem;
        align-items: center;
        padding: .55rem .75rem;
    }

    .file-scanner-table-header {
        background: var(--panel-2);
        color: var(--muted);
        font-size: .69rem;
        font-weight: 750;
    }

    .file-scanner-table-row {
        min-height: 3rem;
        border-top: 1px solid var(--line);
        color: var(--ink);
        font-size: .79rem;
    }

    .stApp:has(.file-scanner-root) [class*="st-key-scan-result-row-"] {
        padding: .15rem .65rem;
        border-top: 1px solid var(--line);
    }

    .file-scanner-table-name {
        overflow: hidden;
        font-weight: 650;
        text-overflow: ellipsis;
        white-space: nowrap;
    }

    .file-scanner-pill {
        display: inline-block;
        width: fit-content;
        padding: .22rem .5rem;
        border-radius: 999px;
        font-size: .68rem;
        font-weight: 700;
        white-space: nowrap;
    }

    .file-scanner-pill.safe { background: #e2f5e8; color: #258044; }
    .file-scanner-pill.warn { background: #fff1c9; color: #8a640c; }
    .file-scanner-pill.danger { background: #fde4e4; color: #a32c39; }

    .stApp:has(.file-scanner-root) [class*="st-key-view_scan_"] button {
        min-height: 1.9rem;
        padding: .15rem .5rem;
        border: 1px solid #78a5fa;
        border-radius: 7px;
        background: transparent;
        color: var(--accent);
        font-size: .72rem;
    }

    .file-scanner-view-panel {
        margin-top: .85rem;
        padding: .85rem 1rem;
        border: 1px solid var(--line);
        border-radius: 10px;
        background: var(--panel-2);
    }

    @media (max-width: 900px) {
        .file-scanner-workspace {
            grid-template-columns: 1fr;
        }

        .file-scanner-table-header,
        .file-scanner-table-row {
            grid-template-columns: minmax(110px, 2fr) minmax(42px, .55fr)
                minmax(60px, .75fr) minmax(82px, 1fr) minmax(62px, .75fr) 3.6rem;
            gap: .25rem;
            padding-right: .45rem;
            padding-left: .45rem;
            font-size: .68rem;
        }
    }

    .stApp:has(.threat-detection-root) .block-container {
        padding-top: .75rem;
        max-width: 1440px;
    }

    .stApp:has(.threat-detection-root) [data-testid="stSidebar"] {
        --sidebar: #0c1932;
        --ink: #edf4ff;
        --muted: #a8bbd8;
        --panel: #132849;
        --line: #233d65;
        --accent: #4b89f5;
        --accent-soft: #1d3965;
        background: #0c1932;
    }

    .threat-detection-header {
        margin: .15rem 0 1.2rem;
    }

    .threat-detection-title {
        margin: 0;
        color: var(--ink);
        font-size: clamp(1.9rem, 3vw, 2.45rem);
        font-weight: 750;
        letter-spacing: -.045em;
        line-height: 1.08;
    }

    .threat-detection-subtitle {
        margin: .35rem 0 0;
        color: var(--muted);
        font-size: .98rem;
    }

    .threat-detection-workspace {
        display: grid;
        grid-template-columns: minmax(225px, .75fr) minmax(0, 1.75fr);
        gap: 1rem;
        align-items: stretch;
    }

    .stApp:has(.threat-detection-root) .st-key-threat-file-list,
    .stApp:has(.threat-detection-root) .st-key-threat-detail-panel {
        min-height: 34rem;
        padding: 1rem;
        border: 1px solid var(--line);
        border-radius: 14px;
        background: var(--panel);
        box-shadow: 0 5px 16px rgba(13, 46, 92, .07);
    }

    .threat-panel-title {
        margin: 0 0 .7rem;
        color: var(--ink);
        font-size: 1.05rem;
        font-weight: 750;
    }

    .stApp:has(.threat-detection-root) .st-key-threat-search input {
        border-color: var(--line);
        background: var(--panel-2);
    }

    .stApp:has(.threat-detection-root) [class*="st-key-threat-select-"] {
        margin: .2rem 0;
    }

    .stApp:has(.threat-detection-root) [class*="st-key-threat-select-"] button {
        min-height: 3.8rem;
        justify-content: flex-start;
        border: 1px solid transparent;
        border-left: 3px solid transparent;
        border-radius: 8px;
        background: transparent;
        color: var(--ink);
        text-align: left;
        white-space: pre-line;
        box-shadow: none;
    }

    .stApp:has(.threat-detection-root) [class*="st-key-threat-select-"] button:hover {
        border-color: var(--line);
        border-left-color: var(--accent);
        background: var(--panel-2);
        color: var(--ink);
        box-shadow: none;
    }

    .stApp:has(.threat-detection-root) [class*="st-key-threat-select-active-"] button {
        border-color: var(--line);
        border-left-color: #e34747;
        background: var(--accent-soft);
        color: var(--ink);
    }

    .threat-file-heading {
        display: flex;
        align-items: center;
        gap: .9rem;
        margin: .15rem 0 .9rem;
    }

    .threat-file-icon {
        display: grid;
        width: 3.3rem;
        height: 3.6rem;
        flex: 0 0 auto;
        place-items: center;
        border-radius: 10px;
        background: #e34b4b;
        color: #fff;
        font-size: 1.55rem;
    }

    .threat-file-icon.safe { background: #45a95c; }
    .threat-file-icon.warn { background: #d7a721; }

    .threat-file-name {
        overflow-wrap: anywhere;
        color: var(--ink);
        font-size: 1.35rem;
        font-weight: 750;
        line-height: 1.2;
    }

    .threat-file-level {
        margin-top: .25rem;
        color: var(--muted);
        font-size: .86rem;
    }

    .threat-file-level strong.high { color: #d94d4d; }
    .threat-file-level strong.medium { color: #d7a721; }
    .threat-file-level strong.low { color: #45a95c; }

    .stApp:has(.threat-detection-root) [data-testid="stTabs"] {
        margin-top: .4rem;
    }

    .stApp:has(.threat-detection-root) [data-testid="stTabs"] [role="tab"] {
        padding: .55rem .85rem;
        color: var(--muted);
        font-size: .9rem;
    }

    .stApp:has(.threat-detection-root) [data-testid="stTabs"] [role="tab"][aria-selected="true"] {
        color: var(--accent);
        font-weight: 750;
    }

    .threat-alert-card {
        display: flex;
        align-items: center;
        gap: .9rem;
        margin: .65rem 0 .9rem;
        padding: .95rem 1rem;
        border: 1px solid #e8b8bc;
        border-radius: 11px;
        background: #fff0f0;
        color: #6f252b;
    }

    .threat-alert-card.safe {
        border-color: #a9d8b7;
        background: #eaf7ed;
        color: #235a34;
    }

    .threat-alert-icon {
        flex: 0 0 auto;
        font-size: 1.65rem;
    }

    .threat-alert-copy strong {
        display: block;
        margin-bottom: .15rem;
        font-size: .98rem;
    }

    .threat-alert-copy span {
        font-size: .8rem;
        line-height: 1.45;
    }

    .threat-indicator-card,
    .threat-detail-card {
        padding: .9rem 1rem;
        border: 1px solid var(--line);
        border-radius: 11px;
        background: var(--panel-2);
    }

    .threat-indicator-card h3,
    .threat-detail-card h3 {
        margin: 0 0 .65rem;
        color: var(--ink);
        font-size: 1rem;
    }

    .threat-indicator-row {
        display: flex;
        align-items: flex-start;
        gap: .55rem;
        padding: .35rem 0;
        color: var(--ink);
        font-size: .82rem;
        line-height: 1.4;
    }

    .threat-indicator-dot {
        display: inline-block;
        width: .62rem;
        height: .62rem;
        flex: 0 0 auto;
        margin-top: .2rem;
        border-radius: 50%;
        background: #df4c4c;
    }

    .threat-meta-grid {
        display: grid;
        grid-template-columns: repeat(2, minmax(0, 1fr));
        gap: .7rem;
        margin: .6rem 0;
    }

    .threat-meta-item {
        padding: .7rem;
        border: 1px solid var(--line);
        border-radius: 9px;
        background: var(--panel-2);
    }

    .threat-meta-item span {
        display: block;
        margin-bottom: .2rem;
        color: var(--muted);
        font-size: .68rem;
    }

    .threat-meta-item strong {
        color: var(--ink);
        font-size: .8rem;
        overflow-wrap: anywhere;
    }

    @media (max-width: 850px) {
        .threat-detection-workspace {
            grid-template-columns: 1fr;
        }

        .stApp:has(.threat-detection-root) .st-key-threat-file-list,
        .stApp:has(.threat-detection-root) .st-key-threat-detail-panel {
            min-height: auto;
        }
    }

    .stApp:has(.audit-history-root) .block-container {
        max-width: 1440px;
        padding-top: .75rem;
    }

    .stApp:has(.audit-history-root) [data-testid="stSidebar"] {
        --sidebar: #0c1932;
        --ink: #edf4ff;
        --muted: #a8bbd8;
        --panel: #132849;
        --line: #233d65;
        --accent: #4b89f5;
        --accent-soft: #1d3965;
        background: #0c1932;
    }

    .audit-history-header {
        margin: .15rem 0 1.15rem;
    }

    .audit-history-title {
        margin: 0;
        color: var(--ink);
        font-size: clamp(1.9rem, 3vw, 2.45rem);
        font-weight: 750;
        letter-spacing: -.045em;
        line-height: 1.08;
    }

    .audit-history-subtitle {
        margin: .35rem 0 0;
        color: var(--muted);
        font-size: .98rem;
    }

    .stApp:has(.audit-history-root) [data-testid="stHorizontalBlock"] {
        align-items: end;
        gap: .65rem;
    }

    .stApp:has(.audit-history-root) .st-key-history-search input,
    .stApp:has(.audit-history-root) .st-key-history-result-filter [data-baseweb="select"],
    .stApp:has(.audit-history-root) .st-key-history-date-filter [data-baseweb="select"] {
        min-height: 3.2rem;
        border-radius: 9px;
        background: var(--panel);
    }

    .stApp:has(.audit-history-root) .st-key-history-export button {
        min-height: 3.2rem;
        border: 0;
        border-radius: 9px;
        background: #3867e8;
        color: #fff;
        font-weight: 700;
    }

    .stApp:has(.audit-history-root) .st-key-history-export button:hover {
        background: #2d58d0;
        color: #fff;
    }

    .audit-history-table-wrap {
        margin-top: .75rem;
        overflow-x: auto;
        border: 1px solid var(--line);
        border-radius: 12px;
        background: var(--panel);
        box-shadow: 0 5px 16px rgba(13, 46, 92, .06);
    }

    .audit-history-table {
        width: 100%;
        border-collapse: collapse;
        color: var(--ink);
        font-size: .84rem;
    }

    .audit-history-table th {
        padding: .8rem .9rem;
        background: var(--panel-2);
        color: var(--ink);
        font-size: .76rem;
        font-weight: 750;
        text-align: left;
        white-space: nowrap;
    }

    .audit-history-table td {
        padding: .82rem .9rem;
        border-top: 1px solid var(--line);
        white-space: nowrap;
    }

    .audit-history-table tbody tr:hover {
        background: var(--panel-2);
    }

    .audit-history-result,
    .audit-history-level {
        display: inline-flex;
        align-items: center;
        gap: .4rem;
        padding: .26rem .65rem;
        border-radius: 999px;
        font-size: .77rem;
        font-weight: 700;
    }

    .audit-history-result.safe,
    .audit-history-level.low {
        background: #e2f5e8;
        color: #258044;
    }

    .audit-history-result.warn,
    .audit-history-level.medium {
        background: #fff1c9;
        color: #8a640c;
    }

    .audit-history-result.danger,
    .audit-history-level.high {
        background: #fde4e4;
        color: #a32c39;
    }

    .audit-history-pagination {
        display: flex;
        justify-content: center;
        gap: .4rem;
        padding: .9rem;
        border-top: 1px solid var(--line);
        background: var(--panel);
    }

    .stApp:has(.audit-history-root) [class*="st-key-history-page-"] button {
        min-width: 2.35rem;
        min-height: 2.35rem;
        padding: .25rem .55rem;
    }

    .stApp:has(.audit-history-root) [class*="st-key-history-page-active-"] button {
        border-color: #3867e8;
        background: #3867e8;
        color: #fff;
    }

    .stApp:has(.audit-history-root) .st-key-history-delete-panel {
        margin-top: 1rem;
    }

    @media (max-width: 850px) {
        .audit-history-table {
            min-width: 690px;
        }
    }

    .stApp:has(.activity-monitor-root) .block-container {
        max-width: 1440px;
        padding-top: .75rem;
    }

    .stApp:has(.activity-monitor-root) [data-testid="stSidebar"] {
        --sidebar: #0c1932;
        --ink: #edf4ff;
        --muted: #a8bbd8;
        --panel: #132849;
        --line: #233d65;
        --accent: #4b89f5;
        --accent-soft: #1d3965;
        background: #0c1932;
    }

    .activity-monitor-header {
        margin: .15rem 0 1.15rem;
    }

    .activity-monitor-title {
        margin: 0;
        color: var(--ink);
        font-size: clamp(1.9rem, 3vw, 2.45rem);
        font-weight: 750;
        letter-spacing: -.045em;
        line-height: 1.08;
    }

    .activity-monitor-subtitle {
        margin: .35rem 0 0;
        color: var(--muted);
        font-size: .98rem;
    }

    .stApp:has(.activity-monitor-root) [data-testid="stMetric"] {
        min-height: 5.2rem;
        padding: .8rem 1rem;
        border: 1px solid var(--line);
        border-radius: 11px;
        background: var(--panel);
        box-shadow: none;
    }

    .stApp:has(.activity-monitor-root) [data-testid="stTabs"] {
        margin-top: .75rem;
    }

    .stApp:has(.activity-monitor-root) [data-testid="stTabs"] [role="tab"] {
        padding: .6rem .8rem;
        color: var(--muted);
        font-size: .9rem;
    }

    .stApp:has(.activity-monitor-root) [data-testid="stTabs"] [role="tab"][aria-selected="true"] {
        color: var(--accent);
        font-weight: 750;
    }

    .activity-table-heading {
        display: grid;
        grid-template-columns: 1.05fr 2fr 1.5fr 1fr .8fr;
        gap: .6rem;
        padding: .75rem .8rem;
        border-radius: 9px 9px 0 0;
        background: var(--panel-2);
        color: var(--ink);
        font-size: .75rem;
        font-weight: 750;
    }

    .stApp:has(.activity-monitor-root) [class*="st-key-activity-row-"] {
        padding: .25rem .8rem;
        border: 1px solid var(--line);
        border-top: 0;
        background: var(--panel);
    }

    .stApp:has(.activity-monitor-root) [class*="st-key-activity-row-"] [data-testid="stHorizontalBlock"] {
        align-items: center;
        gap: .6rem;
    }

    .activity-table-cell {
        overflow: hidden;
        color: var(--ink);
        font-size: .78rem;
        text-overflow: ellipsis;
        white-space: nowrap;
    }

    .activity-status {
        display: inline-flex;
        align-items: center;
        gap: .28rem;
        padding: .2rem .48rem;
        border-radius: 999px;
        font-size: .69rem;
        font-weight: 700;
        white-space: nowrap;
    }

    .activity-status.scanned {
        background: #e2f5e8;
        color: #258044;
    }

    .activity-status.unscanned {
        background: #fff1c9;
        color: #8a640c;
    }

    .activity-status.suspicious {
        background: #fde4e4;
        color: #a32c39;
    }

    .stApp:has(.activity-monitor-root) [class*="st-key-activity-scan-"] button {
        min-height: 1.9rem;
        padding: .15rem .55rem;
        border: 1px solid #78a5fa;
        border-radius: 7px;
        background: #3867e8;
        color: #fff;
        font-size: .72rem;
    }

    .stApp:has(.activity-monitor-root) [class*="st-key-activity-view-"] button {
        min-height: 1.9rem;
        padding: .15rem .55rem;
        border: 1px solid #78a5fa;
        border-radius: 7px;
        background: transparent;
        color: var(--accent);
        font-size: .72rem;
    }

    .stApp:has(.activity-monitor-root) .st-key-activity-monitor-settings {
        margin-top: .85rem;
    }

    @media (max-width: 850px) {
        .activity-table-heading {
            min-width: 680px;
        }

        .stApp:has(.activity-monitor-root) [class*="st-key-activity-row-"] {
            min-width: 680px;
        }
    }

    .stApp:has(.user-management-root) .block-container {
        max-width: 1440px;
        padding-top: .75rem;
    }

    .stApp:has(.user-management-root) [data-testid="stSidebar"] {
        --sidebar: #0c1932;
        --ink: #edf4ff;
        --muted: #a8bbd8;
        --panel: #132849;
        --line: #233d65;
        --accent: #4b89f5;
        --accent-soft: #1d3965;
        background: #0c1932;
    }

    .user-management-header {
        margin: .15rem 0 1.15rem;
    }

    .user-management-title {
        margin: 0;
        color: var(--ink);
        font-size: clamp(1.9rem, 3vw, 2.45rem);
        font-weight: 750;
        letter-spacing: -.045em;
        line-height: 1.08;
    }

    .user-management-subtitle {
        margin: .35rem 0 0;
        color: var(--muted);
        font-size: .98rem;
    }

    .user-management-actions {
        display: flex;
        justify-content: flex-end;
        margin: -.25rem 0 .55rem;
    }

    .user-management-table {
        overflow-x: auto;
        border: 1px solid var(--line);
        border-radius: 12px;
        background: var(--panel);
        box-shadow: 0 5px 16px rgba(13, 46, 92, .06);
    }

    .stApp:has(.user-management-root) .st-key-user-management-table {
        overflow-x: auto;
        border: 1px solid var(--line);
        border-radius: 12px;
        background: var(--panel);
        box-shadow: 0 5px 16px rgba(13, 46, 92, .06);
    }

    .stApp:has(.user-management-root) .st-key-user-management-table [data-testid="stHorizontalBlock"]:first-child {
        padding: .35rem .45rem;
        background: var(--panel-2);
    }

    .user-management-table-header {
        padding: .75rem .45rem;
        color: var(--ink);
        font-size: .76rem;
        font-weight: 750;
    }

    .stApp:has(.user-management-root) [class*="st-key-user-row-"] {
        min-width: 810px;
        padding: .12rem .45rem;
        border-top: 1px solid var(--line);
        background: var(--panel);
    }

    .user-management-cell {
        overflow: hidden;
        color: var(--ink);
        font-size: .79rem;
        text-overflow: ellipsis;
        white-space: nowrap;
    }

    .user-status {
        display: inline-block;
        width: fit-content;
        padding: .25rem .65rem;
        border-radius: 999px;
        font-size: .72rem;
        font-weight: 700;
    }

    .user-status.active {
        background: #e2f5e8;
        color: #258044;
    }

    .user-status.inactive {
        background: #e8edf4;
        color: #59697f;
    }

    .stApp:has(.user-management-root) [class*="st-key-user-edit-"] button,
    .stApp:has(.user-management-root) [class*="st-key-user-delete-"] button {
        min-height: 2rem;
        padding: .15rem .4rem;
        border: 1px solid transparent;
        background: transparent;
        color: var(--accent);
        font-size: .8rem;
    }

    .stApp:has(.user-management-root) .st-key-user-add-button button {
        min-height: 2.65rem;
        border: 0;
        border-radius: 8px;
        background: #3867e8;
        color: #fff;
        font-weight: 700;
    }

    .stApp:has(.user-management-root) .st-key-user-add-button button:hover {
        background: #2d58d0;
        color: #fff;
    }

    .stApp:has(.user-management-root) [data-testid="stExpander"] {
        margin-top: .85rem;
    }

    @media (max-width: 850px) {
        .stApp:has(.user-management-root) [class*="st-key-user-row-"] {
            min-width: 810px;
        }
    }

    .stApp:has(.reports-analytics-root) .block-container {
        max-width: 1440px;
        padding-top: .75rem;
    }

    .stApp:has(.reports-analytics-root) [data-testid="stSidebar"] {
        --sidebar: #0c1932;
        --ink: #edf4ff;
        --muted: #a8bbd8;
        --panel: #132849;
        --line: #233d65;
        --accent: #4b89f5;
        --accent-soft: #1d3965;
        background: #0c1932;
    }

    .reports-analytics-header {
        margin: .15rem 0 .75rem;
    }

    .reports-analytics-title {
        margin: 0;
        color: var(--ink);
        font-size: clamp(1.9rem, 3vw, 2.45rem);
        font-weight: 750;
        letter-spacing: -.045em;
        line-height: 1.08;
    }

    .reports-analytics-subtitle {
        margin: .3rem 0 0;
        color: var(--muted);
        font-size: .96rem;
    }

    .stApp:has(.reports-analytics-root) [data-testid="stTabs"] {
        margin: .3rem 0 .55rem;
    }

    .stApp:has(.reports-analytics-root) [data-testid="stTabs"] [role="tab"] {
        padding: .5rem .85rem;
        color: var(--muted);
        font-size: .86rem;
    }

    .stApp:has(.reports-analytics-root) [data-testid="stTabs"] [role="tab"][aria-selected="true"] {
        color: var(--accent);
        font-weight: 750;
    }

    .reports-overview-section {
        margin: .25rem 0 .55rem;
        color: var(--ink);
        font-size: .88rem;
        font-weight: 750;
    }

    .reports-metric-card {
        padding: .65rem .75rem;
        border: 1px solid var(--line);
        border-radius: 11px;
        background: var(--panel);
        box-shadow: 0 4px 12px rgba(13, 46, 92, .04);
    }

    .stApp:has(.reports-analytics-root) .st-key-reports-scan-chart {
        min-height: 15rem;
        padding: .65rem .75rem;
        border: 1px solid var(--line);
        border-radius: 11px;
        background: var(--panel);
        box-shadow: 0 4px 12px rgba(13, 46, 92, .04);
    }

    .reports-metric-card {
        min-height: 5.2rem;
        margin-bottom: .6rem;
    }

    .reports-metric-label {
        color: var(--muted);
        font-size: .72rem;
        font-weight: 650;
    }

    .reports-metric-value {
        margin-top: .25rem;
        color: var(--ink);
        font-size: 1.42rem;
        font-weight: 780;
        line-height: 1.1;
    }

    .reports-overview-actions {
        margin-top: .45rem;
    }

    .stApp:has(.reports-analytics-root) .st-key-reports-generate button {
        min-height: 2.65rem;
        border: 0;
        border-radius: 8px;
        background: #3867e8;
        color: #fff;
        font-weight: 700;
    }

    .stApp:has(.reports-analytics-root) .st-key-reports-export-pdf button,
    .stApp:has(.reports-analytics-root) .st-key-reports-export-csv button {
        min-height: 2.65rem;
        border: 1px solid #78a5fa;
        border-radius: 8px;
        background: transparent;
        color: var(--accent);
        font-weight: 700;
    }

    .stApp:has(.reports-analytics-root) [data-testid="stDataFrame"] {
        border: 1px solid var(--line);
        border-radius: 10px;
        overflow: hidden;
    }

    @media (max-width: 850px) {
        .reports-overview-columns {
            flex-direction: column;
        }
    }

    .stApp:has(.settings-root) .block-container {
        max-width: 1440px;
        padding-top: .75rem;
    }

    .stApp:has(.settings-root) [data-testid="stSidebar"] {
        --sidebar: #0c1932;
        --ink: #edf4ff;
        --muted: #a8bbd8;
        --panel: #132849;
        --line: #233d65;
        --accent: #4b89f5;
        --accent-soft: #1d3965;
        background: #0c1932;
    }

    .settings-page-header {
        margin: .15rem 0 1rem;
    }

    .settings-page-title {
        margin: 0;
        color: var(--ink);
        font-size: clamp(1.9rem, 3vw, 2.45rem);
        font-weight: 750;
        letter-spacing: -.045em;
        line-height: 1.08;
    }

    .settings-page-subtitle {
        margin: .35rem 0 0;
        color: var(--muted);
        font-size: .96rem;
    }

    .stApp:has(.settings-root) .st-key-settings-category-panel {
        min-height: 18rem;
        padding: .55rem;
        border: 1px solid var(--line);
        border-radius: 11px;
        background: var(--panel);
    }

    .stApp:has(.settings-root) [class*="st-key-settings-nav-"] {
        margin: .12rem 0;
    }

    .stApp:has(.settings-root) [class*="st-key-settings-nav-"] button {
        justify-content: flex-start;
        min-height: 2.55rem;
        border: 1px solid transparent;
        border-radius: 8px;
        background: transparent;
        color: var(--ink);
        text-align: left;
    }

    .stApp:has(.settings-root) [class*="st-key-settings-nav-active-"] button {
        border-color: #3867e8;
        background: #3867e8;
        color: #fff;
    }

    .stApp:has(.settings-root) .st-key-settings-content {
        min-height: 18rem;
        padding: .15rem 1rem 1rem;
        border: 1px solid var(--line);
        border-radius: 11px;
        background: var(--panel);
    }

    .settings-section-heading {
        margin: 0 -.15rem .8rem;
        padding: .65rem .8rem;
        border-radius: 8px 8px 0 0;
        background: var(--panel-2);
        color: var(--ink);
        font-size: .91rem;
        font-weight: 750;
    }

    .settings-field-label {
        padding-top: .43rem;
        color: var(--ink);
        font-size: .8rem;
        font-weight: 600;
    }

    .stApp:has(.settings-root) [data-testid="stTextInput"] input,
    .stApp:has(.settings-root) [data-testid="stSelectbox"] [role="combobox"] {
        min-height: 2.35rem;
        border-color: var(--line);
        border-radius: 7px;
        background: var(--panel);
    }

    .stApp:has(.settings-root) .st-key-settings-save button {
        min-height: 2.55rem;
        border: 0;
        border-radius: 8px;
        background: #3867e8;
        color: #fff;
        font-weight: 700;
    }

    .stApp:has(.settings-root) [data-testid="stRadio"] > div {
        gap: .75rem;
    }

    @media (max-width: 750px) {
        .stApp:has(.settings-root) .st-key-settings-category-panel,
        .stApp:has(.settings-root) .st-key-settings-content {
            min-height: auto;
        }
    }

    .stApp:has(.dashboard-root) {
        background: var(--page);
    }

    .stApp:has(.dashboard-root) .block-container {
        padding-top: 1rem;
        max-width: 1440px;
    }

    .stApp:has(.dashboard-root) [data-testid="stMain"] [data-testid="stCaptionContainer"] {
        display: none;
    }

    .stApp:has(.dashboard-root) [data-testid="stSidebar"] {
        --sidebar: #0c1932;
        --ink: #edf4ff;
        --muted: #a8bbd8;
        --panel: #132849;
        --line: #233d65;
        --accent: #4b89f5;
        --accent-soft: #1d3965;
        background: #0c1932;
    }

    .dashboard-system-score {
        display: inline-flex;
        align-items: center;
        gap: .45rem;
        margin: -.55rem .35rem 1.15rem;
        padding: .4rem .7rem;
        border: 1px solid #214d3d;
        border-radius: 999px;
        background: #102b2d;
        color: #b6e6c1;
        font-size: .73rem;
        font-weight: 650;
    }

    .dashboard-system-score strong {
        color: #73d784;
    }

    .dashboard-system-dot {
        width: .55rem;
        height: .55rem;
        border-radius: 50%;
        background: #61d274;
        box-shadow: 0 0 8px rgba(97, 210, 116, .55);
    }

    .dashboard-header {
        display: flex;
        align-items: flex-start;
        justify-content: space-between;
        gap: 1.25rem;
        margin: .25rem 0 1.25rem;
    }

    .dashboard-title {
        margin: 0;
        color: var(--ink);
        font-size: clamp(1.9rem, 3.2vw, 2.65rem);
        font-weight: 750;
        letter-spacing: -.045em;
        line-height: 1.08;
    }

    .dashboard-subtitle {
        margin: .35rem 0 0;
        color: var(--muted);
        font-size: 1.02rem;
    }

    .dashboard-header-tools {
        display: flex;
        align-items: center;
        justify-content: flex-end;
        gap: .75rem;
        padding-top: .2rem;
        white-space: nowrap;
    }

    .dashboard-alert {
        position: relative;
        color: var(--ink);
        font-size: 1.25rem;
    }

    .dashboard-alert-count {
        position: absolute;
        top: -.45rem;
        right: -.55rem;
        display: grid;
        min-width: 1.1rem;
        height: 1.1rem;
        place-items: center;
        padding: 0 .2rem;
        border-radius: 999px;
        background: #e34747;
        color: #fff;
        font: 700 .62rem "DM Sans", sans-serif;
    }

    .dashboard-profile {
        display: flex;
        align-items: center;
        gap: .5rem;
        color: var(--ink);
        font-size: .75rem;
        line-height: 1.2;
    }

    .dashboard-avatar {
        display: grid;
        width: 2rem;
        height: 2rem;
        place-items: center;
        border-radius: 50%;
        background: #1b3763;
        color: #fff;
        font-size: .72rem;
        font-weight: 700;
    }

    .dashboard-guide,
    .dashboard-score-card,
    .stApp:has(.dashboard-root) .st-key-dashboard-chart-card {
        border: 1px solid var(--line);
        border-radius: 14px;
        background: var(--panel);
        box-shadow: 0 5px 16px rgba(13, 46, 92, .07);
    }

    .dashboard-guide {
        padding: 1rem 1.1rem 1.15rem;
        margin-bottom: 1rem;
    }

    .dashboard-guide-heading {
        display: flex;
        align-items: center;
        gap: .65rem;
        margin-bottom: .95rem;
        color: var(--ink);
        font-size: 1.05rem;
        font-weight: 750;
    }

    .dashboard-guide-icon {
        color: #3e78ea;
        font-size: 1.6rem;
        line-height: 1;
    }

    .dashboard-steps {
        display: grid;
        grid-template-columns: minmax(0, 1fr) auto minmax(0, 1fr) auto minmax(0, 1fr) auto minmax(0, 1fr);
        align-items: center;
        gap: .55rem;
    }

    .dashboard-step {
        position: relative;
        min-height: 8.5rem;
        padding: 1.65rem .65rem .7rem;
        border: 1px solid var(--line);
        border-radius: 10px;
        background: var(--panel-2);
        text-align: center;
    }

    .dashboard-step-number {
        position: absolute;
        top: -.85rem;
        left: calc(50% - 1rem);
        display: grid;
        width: 2rem;
        height: 2rem;
        place-items: center;
        border: 3px solid var(--panel);
        border-radius: 50%;
        background: #3e73e6;
        color: #fff;
        font-weight: 750;
    }

    .dashboard-step strong {
        display: block;
        margin-bottom: .35rem;
        color: var(--ink);
        font-size: .85rem;
    }

    .dashboard-step p {
        margin: 0;
        color: var(--muted);
        font-size: .75rem;
        line-height: 1.45;
    }

    .dashboard-step-arrow {
        color: #91a5c4;
        font-size: 1.2rem;
        font-weight: 700;
    }

    .dashboard-kpis {
        display: grid;
        grid-template-columns: repeat(4, minmax(0, 1fr));
        gap: .8rem;
        margin: 1rem 0;
    }

    .dashboard-kpi {
        display: flex;
        min-width: 0;
        min-height: 5.2rem;
        align-items: center;
        gap: .75rem;
        padding: .8rem 1rem;
        border: 1px solid var(--line);
        border-radius: 12px;
        background: var(--panel);
        box-shadow: 0 4px 12px rgba(13, 46, 92, .06);
    }

    .dashboard-kpi-icon {
        display: grid;
        width: 2.65rem;
        height: 2.65rem;
        flex: 0 0 auto;
        place-items: center;
        border-radius: 10px;
        font-size: 1.45rem;
    }

    .dashboard-kpi-icon.blue { background: #e6efff; color: #3974e6; }
    .dashboard-kpi-icon.green { background: #e4f6e9; color: #45a95c; }
    .dashboard-kpi-icon.amber { background: #fff4d8; color: #d7a721; }
    .dashboard-kpi-icon.red { background: #ffebeb; color: #d94d4d; }

    .dashboard-kpi-copy {
        min-width: 0;
    }

    .dashboard-kpi-copy strong {
        display: block;
        overflow: hidden;
        color: var(--ink);
        font-size: 1.35rem;
        font-weight: 750;
        line-height: 1.1;
        text-overflow: ellipsis;
    }

    .dashboard-kpi-copy span {
        color: var(--muted);
        font-size: .76rem;
    }

    .dashboard-analytics {
        display: grid;
        grid-template-columns: minmax(205px, .34fr) minmax(0, .66fr);
        gap: .9rem;
        align-items: stretch;
        margin-top: .9rem;
    }

    .dashboard-score-card {
        display: flex;
        min-height: 16rem;
        flex-direction: column;
        align-items: center;
        padding: 1rem;
    }

    .dashboard-panel-title {
        width: 100%;
        margin: 0 0 .8rem;
        color: var(--ink);
        font-size: .98rem;
        font-weight: 750;
    }

    .dashboard-score-ring {
        display: grid;
        width: 10.1rem;
        height: 10.1rem;
        place-items: center;
        margin: auto 0 .35rem;
        border-radius: 50%;
        background: conic-gradient(
            #51b45d 0deg var(--score-angle),
            #e8edf4 var(--score-angle) 360deg
        );
    }

    .dashboard-score-inner {
        display: flex;
        width: 8.45rem;
        height: 8.45rem;
        flex-direction: column;
        align-items: center;
        justify-content: center;
        border-radius: 50%;
        background: var(--panel);
        text-align: center;
    }

    .dashboard-score-inner strong {
        color: var(--ink);
        font-size: 2rem;
        font-weight: 800;
        letter-spacing: -.04em;
        line-height: 1.05;
    }

    .dashboard-score-inner span {
        max-width: 6rem;
        margin-top: .25rem;
        color: var(--muted);
        font-size: .75rem;
        font-weight: 650;
        line-height: 1.2;
    }

    .dashboard-score-note {
        margin: .45rem 0 0;
        color: var(--muted);
        font-size: .68rem;
        text-align: center;
    }

    .stApp:has(.dashboard-root) .st-key-dashboard-chart-card {
        min-height: 16rem;
        padding: 1rem 1.1rem .5rem;
    }

    .dashboard-chart-heading {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: .75rem;
        margin-bottom: .1rem;
        color: var(--ink);
        font-size: .98rem;
        font-weight: 750;
    }

    .dashboard-chart-legend {
        display: flex;
        align-items: center;
        gap: .9rem;
        color: var(--muted);
        font-size: .76rem;
        font-weight: 600;
    }

    .dashboard-legend-item {
        display: inline-flex;
        align-items: center;
        gap: .35rem;
    }

    .dashboard-legend-dot {
        width: .65rem;
        height: .65rem;
        border-radius: 50%;
    }

    @media (max-width: 950px) {
        .dashboard-steps {
            grid-template-columns: repeat(2, minmax(0, 1fr));
            row-gap: 1.1rem;
        }

        .dashboard-step-arrow {
            display: none;
        }
    }

    @media (max-width: 700px) {
        .dashboard-header-tools {
            display: none;
        }

        .dashboard-kpis {
            grid-template-columns: repeat(2, minmax(0, 1fr));
        }

        .dashboard-analytics {
            grid-template-columns: 1fr;
        }
    }

    @media (max-width: 800px) {
        .block-container {
            padding: 1.2rem 1rem 2rem;
        }

        .metric-grid {
            grid-template-columns: 1fr;
        }

        .hero-title {
            font-size: 1.9rem;
        }
    }

    .stApp:has(.dashboard-root) .block-container,
    .stApp:has(.file-scanner-root) .block-container,
    .stApp:has(.threat-detection-root) .block-container,
    .stApp:has(.audit-history-root) .block-container,
    .stApp:has(.activity-monitor-root) .block-container,
    .stApp:has(.user-management-root) .block-container,
    .stApp:has(.reports-analytics-root) .block-container,
    .stApp:has(.settings-root) .block-container {
        padding-top: 1.65rem;
    }

    .dashboard-header,
    .file-scanner-header,
    .threat-detection-header {
        align-items: flex-start;
        margin: 0 0 1.15rem;
    }

    .audit-history-header,
    .activity-monitor-header,
    .user-management-header,
    .reports-analytics-header,
    .settings-page-header {
        margin: 0;
    }

    .stApp h1.dashboard-title,
    .stApp h1.file-scanner-title,
    .stApp h1.threat-detection-title,
    .stApp h1.audit-history-title,
    .stApp h1.activity-monitor-title,
    .stApp h1.user-management-title,
    .stApp h1.reports-analytics-title,
    .stApp h1.settings-page-title {
        margin: 0;
        color: var(--ink);
        font-family: "DM Sans", sans-serif;
        font-size: clamp(1.9rem, 3vw, 2.45rem);
        font-weight: 750;
        letter-spacing: -.045em;
        line-height: 1.08;
    }

    .stApp p.dashboard-subtitle,
    .stApp p.file-scanner-subtitle,
    .stApp p.threat-detection-subtitle,
    .stApp p.audit-history-subtitle,
    .stApp p.activity-monitor-subtitle,
    .stApp p.user-management-subtitle,
    .stApp p.reports-analytics-subtitle,
    .stApp p.settings-page-subtitle {
        margin: .35rem 0 0;
        color: var(--muted);
        font-family: "DM Sans", sans-serif;
        font-size: .98rem;
        font-weight: 400;
    }

    .global-header-controls-root {
        display: none;
    }

    .stApp:has(.global-header-controls-root) .st-key-global-header-controls {
        position: fixed;
        top: .35rem;
        right: 1rem;
        z-index: 1000000;
        width: min(17rem, calc(100vw - 1rem));
        padding: 0;
        border: 0;
        background: transparent;
    }

    .stApp:has(.global-header-controls-root) .st-key-global-header-controls [data-testid="stHorizontalBlock"] {
        flex-wrap: nowrap !important;
        align-items: center;
        gap: .15rem;
    }

    .stApp:has(.global-header-controls-root) .st-key-global-header-controls [data-testid="stColumn"] {
        min-width: 0;
    }

    .stApp:has(.global-header-controls-root) .st-key-global-header-controls [data-testid="stColumn"]:first-child {
        flex: 0 0 3.65rem !important;
        width: 3.65rem !important;
    }

    .stApp:has(.global-header-controls-root) .st-key-global-header-controls [data-testid="stPopoverButton"] {
        min-height: 2.65rem;
        padding: .25rem .4rem;
        border: 0;
        border-radius: 999px;
        background: transparent;
        color: var(--ink);
        font-size: .84rem;
        font-weight: 650;
        white-space: nowrap;
    }

    .stApp:has(.global-header-controls-root) .st-key-global-header-controls [data-testid="stPopoverButton"] *,
    .stApp:has(.global-header-controls-root) .st-key-global-header-controls [data-testid="stPopoverButton"] {
        color: var(--ink) !important;
    }

    .stApp:has(.global-header-controls-root) .st-key-global-header-controls [data-testid="stPopoverButton"]:hover {
        background: var(--accent-soft);
    }

    .stApp:has(.global-header-controls-root) .st-key-global-notifications [data-testid="stPopoverButton"] {
        position: relative;
        min-width: 2.8rem;
        justify-content: center;
    }

    .stApp:has(.global-header-controls-root) .st-key-global-notifications [data-testid="stIconMaterial"] {
        color: #315e9d !important;
        font-size: 1.7rem;
    }

    .stApp:has(.global-header-controls-root) .st-key-global-notifications [data-testid="stPopoverButton"] > div > div:last-child {
        display: none;
    }

    .stApp:has(.global-header-controls-root) .st-key-global-notifications [data-testid="stMarkdownContainer"] p {
        position: absolute;
        top: -.05rem;
        right: -.05rem;
        display: inline-flex;
        min-width: 1.1rem;
        height: 1.1rem;
        align-items: center;
        justify-content: center;
        margin: 0;
        padding: 0 .22rem;
        border-radius: 999px;
        background: #e34747;
        color: #fff;
        font-size: .62rem;
        font-weight: 800;
        line-height: 1;
        box-shadow: 0 0 0 2px var(--bg);
    }

    .stApp:has(.global-header-controls-root) .st-key-global-workspace [data-testid="stPopoverButton"] {
        max-width: 14rem;
        justify-content: flex-start;
        gap: .45rem;
        overflow: hidden;
        text-overflow: ellipsis;
    }

    .stApp:has(.global-header-controls-root) .st-key-global-workspace [data-testid="stIconMaterial"] {
        display: none;
    }

    .stApp:has(.global-header-controls-root) .st-key-global-workspace [data-testid="stPopoverButton"]::before {
        display: inline-flex;
        width: 2.15rem;
        height: 2.15rem;
        flex: 0 0 2.15rem;
        align-items: center;
        justify-content: center;
        border-radius: 50%;
        background: linear-gradient(145deg, #245da8, #102d59);
        color: #fff !important;
        content: var(--workspace-initials, "LA");
        font-size: .76rem;
        font-weight: 800;
        letter-spacing: .02em;
    }

    .stApp:has(.global-header-controls-root) [data-testid="stPopoverBody"] {
        min-width: 19rem;
        max-width: min(27rem, 90vw);
        border: 1px solid var(--line);
        border-radius: 12px;
        background: var(--panel);
        box-shadow: 0 14px 36px rgba(0, 0, 0, .28);
    }

    .stApp:has(.global-header-controls-root) [data-testid="stPopoverBody"] [data-testid="stMarkdownContainer"] {
        color: var(--ink);
    }

    .stApp:has(.global-header-controls-root) [data-testid="stPopoverBody"] [data-testid="stButton"] > button {
        min-height: 2.2rem;
        border-radius: 7px;
    }

    .stApp:has(.global-header-controls-root) .dashboard-header-tools,
    .stApp:has(.global-header-controls-root) .file-scanner-header-tools {
        display: none;
    }

    .stApp:not(:has(.settings-root)) [data-testid="stToolbar"] {
        visibility: hidden;
    }

    .stApp:has(.settings-root) [data-testid="stToolbar"] {
        visibility: visible;
    }

    .stApp:has(.settings-root) [data-testid="stToolbar"] > div:first-child > div:last-child {
        margin-left: 0 !important;
        justify-content: flex-start;
    }

    .stApp:has(.settings-root) [data-testid="stToolbar"] > div:first-child {
        justify-content: flex-start;
    }

    @media (max-width: 800px) {
        .stApp:has(.dashboard-root) .block-container,
        .stApp:has(.file-scanner-root) .block-container,
        .stApp:has(.threat-detection-root) .block-container,
        .stApp:has(.audit-history-root) .block-container,
        .stApp:has(.activity-monitor-root) .block-container,
        .stApp:has(.user-management-root) .block-container,
        .stApp:has(.reports-analytics-root) .block-container,
        .stApp:has(.settings-root) .block-container {
            padding-top: 1.2rem;
        }
    }

    @media (max-width: 700px) {
        .stApp:has(.global-header-controls-root) .st-key-global-header-controls {
            top: .2rem;
            right: .35rem;
            width: min(17rem, calc(100vw - .7rem));
        }

        .stApp:has(.global-header-controls-root) .st-key-global-workspace [data-testid="stPopoverButton"] {
            max-width: min(13rem, calc(100vw - 4.5rem));
        }

        .stApp:has(.global-header-controls-root) [data-testid="stPopoverBody"] {
            min-width: min(19rem, 88vw);
        }
    }
    </style>
    """,
    unsafe_allow_html=True,
)


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

INDICATOR_EXPLANATIONS = {
    "Embedded JavaScript action": "Finds PDF markers that can attach JavaScript to a document, which may run when the document is opened or interacted with.",
    "Automatic document action": "Finds PDF markers for actions triggered automatically or in response to document events.",
    "External launch instruction": "Finds a PDF instruction that can attempt to launch an external application or file.",
    "Embedded file payload": "Finds PDF markers associated with files attached or embedded inside the document.",
    "External URI action": "Finds a PDF action that points to a URI, such as a web address.",
    "Script injection pattern": "Finds HTML or script-like text that may indicate embedded or injected executable content.",
    "Shell command reference": "Finds references to command shells that could be used to run system commands.",
    "Dynamic code execution pattern": "Finds calls commonly associated with evaluating or executing code dynamically.",
    "External network reference": "Finds a URL that may cause a document or related content to connect to an external server.",
}


def human_size(size: int) -> str:
    """Format a byte count as a readable file size."""
    value = float(size)
    for unit in ("B", "KB", "MB", "GB"):
        if value < 1024 or unit == "GB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{size} B"


def refresh_download_activity_history() -> tuple[
    str, dict[str, dict[str, object]]
]:
    """Refresh the opt-in folder snapshot and persist alerts for new activity."""
    if not LOCAL_DOWNLOAD_MONITOR_ENABLED:
        return "", {}

    folder = Path(
        st.session_state.get(
            "local_download_folder",
            str(Path.home() / "Downloads"),
        )
    ).expanduser()
    folder_key = str(folder.resolve())
    histories = st.session_state.setdefault("local_download_history", {})
    folder_history = histories.get(folder_key, {})
    if not st.session_state.get("local_download_monitor_enabled", False):
        return folder_key, folder_history

    entries = scan_download_folder(Path(folder_key))
    snapshots = st.session_state.setdefault("local_download_snapshots", {})
    current_snapshot, folder_history = update_download_history(
        entries,
        snapshots.get(folder_key, {}),
        folder_history,
        datetime.now().timestamp(),
    )
    snapshots[folder_key] = current_snapshot
    histories[folder_key] = folder_history

    if get_app_setting("alert_file_activity", "false") == "true":
        for filename, record in folder_history.items():
            state = str(record["state"])
            if state not in {
                "Writing",
                "Recently detected",
                "Temporary download file",
            }:
                continue
            fingerprint = (
                f"{folder_key}|{filename}|{record['modified_at']}|"
                f"{record['size_bytes']}"
            )
            notification_id = hashlib.sha256(
                fingerprint.encode("utf-8")
            ).hexdigest()
            record_workspace_notification(
                f"File activity: {filename}",
                f"{state} · {human_size(int(record['size_bytes']))}",
                "File Activity Monitor",
                notification_id=f"download-{notification_id}",
            )
    return folder_key, folder_history


@st.fragment(run_every="5s")
def render_global_header_controls() -> None:
    """Render the shared notification center and local workspace profile."""
    monitoring_error = None
    if (
        LOCAL_DOWNLOAD_MONITOR_ENABLED
        and st.session_state.get("local_download_monitor_enabled", False)
    ):
        try:
            refresh_download_activity_history()
        except OSError as error:
            monitoring_error = f"Could not monitor this folder: {error}"
            st.session_state.download_monitor_error = monitoring_error
        else:
            st.session_state.pop("download_monitor_error", None)
    if monitoring_error is None:
        monitoring_error = st.session_state.get("download_monitor_error")

    notifications: list[dict[str, str]] = []
    events_setting = get_app_setting("notification_events", "[]")
    try:
        stored_events = json.loads(events_setting)
    except json.JSONDecodeError as error:
        raise ValueError("Saved notification events are not valid JSON.") from error
    if not isinstance(stored_events, list) or any(
        not isinstance(event, dict)
        or not all(
            isinstance(event.get(field), str)
            for field in ("id", "title", "detail", "destination", "created_at")
        )
        for event in stored_events
    ):
        raise ValueError("Saved notification events have an invalid format.")
    valid_destinations = {
        "Audit History",
        "Dashboard",
        "File Scanner",
        "File Activity Monitor",
        "Reports & Analytics",
        "Settings",
        "Threat Detection",
        "User Management",
    }
    for event in stored_events:
        if event["destination"] not in valid_destinations:
            raise ValueError(
                f"Saved notification has an unknown destination: "
                f"{event['destination']}"
            )
        notifications.append(
            {
                "id": event["id"],
                "title": event["title"],
                "detail": event["detail"],
                "destination": event["destination"],
                "created_at": event["created_at"],
            }
        )

    if get_app_setting("alert_high_risk", "true") == "true":
        scan_records = get_all_scans()
        if not scan_records.empty:
            scan_dates = pd.to_datetime(
                scan_records["scan_date"],
                errors="coerce",
            )
            recent_cutoff = pd.Timestamp.now() - pd.Timedelta(days=7)
            recent_scans = scan_records.loc[scan_dates >= recent_cutoff]
            for scan in recent_scans.itertuples(index=False):
                score = int(scan.score)
                verdict = str(scan.verdict)
                if score >= 50 or verdict in {"Malicious", "High risk"}:
                    title = f"High-risk scan: {scan.filename}"
                elif score >= 15 or verdict in {"Suspicious", "Review needed"}:
                    title = f"Scan needs review: {scan.filename}"
                else:
                    continue
                notifications.append(
                    {
                        "id": f"scan-{int(scan.id)}",
                        "title": title,
                        "detail": (
                            f"{verdict} · Risk score {score}/100 · {scan.scan_date}"
                        ),
                        "destination": "Threat Detection",
                        "created_at": str(scan.scan_date),
                    }
                )

    notifications.sort(
        key=lambda notification: notification["created_at"],
        reverse=True,
    )
    notifications = notifications[:50]
    read_setting = get_app_setting("notification_read_ids", "[]")
    try:
        saved_read_ids = json.loads(read_setting)
    except json.JSONDecodeError as error:
        raise ValueError("Saved notification read state is not valid JSON.") from error
    if not isinstance(saved_read_ids, list) or any(
        not isinstance(notification_id, str)
        for notification_id in saved_read_ids
    ):
        raise ValueError("Saved notification read state must contain string IDs.")
    read_ids = set(saved_read_ids)
    active_ids = {notification["id"] for notification in notifications}
    old_read_ids = set(read_ids)
    read_ids.intersection_update(active_ids)
    if read_ids != old_read_ids:
        set_app_setting("notification_read_ids", json.dumps(sorted(read_ids)))
    unread_count = sum(
        notification["id"] not in read_ids for notification in notifications
    )

    organization_name = get_app_setting(
        "organization_name",
        "LiteAudit Enterprise",
    ).strip()
    organization_name = organization_name or "LiteAudit Enterprise"
    initials = "".join(
        word[0] for word in organization_name.split()[:2]
    ).upper()
    initials = "".join(character for character in initials if character.isalnum())
    initials = initials or "LA"
    st.markdown(
        "<style>"
        ".stApp:has(.global-header-controls-root) "
        ".st-key-global-workspace [data-testid='stPopoverButton'] "
        "{ --workspace-initials: "
        f"{json.dumps(initials)};"
        " }"
        "</style>",
        unsafe_allow_html=True,
    )
    st.markdown(
        '<div class="global-header-controls-root"></div>',
        unsafe_allow_html=True,
    )
    with st.container(key="global-header-controls"):
        notification_column, workspace_column = st.columns(
            [.42, 1.8],
            gap="small",
        )
        with notification_column:
            with st.popover(
                f"{unread_count}" if unread_count else " ",
                icon=":material/notifications_none:",
                help=(
                    f"{unread_count} unread notification(s)"
                    if unread_count
                    else "Notifications"
                ),
                type="tertiary",
                width="content",
                key="global-notifications",
            ):
                st.markdown("#### Notifications")
                if notifications:
                    if unread_count and st.button(
                        "Mark all as read",
                        key="notifications-mark-all-read",
                        use_container_width=True,
                    ):
                        read_ids.update(active_ids)
                        set_app_setting(
                            "notification_read_ids",
                            json.dumps(sorted(read_ids)),
                        )
                        st.rerun()

                    for notification in notifications:
                        if notification["id"] in read_ids:
                            st.caption(
                                f'{notification["title"]} · '
                                f'{notification["detail"]}'
                            )
                        else:
                            st.markdown(
                                f'**{escape(notification["title"])}**  \n'
                                f'{escape(notification["detail"])}'
                            )
                        if st.button(
                            f'Review · {notification["destination"]}',
                            key=f'notification-open-{notification["id"]}',
                        ):
                            read_ids.add(notification["id"])
                            set_app_setting(
                                "notification_read_ids",
                                json.dumps(sorted(read_ids)),
                            )
                            st.session_state.selected_section = notification[
                                "destination"
                            ]
                            st.rerun()
                        st.divider()
                else:
                    st.info(
                        "No recent alerts. New scan findings, monitored file activity, "
                        "and workspace changes will appear here."
                    )
                if monitoring_error:
                    st.error(monitoring_error)
                if st.button(
                    "Open Audit History",
                    key="notifications-open-history",
                    use_container_width=True,
                ):
                    st.session_state.selected_section = "Audit History"
                    st.rerun()

        with workspace_column:
            with st.popover(
                organization_name,
                help="Local workspace profile",
                type="tertiary",
                width="content",
                key="global-workspace",
            ):
                st.markdown(f"#### {escape(organization_name)}")
                st.caption(
                    f"Local workspace profile · {initials or 'LA'}"
                )
                st.caption(str(Path("my_data.db").resolve()))
                with st.form("workspace-name-form"):
                    updated_name = st.text_input(
                        "Workspace name",
                        value=organization_name,
                    )
                    rename_workspace = st.form_submit_button(
                        "Save workspace name"
                    )
                if rename_workspace:
                    cleaned_name = updated_name.strip()
                    if not cleaned_name:
                        st.error("Workspace name cannot be empty.")
                    elif cleaned_name != organization_name:
                        set_app_setting("organization_name", cleaned_name)
                        record_workspace_notification(
                            "Workspace profile updated",
                            "The local workspace name was changed.",
                            "Settings",
                        )
                        st.rerun()
                for label, destination, key in (
                    ("Settings", "Settings", "workspace-open-settings"),
                    (
                        "Reports & Analytics",
                        "Reports & Analytics",
                        "workspace-open-reports",
                    ),
                    (
                        "User Management",
                        "User Management",
                        "workspace-open-users",
                    ),
                ):
                    if st.button(label, key=key, use_container_width=True):
                        st.session_state.selected_section = destination
                        st.rerun()


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

    if check_file_integrity:
        extension = Path(file_name).suffix.lower()
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


def build_analytics_pdf(
    total_scans: int,
    clean_rate: float,
    suspicious_rate: float,
    malicious_rate: float,
    records: pd.DataFrame,
) -> bytes:
    """Create a small, dependency-free PDF summary of saved scan metadata."""
    lines = [
        "LiteAudit - Security Analytics Report",
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}",
        "",
        "Key Metrics (Last 30 Days)",
        f"Files scanned: {total_scans:,}",
        f"Clean rate: {clean_rate:.1f}%",
        f"Suspicious: {suspicious_rate:.1f}%",
        f"Malicious: {malicious_rate:.1f}%",
        "",
        "Recent scan records",
    ]
    for row in records.head(25).itertuples(index=False):
        lines.append(
            f"{row.scan_date} | {row.filename} | {row.verdict} | "
            f"Risk {int(row.score)}/100"
        )
    if records.empty:
        lines.append("No saved scan records.")

    def pdf_escape(value: str) -> str:
        printable = value.encode("ascii", "replace").decode("ascii")
        return printable.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")

    text_commands = ["BT", "/F1 10 Tf", "50 750 Td", "14 TL"]
    for index, line in enumerate(lines):
        if index:
            text_commands.append("T*")
        text_commands.append(f"({pdf_escape(line[:105])}) Tj")
    text_commands.append("ET")
    stream = "\n".join(text_commands).encode("ascii")
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
        b"/Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        b"<< /Length " + str(len(stream)).encode("ascii") + b" >>\nstream\n"
        + stream + b"\nendstream",
    ]
    pdf = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for object_number, body in enumerate(objects, start=1):
        offsets.append(len(pdf))
        pdf.extend(
            f"{object_number} 0 obj\n".encode("ascii")
            + body
            + b"\nendobj\n"
        )
    xref_offset = len(pdf)
    pdf.extend(f"xref\n0 {len(offsets)}\n".encode("ascii"))
    pdf.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        pdf.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
    pdf.extend(
        f"trailer\n<< /Size {len(offsets)} /Root 1 0 R >>\n"
        f"startxref\n{xref_offset}\n%%EOF\n".encode("ascii")
    )
    return bytes(pdf)


@st.fragment(run_every="2s")
def render_file_activity_monitor() -> None:
    """Render recent local downloads and scan files only when explicitly requested."""
    monitoring_enabled = st.session_state.get("local_download_monitor_enabled", False)
    folder = Path(
        st.session_state.get(
            "local_download_folder",
            str(Path.home() / "Downloads"),
        )
    ).expanduser()
    folder_key = ""
    folder_history: dict[str, dict[str, object]] = {}
    if LOCAL_DOWNLOAD_MONITOR_ENABLED:
        try:
            folder_key, folder_history = refresh_download_activity_history()
        except OSError as error:
            st.error(f"Could not monitor this folder: {error}")
            return

    scan_registry = st.session_state.setdefault("local_download_scans", {}).get(
        folder_key, {}
    )
    records = sorted(
        folder_history.items(),
        key=lambda item: float(item[1]["modified_at"]),
        reverse=True,
    )
    scanned_count = sum(
        f"{filename}|{record['modified_at']}|{record['size_bytes']}"
        in scan_registry
        for filename, record in records
    )
    suspicious_count = sum(
        int(scan_registry[
            f"{filename}|{record['modified_at']}|{record['size_bytes']}"
        ]["score"]) >= 15
        for filename, record in records
        if f"{filename}|{record['modified_at']}|{record['size_bytes']}"
        in scan_registry
    )
    metric_columns = st.columns(4, gap="medium")
    metric_columns[0].metric("↓  Tracked Downloads", f"{len(records):,}")
    metric_columns[1].metric("✓  Scanned", f"{scanned_count:,}")
    metric_columns[2].metric("!  Unscanned", f"{len(records) - scanned_count:,}")
    metric_columns[3].metric("⚠  Suspicious", f"{suspicious_count:,}")

    recent_tab, alerts_tab = st.tabs(["Recent Downloads", "Activity Alerts"])

    def render_download_table(
        selected_records: list[tuple[str, dict[str, object]]],
        table_id: str,
    ) -> None:
        headers = st.columns([1.05, 2, 1.5, 1, .8], gap="small")
        for column, heading in zip(
            headers, ["Time", "File Name", "Source", "Status", "Action"]
        ):
            column.markdown(
                f'<div class="activity-table-cell"><strong>{heading}</strong></div>',
                unsafe_allow_html=True,
            )

        for filename, record in selected_records:
            fingerprint = (
                f"{filename}|{record['modified_at']}|{record['size_bytes']}"
            )
            saved_scan = scan_registry.get(fingerprint)
            score = int(saved_scan["score"]) if saved_scan else 0
            if saved_scan and score >= 15:
                status, status_class, icon = "Suspicious", "suspicious", "⚠"
            elif saved_scan:
                status, status_class, icon = "Scanned", "scanned", "✓"
            else:
                status, status_class, icon = "Unscanned", "unscanned", "⚠"
            time_label = datetime.fromtimestamp(
                float(record["modified_at"])
            ).strftime("%I:%M %p").lstrip("0")
            state = str(record["state"])
            file_is_present = state != "No longer in folder"
            safe_key = hashlib.sha256(fingerprint.encode("utf-8")).hexdigest()[:12]

            with st.container(key=f"activity-row-{table_id}-{safe_key}"):
                row_columns = st.columns([1.05, 2, 1.5, 1, .8], gap="small")
                row_columns[0].markdown(
                    f'<div class="activity-table-cell">{escape(time_label)}</div>',
                    unsafe_allow_html=True,
                )
                row_columns[1].markdown(
                    f'<div class="activity-table-cell" title="{escape(filename, quote=True)}">'
                    f'{escape(filename)}</div>',
                    unsafe_allow_html=True,
                )
                row_columns[2].markdown(
                    '<div class="activity-table-cell">Monitored folder</div>',
                    unsafe_allow_html=True,
                )
                row_columns[3].markdown(
                    f'<span class="activity-status {status_class}">'
                    f"{icon} {status}</span>",
                    unsafe_allow_html=True,
                )
                if saved_scan:
                    if row_columns[4].button(
                        "View",
                        key=f"activity-view-{table_id}-{safe_key}",
                        help="View saved scan result",
                    ):
                        st.session_state.activity_view_scan_id = int(saved_scan["id"])
                elif row_columns[4].button(
                    "Scan",
                    key=f"activity-scan-{table_id}-{safe_key}",
                    disabled=(
                        not LOCAL_DOWNLOAD_MONITOR_ENABLED
                        or not monitoring_enabled
                        or not file_is_present
                    ),
                    help=(
                        "Read and scan this file in memory. It will not be uploaded."
                    ),
                ):
                    try:
                        resolved_folder = folder.resolve(strict=True)
                        target = (folder / filename).resolve(strict=True)
                        if target.parent != resolved_folder or not target.is_file():
                            st.error("This file is no longer available in the monitored folder.")
                            continue
                        file_bytes = target.read_bytes()
                    except (OSError, RuntimeError) as error:
                        st.error(f"Could not read {filename} for scanning: {error}")
                        continue
                    if len(file_bytes) > MAX_FILE_SIZE:
                        st.error(
                            f"{filename} exceeds the {MAX_FILE_SIZE_MB} MiB scan limit."
                        )
                        continue
                    result = scan_document(filename, file_bytes)
                    scan_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    insert_scan_result(
                        filename=filename,
                        verdict=result["verdict"],
                        score=result["score"],
                        sha256=result["sha256"],
                        tone=result["tone"],
                        scan_date=scan_date,
                        findings=result["findings"],
                        file_size_bytes=len(file_bytes),
                    )
                    saved_scans = get_all_scans()
                    saved_row = saved_scans.loc[
                        saved_scans["sha256"] == result["sha256"]
                    ].sort_values("id", ascending=False).iloc[0]
                    scan_registry[fingerprint] = {
                        "id": int(saved_row["id"]),
                        "score": int(result["score"]),
                    }
                    st.session_state.setdefault("local_download_scans", {})[
                        folder_key
                    ] = scan_registry
                    st.session_state.activity_scan_notice = (
                        f"Scanned {filename}: {result['verdict']} "
                        f"(risk score {result['score']}/100)."
                    )
                    st.rerun()

    with recent_tab:
        if "activity_scan_notice" in st.session_state:
            st.success(st.session_state.pop("activity_scan_notice"))
        with st.expander("Monitor settings", key="activity-monitor-settings"):
            st.toggle(
                "Monitor this folder path",
                key="local_download_monitor_enabled",
                disabled=not LOCAL_DOWNLOAD_MONITOR_ENABLED,
                on_change=save_download_monitor_settings,
                help="Monitoring is available only when LiteAudit runs on the computer "
                "that owns the selected folder.",
            )
            st.text_input(
                "Folder path to monitor",
                key="local_download_folder",
                help="Enter an absolute path, such as C:\\Users\\you\\Downloads.",
                disabled=not LOCAL_DOWNLOAD_MONITOR_ENABLED,
                on_change=save_download_monitor_settings,
            )
            if st.button(
                "Clear detected files",
                key="clear_download_history",
                disabled=not folder_history,
            ):
                st.session_state.setdefault("local_download_history", {})[
                    folder_key
                ] = {}
                st.session_state.setdefault("local_download_snapshots", {})[
                    folder_key
                ] = {}
                st.rerun()

        if records:
            render_download_table(records, "recent")
        elif not LOCAL_DOWNLOAD_MONITOR_ENABLED:
            st.info(
                "Local monitoring is disabled. Enable "
                "LITEAUDIT_ENABLE_LOCAL_DOWNLOAD_MONITOR on the computer that owns "
                "the folder."
            )
            st.code(
                '$env:LITEAUDIT_ENABLE_LOCAL_DOWNLOAD_MONITOR = "1"\n'
                "streamlit run liteaudit_app.py",
                language="powershell",
            )
        elif not monitoring_enabled:
            st.info("Monitoring is off. Turn it on in Monitor settings to watch the folder.")
        else:
            st.info("No downloads have been detected yet.")

        viewed_scan_id = st.session_state.get("activity_view_scan_id")
        if viewed_scan_id is not None:
            saved_scans = get_all_scans()
            viewed_scan = saved_scans.loc[saved_scans["id"] == viewed_scan_id]
            if not viewed_scan.empty:
                view = viewed_scan.iloc[0]
                st.markdown(
                    f'<div class="file-scanner-view-panel">'
                    f'<strong>{escape(str(view["filename"]))}</strong> · '
                    f'{escape(str(view["verdict"]))} · Risk score '
                    f'{int(view["score"])}/100<br><small>Scanned '
                    f'{escape(str(view["scan_date"]))} · SHA-256 '
                    f'{escape(str(view["sha256"]))}</small></div>',
                    unsafe_allow_html=True,
                )

    with alerts_tab:
        active_entries = [
            (filename, record)
            for filename, record in records
            if record["state"]
            in {"Writing", "Recently detected", "Temporary download file"}
        ]
        suspicious_entries = [
            (filename, record)
            for filename, record in records
            if (
                f"{filename}|{record['modified_at']}|{record['size_bytes']}"
                in scan_registry
                and int(
                    scan_registry[
                        f"{filename}|{record['modified_at']}|{record['size_bytes']}"
                    ]["score"]
                ) >= 15
            )
        ]
        if active_entries and get_app_setting("alert_file_activity", "false") == "true":
            st.warning(f"{len(active_entries)} file(s) are new or still changing.")
        elif active_entries:
            st.info(f"{len(active_entries)} file(s) are new or still changing.")
        if suspicious_entries:
            st.error(f"{len(suspicious_entries)} scanned file(s) triggered review rules.")
        if not active_entries and not suspicious_entries:
            st.success("No new file activity or suspicious scan results.")
        elif records:
            alert_records = {
                (
                    filename,
                    f"{record['modified_at']}|{record['size_bytes']}",
                ): (filename, record)
                for filename, record in active_entries + suspicious_entries
            }
            render_download_table(list(alert_records.values()), "alerts")

    st.caption(
        "The monitor checks file metadata every 2 seconds while this page is open. "
        "Up to 50 recent files are tracked per session. Files are read into memory "
        "only when you choose Scan; monitoring alone does not inspect file contents."
    )


def prepare_daily_scan_chart(daily_metrics):
    chart_data = daily_metrics.rename(
        columns={
            "scan_day": "Date",
            "total_scans": "Scans",
            "malicious_count": "Malicious verdicts",
        }
    ).copy()
    chart_data["Date"] = pd.to_datetime(chart_data["Date"], errors="coerce")
    for column in ("Scans", "Malicious verdicts"):
        chart_data[column] = pd.to_numeric(chart_data[column], errors="coerce")
    chart_data = chart_data.dropna(subset=["Date", "Scans"])
    chart_data = chart_data.loc[chart_data["Scans"] > 0].set_index("Date").sort_index()
    chart_data = chart_data.loc[:, chart_data.notna().any()]
    return chart_data.loc[:, chart_data.ne(0).any()]


def prepare_weekly_scan_chart(daily_metrics):
    chart_data = daily_metrics.rename(
        columns={
            "scan_day": "Date",
            "total_scans": "Scans",
            "threat_count": "Threats",
        }
    ).copy()
    chart_data["Date"] = pd.to_datetime(chart_data["Date"], errors="coerce")
    for column in ("Scans", "Threats"):
        if column not in chart_data:
            chart_data[column] = 0
        chart_data[column] = pd.to_numeric(chart_data[column], errors="coerce").fillna(0)
    chart_data = chart_data.dropna(subset=["Date"])
    chart_data = chart_data.groupby("Date")[["Scans", "Threats"]].sum()
    week = pd.date_range(
        end=pd.Timestamp.now().normalize(),
        periods=7,
        freq="D",
        name="Date",
    )
    return chart_data.reindex(week, fill_value=0).reset_index()


def render_weekly_scan_chart(daily_metrics):
    weekly_data = prepare_weekly_scan_chart(daily_metrics)
    tick_values = [
        date.to_pydatetime() for date in weekly_data["Date"]
    ]
    chart_data = weekly_data.melt(
        id_vars="Date",
        var_name="Metric",
        value_name="Count",
    )
    max_count = max(1, int(chart_data["Count"].max()))
    chart = (
        alt.Chart(chart_data)
        .mark_line(point=alt.OverlayMarkDef(filled=True, size=65), strokeWidth=2.5)
        .encode(
            x=alt.X(
                "Date:T",
                title=None,
                axis=alt.Axis(
                    format="%a",
                    labelAngle=0,
                    tickSize=0,
                    values=tick_values,
                ),
            ),
            y=alt.Y(
                "Count:Q",
                title=None,
                scale=alt.Scale(domain=[0, max_count], nice=True),
                axis=alt.Axis(
                    format="~s",
                    tickCount=4,
                    tickMinStep=1,
                    grid=True,
                ),
            ),
            color=alt.Color(
                "Metric:N",
                title=None,
                scale=alt.Scale(
                    domain=["Scans", "Threats"],
                    range=["#416fe4", "#dc4c4c"],
                ),
                legend=None,
            ),
            tooltip=[
                alt.Tooltip("Date:T", title="Date", format="%A, %b %d"),
                alt.Tooltip("Metric:N", title="Activity"),
                alt.Tooltip("Count:Q", title="Count", format=","),
            ],
        )
        .properties(height=220)
    )
    st.altair_chart(chart, width="stretch")


def render_daily_scan_chart(daily_metrics, height):
    chart_data = prepare_daily_scan_chart(daily_metrics)
    if chart_data.empty:
        st.info("Daily activity could not be charted from the saved scan dates.")
        return

    chart_data = chart_data.reset_index().melt(
        id_vars="Date",
        var_name="Metric",
        value_name="Count",
    )
    max_count = max(1, int(chart_data["Count"].max()))
    chart = (
        alt.Chart(chart_data)
        .mark_line(point=True)
        .encode(
            x=alt.X("Date:T", title="Date"),
            y=alt.Y(
                "Count:Q",
                title="Scans",
                scale=alt.Scale(domain=[0, max_count]),
            ),
            color=alt.Color("Metric:N", title=None),
            tooltip=["Date:T", "Metric:N", "Count:Q"],
        )
        .properties(height=height)
    )
    st.altair_chart(chart, width="stretch")


dashboard_verdict_metrics = get_verdict_metrics()
if dashboard_verdict_metrics.empty:
    dashboard_verdict_counts = pd.Series(dtype="int64")
else:
    dashboard_verdict_counts = dashboard_verdict_metrics.set_index("verdict")[
        "total_files"
    ]
dashboard_total_scans = int(dashboard_verdict_counts.sum())
dashboard_clean_scans = int(
    dashboard_verdict_counts.reindex(
        ["No known indicators", "Clean", "Safe"], fill_value=0
    ).sum()
)
dashboard_review_scans = int(
    dashboard_verdict_counts.reindex(
        ["Review needed", "Suspicious"], fill_value=0
    ).sum()
)
dashboard_malicious_scans = int(
    dashboard_verdict_counts.reindex(
        ["High risk", "Malicious"], fill_value=0
    ).sum()
)
dashboard_security_score = (
    round(dashboard_clean_scans / dashboard_total_scans * 100)
    if dashboard_total_scans
    else 0
)


# Render the application identity and status panel.
with st.sidebar:
    st.markdown(
        """
        <div class="brand">
            <div class="brand-mark" aria-hidden="true">
                <svg viewBox="0 0 40 40" fill="none">
                    <path d="M20 3.5 34 9v9.2c0 8.7-5.8 15.1-14 18.3C11.8 33.3 6 26.9 6 18.2V9l14-5.5Z"
                          stroke="currentColor" stroke-width="2.7" stroke-linejoin="round"/>
                    <path d="m13.5 19.8 4.2 4.1 8.9-9.2"
                          stroke="currentColor" stroke-width="2.7" stroke-linecap="round"
                          stroke-linejoin="round"/>
                </svg>
            </div>
            <div>
                <div class="brand-name">Lite<span>Audit</span></div>
                <div class="brand-tagline">Document Security Platform</div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    st.markdown('<div class="side-label">Appearance</div>', unsafe_allow_html=True)
    st.toggle(
        "Light mode",
        key="light_mode",
        help="Switch between the navy dark theme and light theme.",
        on_change=save_theme_preference,
    )
    st.markdown('<div class="side-label">Workspace</div>', unsafe_allow_html=True)
    organization_label = escape(get_app_setting("organization_name", "LiteAudit"))
    if "selected_section" not in st.session_state:
        st.session_state.selected_section = "Dashboard"
    elif st.session_state.selected_section == "Getting started":
        st.session_state.selected_section = "Dashboard"
    elif st.session_state.selected_section == "Document Scanner":
        st.session_state.selected_section = "File Scanner"
    elif st.session_state.selected_section == "Reports & Search":
        st.session_state.selected_section = "Reports & Analytics"
    elif st.session_state.selected_section == "Detection Rules":
        st.session_state.selected_section = "Threat Detection"

    if st.session_state.selected_section in {"Dashboard", "Threat Detection"}:
        score_label = (
            f"{dashboard_security_score}%" if dashboard_total_scans else "—"
        )
        st.markdown(
            f"""
            <div class="dashboard-system-score"
                 title="Clean scan rate from {dashboard_total_scans:,} saved scans">
                <span class="dashboard-system-dot"></span>
                <span>Scan health</span>
                <strong>{score_label}</strong>
            </div>
            """,
            unsafe_allow_html=True,
        )

    navigation_items = [
        ("⌂", "Dashboard"),
        ("◈", "File Scanner"),
        ("⬟", "Threat Detection"),
        ("◷", "Audit History"),
        ("⌁", "File Activity Monitor"),
        ("♙", "User Management"),
        ("▤", "Reports & Analytics"),
        ("⚙", "Settings"),
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
        f"""
        <div class="side-card">
            <strong>{organization_label} · Local-first protection</strong>
            Files are inspected in memory. Scan metadata is saved to the local audit database.
        </div>
        <div class="footer-note">Prototype engine · v0.8.2</div>
        """,
        unsafe_allow_html=True,
    )

render_global_header_controls()

if selected_section == "Dashboard":
    st.markdown('<div class="dashboard-root"></div>', unsafe_allow_html=True)
    threat_count = dashboard_review_scans + dashboard_malicious_scans
    alerts_text = (
        f'<span class="dashboard-alert-count">{threat_count:,}</span>'
        if threat_count
        else ""
    )
    st.markdown(
        f"""
        <div class="dashboard-header">
            <div>
                <h1 class="dashboard-title">Welcome to LiteAudit!</h1>
                <p class="dashboard-subtitle">Monitor. Detect. Stay Secure.</p>
            </div>
            <div class="dashboard-header-tools">
                <span class="dashboard-alert" title="{threat_count:,} flagged scans">
                    &#128276;{alerts_text}
                </span>
                <div class="dashboard-profile">
                    <span class="dashboard-avatar">LA</span>
                    <strong>Local<br>workspace</strong>
                    <span aria-hidden="true">&#8964;</span>
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown(
        """
        <section class="dashboard-guide" aria-label="Getting started">
            <div class="dashboard-guide-heading">
                <span class="dashboard-guide-icon" aria-hidden="true">&#128214;</span>
                Getting Started: How to Use LiteAudit
            </div>
            <div class="dashboard-steps">
                <div class="dashboard-step">
                    <span class="dashboard-step-number">1</span>
                    <strong>Upload a File</strong>
                    <p>Go to File Scanner and upload a supported document.</p>
                </div>
                <span class="dashboard-step-arrow" aria-hidden="true">&#8594;</span>
                <div class="dashboard-step">
                    <span class="dashboard-step-number">2</span>
                    <strong>Scan &amp; Review</strong>
                    <p>Review the risk score and any indicators found.</p>
                </div>
                <span class="dashboard-step-arrow" aria-hidden="true">&#8594;</span>
                <div class="dashboard-step">
                    <span class="dashboard-step-number">3</span>
                    <strong>Check History</strong>
                    <p>Find previous scan results in Audit History.</p>
                </div>
                <span class="dashboard-step-arrow" aria-hidden="true">&#8594;</span>
                <div class="dashboard-step">
                    <span class="dashboard-step-number">4</span>
                    <strong>Monitor &amp; Report</strong>
                    <p>Track local file activity and scan trends in Reports.</p>
                </div>
            </div>
        </section>
        """,
        unsafe_allow_html=True,
    )

    metric_cards = [
        ("▤", "blue", dashboard_total_scans, "Files Scanned"),
        ("✓", "green", dashboard_clean_scans, "Clean"),
        ("▲", "amber", dashboard_review_scans, "Suspicious"),
        ("☣", "red", dashboard_malicious_scans, "Malicious"),
    ]
    metric_markup = "".join(
        f'<div class="dashboard-kpi"><div class="dashboard-kpi-icon {tone}" '
        f'aria-hidden="true">{icon}</div><div class="dashboard-kpi-copy">'
        f"<strong>{count:,}</strong><span>{label}</span></div></div>"
        for icon, tone, count, label in metric_cards
    )
    st.markdown(
        f'<div class="dashboard-kpis">{metric_markup}</div>',
        unsafe_allow_html=True,
    )

    score_label = f"{dashboard_security_score}%" if dashboard_total_scans else "—"
    score_angle = dashboard_security_score * 3.6 if dashboard_total_scans else 0
    score_description = (
        f"Clean scan rate across {dashboard_total_scans:,} saved scans."
        if dashboard_total_scans
        else "Scan a file to calculate the clean scan rate."
    )
    score_column, trends_column = st.columns([0.34, 0.66], gap="small")
    with score_column:
        st.markdown(
            f"""
            <section class="dashboard-score-card">
                <h2 class="dashboard-panel-title">◉ &nbsp;Security Score</h2>
                <div class="dashboard-score-ring"
                     style="--score-angle: {score_angle:.1f}deg"
                     role="img"
                     aria-label="Clean scan rate {escape(score_label)}">
                    <div class="dashboard-score-inner">
                        <strong>{escape(score_label)}</strong>
                        <span>Security<br>Score</span>
                    </div>
                </div>
                <p class="dashboard-score-note">{escape(score_description)}</p>
            </section>
            """,
            unsafe_allow_html=True,
        )

    with trends_column:
        with st.container(key="dashboard-chart-card"):
            st.markdown(
                """
                <div class="dashboard-chart-heading">
                    <span>Scanning Activity (Last 7 Days)</span>
                    <span class="dashboard-chart-legend">
                        <span class="dashboard-legend-item">
                            <span class="dashboard-legend-dot" style="background:#416fe4"></span>
                            Scans
                        </span>
                        <span class="dashboard-legend-item">
                            <span class="dashboard-legend-dot" style="background:#dc4c4c"></span>
                            Threats
                        </span>
                    </span>
                </div>
                """,
                unsafe_allow_html=True,
            )
            weekly_metrics = get_daily_scan_metrics(days=7)
            render_weekly_scan_chart(weekly_metrics)
elif selected_section == "File Scanner":
    st.markdown('<div class="file-scanner-root"></div>', unsafe_allow_html=True)
    all_scan_results = get_all_scans()
    flagged_scan_count = int(
        (
            all_scan_results["score"].ge(15)
            | all_scan_results["verdict"].isin(
                ["Suspicious", "Malicious", "High risk", "Review needed"]
            )
        ).sum()
    )
    alert_badge = (
        f"<span>{flagged_scan_count:,}</span>" if flagged_scan_count else ""
    )
    st.markdown(
        f"""
        <div class="file-scanner-header">
            <div>
                <h1 class="file-scanner-title">File Scanner</h1>
                <p class="file-scanner-subtitle">
                    Upload and scan files for harmful scripts, injections, and suspicious content.
                </p>
            </div>
            <div class="file-scanner-header-tools">
                <span class="file-scanner-header-alert" title="{flagged_scan_count:,} flagged scans">
                    &#128276;{alert_badge}
                </span>
                <span class="dashboard-avatar">LA</span>
                <span class="file-scanner-header-user">Local workspace &nbsp;⌄</span>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    upload_col, options_col = st.columns([1.65, .85], gap="medium")
    with upload_col:
        with st.container(key="file-upload-card"):
            st.markdown('<div class="file-scanner-upload-heading">Upload a file</div>', unsafe_allow_html=True)
            st.markdown(
                '<div class="file-scanner-upload-help">Files are inspected in memory and are never executed.</div>',
                unsafe_allow_html=True,
            )
            uploaded_files = st.file_uploader(
                "Drag and drop files here or click to browse",
                type=["pdf", "csv", "doc", "txt"],
                label_visibility="collapsed",
                accept_multiple_files=True,
                key="scanner_uploaded_files",
                help=(
                    "Supported files: PDF, CSV, DOC, TXT. Maximum file size: "
                    f"{MAX_FILE_SIZE_MB} MiB."
                ),
            )
            if uploaded_files:
                selected_file_rows = "".join(
                    (
                        '<div class="file-scanner-selected-row">'
                        f'<span class="file-scanner-selected-icon">'
                        f'{escape(Path(file.name).suffix.lstrip(".").upper() or "FILE")[:4]}'
                        "</span>"
                        '<span class="file-scanner-selected-meta">'
                        f'<span class="file-scanner-selected-name" '
                        f'title="{escape(file.name, quote=True)}">'
                        f"{escape(file.name)}</span>"
                        f'<span class="file-scanner-selected-size">'
                        f"{human_size(file.size)}</span>"
                        "</span></div>"
                    )
                    for file in uploaded_files
                )
                st.markdown(
                    f'<div class="file-scanner-selected-list">'
                    f'<div class="file-scanner-selected-heading">'
                    f"Selected files ({len(uploaded_files)})</div>"
                    f"{selected_file_rows}"
                    f'<div class="file-scanner-selected-total">'
                    f"{len(uploaded_files)} file(s) ready to scan</div></div>",
                    unsafe_allow_html=True,
                )
            st.caption(
                f"Supported files: PDF, CSV, DOC, TXT · Maximum size: "
                f"{MAX_FILE_SIZE_MB} MiB"
            )

    with options_col:
        with st.container(key="file-options-card"):
            st.markdown(
                '<div class="file-scanner-options-heading">Scan Options</div>',
                unsafe_allow_html=True,
            )
            check_signatures = st.checkbox(
                "Scan for malicious scripts",
                value=True,
                key="scan_check_signatures",
                help="Check for document actions, shell references, links, and known static patterns.",
            )
            check_injections = st.checkbox(
                "Check for injections",
                value=True,
                key="scan_check_injections",
                help="Check for script-injection and dynamic-code execution patterns.",
            )
            check_file_integrity = st.checkbox(
                "Analyze embedded content",
                value=True,
                key="scan_check_file_integrity",
                help=(
                    "Check PDF headers and embedded-file markers, plus binary "
                    "content in text files. Attachments are not extracted."
                ),
            )
            st.checkbox(
                "Include archive files (.zip)",
                value=False,
                disabled=True,
                key="scan_include_archives",
                help="Archive scanning is not supported. Extract and scan supported files individually.",
            )
            scan_clicked = st.button(
                "▶  Start Scan",
                type="primary",
                use_container_width=True,
                disabled=not uploaded_files,
                key="start_file_scan",
            )

    scan_notice = st.session_state.pop("scanner_scan_notice", None)
    if scan_notice:
        st.success(scan_notice)

    if scan_clicked and uploaded_files:
        if not (
            check_signatures or check_injections or check_file_integrity
        ):
            st.error("Enable at least one scan check before starting the scan.")
        else:
            completed_scans = 0
            oversized_files = 0
            last_scan_result = None
            for uploaded_file in uploaded_files:
                uploaded_bytes = uploaded_file.getvalue()
                if len(uploaded_bytes) > MAX_FILE_SIZE:
                    oversized_files += 1
                    st.error(
                        f"{uploaded_file.name}: exceeds the configured "
                        f"{MAX_FILE_SIZE_MB} MiB file limit and was skipped."
                    )
                    continue

                result = scan_document(
                    uploaded_file.name,
                    uploaded_bytes,
                    check_signatures=check_signatures,
                    check_injections=check_injections,
                    check_file_integrity=check_file_integrity,
                )
                scan_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                insert_scan_result(
                    filename=uploaded_file.name,
                    verdict=result["verdict"],
                    score=result["score"],
                    sha256=result["sha256"],
                    tone=result["tone"],
                    scan_date=scan_date,
                    findings=result["findings"],
                    file_size_bytes=len(uploaded_bytes),
                )
                completed_scans += 1
                last_scan_result = {
                    "filename": uploaded_file.name,
                    **result,
                }

            if completed_scans:
                st.session_state.last_scan_result = last_scan_result
                st.session_state.scanner_view_scan_id = None
                st.session_state.scanner_scan_notice = (
                    f"Scanned {completed_scans} file(s) successfully."
                )
                if oversized_files:
                    st.session_state.scanner_scan_notice += (
                        f" Skipped {oversized_files} file(s) over the size limit."
                    )
                st.rerun()

    st.markdown('<div class="file-scanner-section-heading">Scan Results</div>', unsafe_allow_html=True)
    st.markdown(
        """
        <div class="file-scanner-results">
            <div class="file-scanner-table-header">
                <span>File Name</span><span>File Type</span><span>Size</span>
                <span>Result</span><span>Threat Level</span><span>Actions</span>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    recent_results = all_scan_results.head(8)
    if recent_results.empty:
        st.info("Your scan results will appear here after your first file scan.")
    else:
        for scan in recent_results.itertuples(index=False):
            file_type = Path(str(scan.filename)).suffix.lstrip(".").upper() or "FILE"
            size_bytes = int(scan.file_size_bytes or 0)
            display_size = human_size(size_bytes) if size_bytes else "—"
            tone = (
                "danger"
                if int(scan.score) >= 50
                else "warn"
                if int(scan.score) >= 15
                else "safe"
            )
            result_label = (
                "High risk"
                if tone == "danger"
                else "Suspicious"
                if tone == "warn"
                else "Clean"
            )
            threat_level = (
                "High"
                if tone == "danger"
                else "Medium"
                if tone == "warn"
                else "Low"
            )
            with st.container(key=f"scan-result-row-{int(scan.id)}"):
                row_columns = st.columns([2.1, .65, .8, 1, .8, .55], gap="small")
                row_columns[0].markdown(
                    f'<div class="file-scanner-table-name" title="{escape(str(scan.filename), quote=True)}">'
                    f'{escape(str(scan.filename))}</div>',
                    unsafe_allow_html=True,
                )
                row_columns[1].markdown(escape(file_type))
                row_columns[2].markdown(escape(display_size))
                row_columns[3].markdown(
                    f'<span class="file-scanner-pill {tone}">{escape(result_label)}</span>',
                    unsafe_allow_html=True,
                )
                row_columns[4].markdown(
                    f'<span class="file-scanner-pill {tone}">{threat_level}</span>',
                    unsafe_allow_html=True,
                )
                if row_columns[5].button(
                    "View",
                    key=f"view_scan_{int(scan.id)}",
                    help="View saved scan details",
                ):
                    st.session_state.scanner_view_scan_id = int(scan.id)

    selected_scan_id = st.session_state.get("scanner_view_scan_id")
    if selected_scan_id is not None:
        selected_scan = all_scan_results.loc[
            all_scan_results["id"] == selected_scan_id
        ]
        if not selected_scan.empty:
            scan = selected_scan.iloc[0]
            st.markdown(
                f'<div class="file-scanner-view-panel"><strong>{escape(str(scan["filename"]))}</strong>'
                f' · {escape(str(scan["verdict"]))} · Risk score {int(scan["score"])}/100'
                f'<br><small>Scanned {escape(str(scan["scan_date"]))} · SHA-256 '
                f'{escape(str(scan["sha256"]))}</small></div>',
                unsafe_allow_html=True,
            )
            findings = json.loads(str(scan["findings_json"]))
            if findings:
                for finding in findings:
                    st.caption(
                        f"{finding['indicator']} · {int(finding['matches'])} match(es)"
                    )
            else:
                st.caption("No indicators were recorded for this scan.")

elif selected_section == "Audit History":
    st.markdown('<div class="audit-history-root"></div>', unsafe_allow_html=True)
    st.markdown(
        """
        <div class="file-scanner-header">
            <div class="audit-history-header">
                <h1 class="audit-history-title">Audit History</h1>
                <p class="audit-history-subtitle">
                    View and search past file scans for compliance and reporting.
                </p>
            </div>
            <div class="file-scanner-header-tools">
                <span class="file-scanner-header-alert" title="Audit notifications">
                    &#128276;
                </span>
                <span class="dashboard-avatar">LA</span>
                <span class="file-scanner-header-user">Local workspace &nbsp;⌄</span>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    if "delete_selection_version" not in st.session_state:
        st.session_state.delete_selection_version = 0
    if "deleted_scans_notice" in st.session_state:
        st.success(st.session_state.pop("deleted_scans_notice"))

    history_df = get_all_scans()
    filters = st.columns([1.8, .9, 1, .72], gap="small")
    with filters[0]:
        filename_query = st.text_input(
            "Search files",
            placeholder="Search files, users, or IDs...",
            key="history-search",
            label_visibility="collapsed",
        )
    with filters[1]:
        verdict_options = ["All results"] + sorted(history_df["verdict"].unique())
        selected_verdict = st.selectbox(
            "Result",
            verdict_options,
            key="history-result-filter",
            label_visibility="collapsed",
        )
    with filters[2]:
        date_filter = st.selectbox(
            "Date range",
            ["Last 30 Days", "Last 90 Days", "All Time"],
            key="history-date-filter",
            label_visibility="collapsed",
        )
    with filters[3]:
        st.download_button(
            "Export ⌄",
            data=history_df.drop(
                columns=["findings_json"], errors="ignore"
            ).to_csv(index=False).encode("utf-8"),
            file_name="liteaudit-audit-history.csv",
            mime="text/csv",
            use_container_width=True,
            disabled=history_df.empty,
            key="history-export",
        )

    filtered_history = history_df.copy()
    if filename_query.strip():
        query = filename_query.strip()
        search_columns = [
            filtered_history["filename"].astype(str),
            filtered_history["sha256"].astype(str),
            filtered_history["id"].astype(str),
            pd.Series("Local user", index=filtered_history.index),
        ]
        search_match = pd.concat(search_columns, axis=1).apply(
            lambda row: row.str.contains(query, case=False, regex=False).any(),
            axis=1,
        )
        filtered_history = filtered_history.loc[search_match]
    if selected_verdict != "All results":
        filtered_history = filtered_history[
            filtered_history["verdict"] == selected_verdict
        ]
    if date_filter != "All Time":
        days = 30 if date_filter == "Last 30 Days" else 90
        date_values = pd.to_datetime(filtered_history["scan_date"], errors="coerce")
        filtered_history = filtered_history[
            date_values >= pd.Timestamp.now() - pd.Timedelta(days=days)
        ]

    if history_df.empty:
        st.info("No scans have been saved yet. Scan a document to create the first record.")
    elif filtered_history.empty:
        st.info("No audit records match the selected filters.")
    else:
        rows_per_page = 5
        total_pages = max(
            1, (len(filtered_history) + rows_per_page - 1) // rows_per_page
        )
        current_page = min(
            max(1, int(st.session_state.get("history_page", 1))),
            total_pages,
        )
        st.session_state.history_page = current_page
        page_start = (current_page - 1) * rows_per_page
        page_rows = filtered_history.iloc[page_start:page_start + rows_per_page]

        table_rows = []
        for row in page_rows.itertuples(index=False):
            score = int(row.score)
            tone = "danger" if score >= 50 else "warn" if score >= 15 else "safe"
            threat_level = "High" if tone == "danger" else "Medium" if tone == "warn" else "Low"
            result_label = (
                "High risk" if tone == "danger"
                else "Suspicious" if tone == "warn"
                else "Clean"
            )
            result_icon = "✕" if tone == "danger" else "▲" if tone == "warn" else "✓"
            parsed_date = pd.to_datetime(row.scan_date, errors="coerce")
            formatted_date = (
                parsed_date.strftime("%m/%d/%Y %I:%M %p").replace(" 0", " ")
                if pd.notna(parsed_date)
                else str(row.scan_date)
            )
            filename = escape(str(row.filename))
            table_rows.append(
                "<tr>"
                f"<td>{escape(formatted_date)}</td>"
                f'<td title="{filename}">{filename}</td>'
                "<td>Local user</td>"
                f'<td><span class="audit-history-result {tone}">'
                f'<span aria-hidden="true">{result_icon}</span>{result_label}</span></td>'
                f'<td><span class="audit-history-level {threat_level.lower()}">'
                f"{threat_level}</span></td>"
                "</tr>"
            )
        table_html = (
            '<div class="audit-history-table-wrap"><table class="audit-history-table">'
            "<thead><tr><th>Date/Time</th><th>File Name</th><th>User</th>"
            "<th>Result</th><th>Threat Level</th></tr></thead>"
            f"<tbody>{''.join(table_rows)}</tbody></table>"
            '<div class="audit-history-pagination">'
            f'<span>{len(filtered_history):,} scan(s) · Page {current_page} of {total_pages}</span>'
            "</div></div>"
        )
        st.markdown(table_html, unsafe_allow_html=True)

        if total_pages > 1:
            page_window_start = max(1, min(current_page - 2, total_pages - 4))
            page_numbers = list(
                range(page_window_start, min(total_pages, page_window_start + 4) + 1)
            )
            page_columns = st.columns([1] + [1] * len(page_numbers) + [1], gap="small")
            if page_columns[0].button(
                "‹",
                key="history-page-previous",
                disabled=current_page == 1,
                help="Previous page",
            ):
                st.session_state.history_page = current_page - 1
                st.rerun()
            for index, page_number in enumerate(page_numbers, start=1):
                if page_columns[index].button(
                    str(page_number),
                    key=(
                        f"history-page-active-{page_number}"
                        if page_number == current_page
                        else f"history-page-{page_number}"
                    ),
                    type="primary" if page_number == current_page else "secondary",
                ):
                    st.session_state.history_page = page_number
                    st.rerun()
            if page_columns[-1].button(
                "›",
                key="history-page-next",
                disabled=current_page == total_pages,
                help="Next page",
            ):
                st.session_state.history_page = current_page + 1
                st.rerun()

        with st.expander("Manage audit records"):
            scan_labels = {
                int(row.id): (
                    f"{row.filename} — {row.scan_date} — {row.verdict} "
                    f"(record #{row.id})"
                )
                for row in filtered_history.itertuples(index=False)
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

elif selected_section == "Threat Detection":
    st.markdown('<div class="threat-detection-root"></div>', unsafe_allow_html=True)
    scan_records = get_all_scans()
    threat_count = int(
        (
            scan_records["score"].ge(15)
            | scan_records["verdict"].isin(
                ["Suspicious", "Malicious", "High risk", "Review needed"]
            )
        ).sum()
    )
    alert_badge = f"<span>{threat_count:,}</span>" if threat_count else ""
    st.markdown(
        f"""
        <div class="file-scanner-header threat-detection-header">
            <div>
                <h1 class="file-scanner-title">Threat Detection</h1>
                <p class="file-scanner-subtitle">
                    Detailed analysis of flagged files and detected threats.
                </p>
            </div>
            <div class="file-scanner-header-tools">
                <span class="file-scanner-header-alert" title="{threat_count:,} flagged scans">
                    &#128276;{alert_badge}
                </span>
                <span class="dashboard-avatar">LA</span>
                <span class="file-scanner-header-user">Local workspace &nbsp;⌄</span>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    list_column, detail_column = st.columns([.78, 1.82], gap="medium")
    with list_column:
        with st.container(key="threat-file-list"):
            st.markdown(
                '<div class="threat-panel-title">Scanned Files</div>',
                unsafe_allow_html=True,
            )
            search_threat = st.text_input(
                "Search files",
                placeholder="Search files...",
                key="threat-search",
                label_visibility="collapsed",
            )
            visible_scans = scan_records
            if search_threat.strip():
                visible_scans = visible_scans[
                    visible_scans["filename"].str.contains(
                        search_threat.strip(),
                        case=False,
                        na=False,
                        regex=False,
                    )
                ]

            if visible_scans.empty:
                st.info("No scanned files match your search.")
            else:
                selected_id = st.session_state.get("threat_selected_scan_id")
                if selected_id not in visible_scans["id"].tolist():
                    flagged_visible = visible_scans.loc[
                        (visible_scans["score"] >= 15)
                        | visible_scans["verdict"].isin(
                            ["Suspicious", "Malicious", "High risk", "Review needed"]
                        )
                    ]
                    default_row = (
                        flagged_visible.iloc[0]
                        if not flagged_visible.empty
                        else visible_scans.iloc[0]
                    )
                    selected_id = int(default_row["id"])
                    st.session_state.threat_selected_scan_id = selected_id

                for scan in visible_scans.itertuples(index=False):
                    score = int(scan.score)
                    tone = (
                        "danger"
                        if score >= 50
                        else "warn"
                        if score >= 15
                        else "safe"
                    )
                    level = (
                        "High"
                        if tone == "danger"
                        else "Medium"
                        if tone == "warn"
                        else "Low"
                    )
                    is_selected = int(scan.id) == int(selected_id)
                    if st.button(
                        f"{scan.filename}\n{level}",
                        key=(
                            f"threat-select-active-{int(scan.id)}"
                            if is_selected
                            else f"threat-select-{int(scan.id)}"
                        ),
                        type="primary" if is_selected else "secondary",
                        use_container_width=True,
                    ):
                        st.session_state.threat_selected_scan_id = int(scan.id)
                        st.rerun()

    with detail_column:
        with st.container(key="threat-detail-panel"):
            if visible_scans.empty:
                st.info(
                    "Scanned-file analysis will appear here when a matching record is available."
                )
            else:
                selected_threat = visible_scans.loc[
                    visible_scans["id"]
                    == st.session_state.threat_selected_scan_id
                ].iloc[0]
                selected_score = int(selected_threat["score"])
                selected_tone = (
                    "danger"
                    if selected_score >= 50
                    else "warn"
                    if selected_score >= 15
                    else "safe"
                )
                selected_level = (
                    "High"
                    if selected_tone == "danger"
                    else "Medium"
                    if selected_tone == "warn"
                    else "Low"
                )
                scan_date = pd.to_datetime(
                    selected_threat["scan_date"], errors="coerce"
                )
                formatted_scan_date = (
                    scan_date.strftime("%b %d, %Y %I:%M %p").replace(" 0", " ")
                    if pd.notna(scan_date)
                    else str(selected_threat["scan_date"])
                )
                file_extension = (
                    Path(str(selected_threat["filename"])).suffix.lstrip(".").upper()
                    or "FILE"
                )
                file_icon = (
                    "▤" if file_extension in {"PDF", "DOC", "DOCX"} else "▧"
                )
                st.markdown(
                    f"""
                    <div class="threat-file-heading">
                        <div class="threat-file-icon {selected_tone}" aria-hidden="true">
                            {file_icon}
                        </div>
                        <div>
                            <div class="threat-file-name">
                                {escape(str(selected_threat["filename"]))}
                            </div>
                            <div class="threat-file-level">
                                Threat Level: <strong class="{selected_level.lower()}">
                                    {selected_level}
                                </strong>
                            </div>
                            <div class="threat-file-level">
                                Scanned: {escape(formatted_scan_date)}
                            </div>
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

                overview_tab, content_tab, details_tab = st.tabs(
                    ["Overview", "Detected Content", "Details"]
                )
                findings = json.loads(str(selected_threat["findings_json"]))
                if not isinstance(findings, list):
                    raise ValueError("Saved scan findings must be a JSON list.")

                if selected_tone == "danger":
                    alert_title = "High-Risk File Detected"
                    alert_message = (
                        "This file triggered high-risk static checks. Review the "
                        "indicators before opening it."
                    )
                elif selected_tone == "warn":
                    alert_title = "Suspicious File Detected"
                    alert_message = (
                        "One or more static checks need review. Inspect the detected "
                        "indicators before trusting this file."
                    )
                else:
                    alert_title = "No Known Indicators Detected"
                    alert_message = (
                        "The selected checks did not find a known indicator. "
                        "This does not prove that the file is safe."
                    )

                with overview_tab:
                    alert_class = "" if selected_tone != "safe" else "safe"
                    alert_icon = (
                        "☣"
                        if selected_tone == "danger"
                        else "!"
                        if selected_tone == "warn"
                        else "✓"
                    )
                    st.markdown(
                        f"""
                        <div class="threat-alert-card {alert_class}">
                            <span class="threat-alert-icon" aria-hidden="true">
                                {alert_icon}
                            </span>
                            <div class="threat-alert-copy">
                                <strong>{alert_title}</strong>
                                <span>{alert_message}</span>
                            </div>
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )
                    indicator_rows = []
                    if findings:
                        for finding in findings:
                            indicator = str(
                                finding.get("indicator", "Unknown indicator")
                            )
                            explanation = INDICATOR_EXPLANATIONS.get(
                                indicator,
                                "A file-format consistency check was triggered.",
                            )
                            indicator_rows.append(
                                '<div class="threat-indicator-row">'
                                '<span class="threat-indicator-dot"></span>'
                                f'<span title="{escape(explanation, quote=True)}">'
                                f'{escape(indicator)} · '
                                f'{int(finding.get("matches", 0))} match(es)'
                                "</span></div>"
                            )
                    indicators_content = (
                        "".join(indicator_rows)
                        if indicator_rows
                        else '<p class="threat-empty-indicators">'
                        "No indicators were recorded for this scan.</p>"
                    )
                    st.markdown(
                        '<div class="threat-indicator-card">'
                        "<h3>Threat Indicators</h3>"
                        f"{indicators_content}</div>",
                        unsafe_allow_html=True,
                    )
                    st.caption(
                        "Static scan findings are signals for review, not proof that "
                        "a file is malicious or safe."
                    )

                with content_tab:
                    if findings:
                        for finding in findings:
                            indicator = str(
                                finding.get("indicator", "Unknown indicator")
                            )
                            explanation = INDICATOR_EXPLANATIONS.get(
                                indicator,
                                "A file-format consistency check was triggered.",
                            )
                            st.markdown(
                                f"**{escape(indicator)}**  \n"
                                f"{escape(explanation)}  \n"
                                f"Matches: **{int(finding.get('matches', 0))}** · "
                                f"Risk weight: **{int(finding.get('weight', 0))}**"
                            )
                            st.divider()
                    else:
                        st.success("No indicators were found in this scan.")

                with details_tab:
                    extension = Path(str(selected_threat["filename"])).suffix.upper()
                    size_value = int(
                        selected_threat.get("file_size_bytes", 0) or 0
                    )
                    details_markup = f"""
                    <div class="threat-detail-card">
                        <h3>File Details</h3>
                        <div class="threat-meta-grid">
                            <div class="threat-meta-item">
                                <span>File Type</span>
                                <strong>{escape(extension or "Unknown")}</strong>
                            </div>
                            <div class="threat-meta-item">
                                <span>File Size</span>
                                <strong>{escape(human_size(size_value) if size_value else "Unknown")}</strong>
                            </div>
                            <div class="threat-meta-item">
                                <span>Verdict</span>
                                <strong>{escape(str(selected_threat["verdict"]))}</strong>
                            </div>
                            <div class="threat-meta-item">
                                <span>Risk Score</span><strong>{selected_score}/100</strong>
                            </div>
                            <div class="threat-meta-item">
                                <span>Scan Record</span>
                                <strong>#{int(selected_threat["id"])}</strong>
                            </div>
                            <div class="threat-meta-item">
                                <span>Indicators</span><strong>{len(findings)}</strong>
                            </div>
                        </div>
                        <span>SHA-256</span><br>
                        <strong>{escape(str(selected_threat["sha256"]))}</strong>
                    </div>
                    """
                    st.markdown(details_markup, unsafe_allow_html=True)

elif selected_section == "File Activity Monitor":
    st.markdown('<div class="activity-monitor-root"></div>', unsafe_allow_html=True)
    st.markdown(
        """
        <div class="file-scanner-header">
            <div class="activity-monitor-header">
                <h1 class="activity-monitor-title">File Activity Monitor</h1>
                <p class="activity-monitor-subtitle">
                    Monitor new and background downloads in the Downloads folder.
                </p>
            </div>
            <div class="file-scanner-header-tools">
                <span class="file-scanner-header-alert" title="File activity alerts">
                    &#128276;
                </span>
                <span class="dashboard-avatar">LA</span>
                <span class="file-scanner-header-user">Local workspace &nbsp;⌄</span>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    render_file_activity_monitor()

elif selected_section == "User Management":
    st.markdown('<div class="user-management-root"></div>', unsafe_allow_html=True)
    st.markdown(
        """
        <div class="file-scanner-header">
            <div class="user-management-header">
                <h1 class="user-management-title">User Management</h1>
                <p class="user-management-subtitle">
                    Manage user accounts, roles, and permissions.
                </p>
            </div>
            <div class="file-scanner-header-tools">
                <span class="file-scanner-header-alert" title="User management">
                    &#128276;
                </span>
                <span class="dashboard-avatar">LA</span>
                <span class="file-scanner-header-user">Local workspace &nbsp;⌄</span>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    if "show_add_user_form" not in st.session_state:
        st.session_state.show_add_user_form = False
    if "managed_user_id" not in st.session_state:
        st.session_state.managed_user_id = None

    users_df = get_users()
    add_action, _ = st.columns([1, 5])
    with add_action:
        if st.button(
            "＋ Add User",
            key="user-add-button",
            type="primary",
            use_container_width=True,
        ):
            st.session_state.show_add_user_form = not st.session_state.show_add_user_form
            st.rerun()

    if users_df.empty:
        st.info("No users have been added yet. Select Add User to create the first account.")
    else:
        with st.container(key="user-management-table"):
            user_header = st.columns([1.05, 1.7, 1.3, .8, 1.45, .65], gap="small")
            for column, heading in zip(
                user_header,
                ["Name", "Email", "Role", "Status", "Last Login", "Actions"],
            ):
                column.markdown(
                    f'<div class="user-management-table-header">{heading}</div>',
                    unsafe_allow_html=True,
                )
            for user in users_df.itertuples(index=False):
                user_id = int(user.id)
                with st.container(key=f"user-row-{user_id}"):
                    row_columns = st.columns(
                        [1.05, 1.7, 1.3, .8, 1.45, .65],
                        gap="small",
                    )
                    row_columns[0].markdown(
                        f'<div class="user-management-cell">{escape(str(user.name))}</div>',
                        unsafe_allow_html=True,
                    )
                    row_columns[1].markdown(
                        f'<div class="user-management-cell">{escape(str(user.email))}</div>',
                        unsafe_allow_html=True,
                    )
                    row_columns[2].markdown(
                        f'<div class="user-management-cell">{escape(str(user.role))}</div>',
                        unsafe_allow_html=True,
                    )
                    status_class = (
                        "active" if str(user.status) == "Active" else "inactive"
                    )
                    row_columns[3].markdown(
                        f'<span class="user-status {status_class}">'
                        f'{escape(str(user.status))}</span>',
                        unsafe_allow_html=True,
                    )
                    row_columns[4].markdown(
                        '<div class="user-management-cell" '
                        'title="Login events are not tracked">Not recorded</div>',
                        unsafe_allow_html=True,
                    )
                    with row_columns[5]:
                        edit_action, menu_action = st.columns(2, gap="small")
                        if edit_action.button(
                            "✎",
                            key=f"user-edit-{user_id}",
                            help=f"Edit {user.name}",
                        ):
                            st.session_state.managed_user_id = user_id
                            st.session_state.show_add_user_form = False
                            st.rerun()
                        if menu_action.button(
                            "⋮",
                            key=f"user-delete-{user_id}",
                            help=f"Delete {user.name}",
                        ):
                            st.session_state.confirm_delete_user_id = user_id

    roles = ["Administrator", "Security Analyst", "Employee"]
    statuses = ["Active", "Inactive"]
    configured_role = get_app_setting("default_user_role", "Employee")
    default_role_index = (
        roles.index(configured_role)
        if configured_role in roles
        else roles.index("Employee")
    )

    if st.session_state.show_add_user_form:
        with st.form("add_user_form", clear_on_submit=True):
            st.markdown("#### Add user")
            new_name = st.text_input("Name", key="new_user_name")
            new_email = st.text_input("Email", key="new_user_email")
            new_role = st.selectbox(
                "Role",
                roles,
                index=default_role_index,
                key="new_user_role",
            )
            new_status = st.selectbox(
                "Status", statuses, key="new_user_status"
            )
            add_submitted = st.form_submit_button(
                "Add user",
                type="primary",
                use_container_width=True,
            )
        if add_submitted:
            if not new_name.strip():
                st.error("Enter a name.")
            elif not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", new_email.strip()):
                st.error("Enter a valid email address.")
            else:
                try:
                    insert_user(new_name, new_email, new_role, new_status)
                except sqlite3.IntegrityError:
                    st.error("That email address already exists in the directory.")
                else:
                    record_workspace_notification(
                        "User directory updated",
                        "A user entry was added to the local directory.",
                        "User Management",
                    )
                    st.success("User added.")
                    st.session_state.show_add_user_form = False
                    st.rerun()

    selected_user_id = st.session_state.managed_user_id
    if selected_user_id is not None:
        selected_user_rows = users_df.loc[users_df["id"] == selected_user_id]
        if selected_user_rows.empty:
            st.session_state.managed_user_id = None
        else:
            selected_user = selected_user_rows.iloc[0]
            with st.expander(
                f"Edit {selected_user['name']}",
                expanded=True,
                key="user-edit-panel",
            ):
                with st.form("edit_user_form"):
                    edit_name = st.text_input(
                        "Name",
                        value=str(selected_user["name"]),
                        key=f"edit_user_name_{selected_user_id}",
                    )
                    edit_email = st.text_input(
                        "Email",
                        value=str(selected_user["email"]),
                        key=f"edit_user_email_{selected_user_id}",
                    )
                    edit_role = st.selectbox(
                        "Role",
                        roles,
                        index=roles.index(str(selected_user["role"])),
                        key=f"edit_user_role_{selected_user_id}",
                    )
                    edit_status = st.selectbox(
                        "Status",
                        statuses,
                        index=statuses.index(str(selected_user["status"])),
                        key=f"edit_user_status_{selected_user_id}",
                    )
                    save_col, cancel_col = st.columns(2)
                    edit_submitted = save_col.form_submit_button(
                        "Save changes",
                        type="primary",
                        use_container_width=True,
                    )
                    cancel_edit = cancel_col.form_submit_button(
                        "Cancel",
                        use_container_width=True,
                    )
                if edit_submitted:
                    if not edit_name.strip():
                        st.error("Enter a name.")
                    elif not re.fullmatch(
                        r"[^@\s]+@[^@\s]+\.[^@\s]+", edit_email.strip()
                    ):
                        st.error("Enter a valid email address.")
                    else:
                        try:
                            update_user(
                                int(selected_user_id),
                                edit_name,
                                edit_email,
                                edit_role,
                                edit_status,
                            )
                        except sqlite3.IntegrityError:
                            st.error("That email address already exists in the directory.")
                        else:
                            record_workspace_notification(
                                "User directory updated",
                                "A local user entry was changed.",
                                "User Management",
                            )
                            st.session_state.managed_user_id = None
                            st.success("User updated.")
                            st.rerun()
                if cancel_edit:
                    st.session_state.managed_user_id = None
                    st.rerun()

    confirm_delete_id = st.session_state.get("confirm_delete_user_id")
    if confirm_delete_id is not None:
        delete_target = users_df.loc[users_df["id"] == confirm_delete_id]
        if not delete_target.empty:
            st.warning(
                f"Delete {delete_target.iloc[0]['name']} from this directory? "
                "This cannot be undone."
            )
            confirm_col, cancel_col = st.columns(2)
            if confirm_col.button(
                "Confirm delete",
                key="confirm-delete-user",
                type="primary",
            ):
                deleted_users = delete_users([int(confirm_delete_id)])
                if deleted_users:
                    record_workspace_notification(
                        "User directory updated",
                        "A user entry was removed from the local directory.",
                        "User Management",
                    )
                st.session_state.pop("confirm_delete_user_id", None)
                st.rerun()
            if cancel_col.button("Cancel", key="cancel-delete-user"):
                st.session_state.pop("confirm_delete_user_id", None)
                st.rerun()

    st.caption(
        "Local directory only. This prototype does not authenticate users or track login activity."
    )

elif selected_section == "Settings":
    st.markdown('<div class="settings-root"></div>', unsafe_allow_html=True)
    st.markdown(
        """
        <div class="file-scanner-header">
            <div class="settings-page-header">
                <h1 class="settings-page-title">Settings</h1>
                <p class="settings-page-subtitle">
                    Configure scanning, monitoring, notifications, and system preferences.
                </p>
            </div>
            <div class="file-scanner-header-tools">
                <span class="file-scanner-header-alert" title="Settings notifications">
                    &#128276;
                </span>
                <span class="dashboard-avatar">LA</span>
                <span class="file-scanner-header-user">Local workspace &nbsp;⌄</span>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    setting_categories = [
        ("⚙", "General"),
        ("⬟", "Scanning"),
        ("♧", "Alerts & Notifications"),
        ("⇩", "Downloads Monitor"),
        ("▤", "Database"),
        ("☷", "System"),
    ]
    if "settings_category" not in st.session_state:
        st.session_state.settings_category = "General"

    nav_column, content_column = st.columns([.82, 2.18], gap="medium")
    with nav_column:
        with st.container(key="settings-category-panel"):
            for icon, category in setting_categories:
                active = st.session_state.settings_category == category
                if st.button(
                    f"{icon}  {category}",
                    key=(
                        f"settings-nav-active-{category}"
                        if active
                        else f"settings-nav-{category}"
                    ),
                    type="primary" if active else "secondary",
                    use_container_width=True,
                ):
                    st.session_state.settings_category = category
                    st.rerun()

    with content_column:
        with st.container(key="settings-content"):
            active_category = st.session_state.settings_category
            st.markdown(
                f'<div class="settings-section-heading">{escape(active_category)} Settings</div>',
                unsafe_allow_html=True,
            )

            if active_category == "General":
                roles = ["Employee", "Security Analyst", "Administrator"]
                configured_role = get_app_setting("default_user_role", "Employee")
                if configured_role not in roles:
                    configured_role = "Employee"
                retention_options = [
                    "30 Days",
                    "90 Days",
                    "180 Days",
                    "365 Days",
                    "Indefinite",
                ]
                configured_retention = get_app_setting(
                    "audit_log_retention_days", "365"
                )
                retention_labels = {
                    "30": "30 Days",
                    "90": "90 Days",
                    "180": "180 Days",
                    "365": "365 Days",
                    "indefinite": "Indefinite",
                }
                saved_retention = retention_labels.get(
                    configured_retention.lower(), "365 Days"
                )
                with st.form("general_settings_form"):
                    org_label, org_input = st.columns([.82, 1.18])
                    org_label.markdown(
                        '<div class="settings-field-label">Organization Name</div>',
                        unsafe_allow_html=True,
                    )
                    organization_name = org_input.text_input(
                        "Organization Name",
                        value=get_app_setting("organization_name", "LiteAudit Enterprise"),
                        label_visibility="collapsed",
                        key="settings-organization-name",
                    )

                    retention_label, retention_input = st.columns([.82, 1.18])
                    retention_label.markdown(
                        '<div class="settings-field-label">Audit Log Retention</div>',
                        unsafe_allow_html=True,
                    )
                    retention_choice = retention_input.selectbox(
                        "Audit Log Retention",
                        retention_options,
                        index=retention_options.index(saved_retention),
                        label_visibility="collapsed",
                        key="settings-retention",
                    )

                    role_label, role_input = st.columns([.82, 1.18])
                    role_label.markdown(
                        '<div class="settings-field-label">Default User Role</div>',
                        unsafe_allow_html=True,
                    )
                    default_role = role_input.selectbox(
                        "Default User Role",
                        roles,
                        index=roles.index(configured_role),
                        label_visibility="collapsed",
                        key="settings-default-role",
                    )

                    save_general = st.form_submit_button(
                        "Save Changes",
                        type="primary",
                        use_container_width=True,
                    )
                if save_general:
                    if not organization_name.strip():
                        st.error("Organization name cannot be empty.")
                    else:
                        retention_values = {
                            "30 Days": "30",
                            "90 Days": "90",
                            "180 Days": "180",
                            "365 Days": "365",
                            "Indefinite": "indefinite",
                        }
                        updates = [
                            (
                                "organization_name",
                                organization_name.strip(),
                                "workspace name",
                                "LiteAudit Enterprise",
                            ),
                            (
                                "default_user_role",
                                default_role,
                                "default user role",
                                "Employee",
                            ),
                            (
                                "audit_log_retention_days",
                                retention_values[retention_choice],
                                "audit retention",
                                "365",
                            ),
                        ]
                        changed_settings = [
                            label
                            for key, value, label, default in updates
                            if get_app_setting(key, default) != value
                        ]
                        for key, value, _, _ in updates:
                            set_app_setting(key, value)
                        if changed_settings:
                            record_settings_change(
                                "Changed: " + ", ".join(changed_settings) + "."
                            )
                        st.success("Settings saved.")
                        st.rerun()

                theme_label, theme_choice_column = st.columns([.82, 1.18])
                theme_label.markdown(
                    '<div class="settings-field-label">Theme</div>',
                    unsafe_allow_html=True,
                )
                theme_choice_column.radio(
                    "Theme",
                    ["Light Mode", "Dark Mode"],
                    index=0 if st.session_state.light_mode else 1,
                    horizontal=True,
                    label_visibility="collapsed",
                    key="settings-theme-choice",
                    on_change=save_settings_theme_preference,
                )
                st.caption(
                    "Retention is a cleanup target only. Expired records are never "
                    "removed automatically; review them in Database settings."
                )
                st.toggle(
                    "Auto-Update Scanner",
                    value=False,
                    disabled=True,
                    help="Scanner rule updates are delivered with application releases.",
                )
                st.caption(
                    "Automatic scanner updates are unavailable because this local "
                    "prototype has no update service."
                )

            elif active_category == "Scanning":
                with st.form("scanning_settings_form"):
                    file_size_limit = st.number_input(
                        "Maximum file size (MiB)",
                        min_value=1,
                        max_value=25,
                        value=MAX_FILE_SIZE_MB,
                        step=1,
                        help="Limits the size of files accepted by the scanner, up to 25 MiB.",
                    )
                    st.text_input(
                        "Supported file types",
                        value="PDF, CSV, DOC, TXT",
                        disabled=True,
                    )
                    st.caption(
                        "Files are scanned only after you select Run secure scan. "
                        "The app does not execute files or save uploaded contents to disk."
                    )
                    if st.form_submit_button("Save Scanning Settings"):
                        new_limit = str(int(file_size_limit))
                        old_limit = get_app_setting("max_file_size_mb", "25")
                        set_app_setting("max_file_size_mb", new_limit)
                        if old_limit != new_limit:
                            record_settings_change(
                                f"Maximum scan file size changed to {new_limit} MiB."
                            )
                        st.success("Scanning settings saved.")
                        st.rerun()

            elif active_category == "Alerts & Notifications":
                with st.form("alert_settings_form"):
                    high_risk_alerts = st.checkbox(
                        "Show an in-app alert for high-risk scans",
                        value=get_app_setting("alert_high_risk", "true") == "true",
                    )
                    file_activity_alerts = st.checkbox(
                        "Highlight new or changing files in the activity monitor",
                        value=get_app_setting("alert_file_activity", "false") == "true",
                    )
                    if st.form_submit_button("Save Alert Preferences"):
                        old_high_risk = (
                            get_app_setting("alert_high_risk", "true") == "true"
                        )
                        old_file_activity = (
                            get_app_setting("alert_file_activity", "false") == "true"
                        )
                        set_app_setting(
                            "alert_high_risk",
                            "true" if high_risk_alerts else "false",
                        )
                        set_app_setting(
                            "alert_file_activity",
                            "true" if file_activity_alerts else "false",
                        )
                        changed_preferences = []
                        if old_high_risk != high_risk_alerts:
                            changed_preferences.append(
                                f"high-risk scan alerts "
                                f"{'enabled' if high_risk_alerts else 'disabled'}"
                            )
                        if old_file_activity != file_activity_alerts:
                            changed_preferences.append(
                                f"file activity alerts "
                                f"{'enabled' if file_activity_alerts else 'disabled'}"
                            )
                        if changed_preferences:
                            record_settings_change(
                                "Changed: " + ", ".join(changed_preferences) + "."
                            )
                        st.success("Alert preferences saved.")
                st.caption(
                    "These preferences control alerts inside LiteAudit only. Email and "
                    "desktop notification delivery are not configured."
                )

            elif active_category == "Downloads Monitor":
                st.write(
                    "Monitor a local folder for downloads. The monitor records file "
                    "names and sizes only; content is read only when you explicitly scan."
                )
                st.toggle(
                    "Enable local folder monitoring",
                    key="local_download_monitor_enabled",
                    disabled=not LOCAL_DOWNLOAD_MONITOR_ENABLED,
                    on_change=save_download_monitor_settings,
                )
                st.text_input(
                    "Folder path",
                    key="local_download_folder",
                    disabled=not LOCAL_DOWNLOAD_MONITOR_ENABLED,
                    on_change=save_download_monitor_settings,
                )
                if not LOCAL_DOWNLOAD_MONITOR_ENABLED:
                    st.info(
                        "Set LITEAUDIT_ENABLE_LOCAL_DOWNLOAD_MONITOR=1 in the local "
                        "app environment to enable monitoring."
                    )
                if st.button("Open File Activity Monitor", key="settings_open_monitor"):
                    st.session_state.selected_section = "File Activity Monitor"
                    st.rerun()

            elif active_category == "Database":
                scan_count = int(get_verdict_metrics()["total_files"].sum())
                database_metrics = st.columns(3, gap="medium")
                database_metrics[0].metric("Scan Records", f"{scan_count:,}")
                database_metrics[1].metric("User Directory", f"{len(get_users()):,}")
                database_metrics[2].metric("Storage", "SQLite")
                st.code(str(Path("my_data.db").resolve()), language="text")
                st.caption(
                    "Scan metadata and settings are stored locally. Uploaded document "
                    "contents are not saved to the database."
                )
                retention_days = get_app_setting("audit_log_retention_days", "365")
                if retention_days.lower() == "indefinite":
                    st.info("Audit log retention is indefinite; no records are eligible for cleanup.")
                else:
                    try:
                        retention_count = max(1, int(retention_days))
                    except ValueError as error:
                        raise ValueError(
                            "Saved audit log retention must be a day count or 'indefinite'."
                        ) from error
                    cutoff = (
                        pd.Timestamp.now().normalize()
                        - pd.Timedelta(days=retention_count)
                    )
                    eligible_records = get_all_scans()
                    eligible_dates = pd.to_datetime(
                        eligible_records["scan_date"],
                        errors="coerce",
                    )
                    eligible_count = int((eligible_dates < cutoff).sum())
                    st.markdown(
                        f"Retention target: **{retention_count} days** · "
                        f"**{eligible_count:,}** record(s) older than "
                        f"{cutoff.strftime('%Y-%m-%d')}."
                    )
                    confirm_expired = st.checkbox(
                        "I understand this permanently deletes expired scan records.",
                        key="confirm-expired-scan-cleanup",
                        disabled=eligible_count == 0,
                    )
                    if st.button(
                        "Delete Expired Records",
                        key="delete-expired-scans",
                        type="primary",
                        disabled=eligible_count == 0 or not confirm_expired,
                    ):
                        deleted_count = delete_scans_before(
                            cutoff.strftime("%Y-%m-%d")
                        )
                        st.session_state.expired_scan_cleanup_notice = (
                            f"Deleted {deleted_count:,} expired scan record(s)."
                        )
                        st.rerun()
                    if "expired_scan_cleanup_notice" in st.session_state:
                        st.success(
                            st.session_state.pop("expired_scan_cleanup_notice")
                        )
                if st.button("Open Audit History", key="settings_open_history"):
                    st.session_state.selected_section = "Audit History"
                    st.rerun()

            elif active_category == "System":
                scan_count = int(get_verdict_metrics()["total_files"].sum())
                st.write("**Application version:** v0.8.2")
                st.write(f"**Saved scans:** {scan_count:,}")
                st.write(f"**Audit database:** `{Path('my_data.db').resolve()}`")
                st.info(
                    "LiteAudit is a local document-scanning prototype, not a production "
                    "malware analysis or identity-management service."
                )

elif selected_section == "Reports & Analytics":
    st.markdown(
        '<div class="reports-analytics-root"></div>',
        unsafe_allow_html=True,
    )
    st.markdown(
        '<div class="file-scanner-header">'
        '<div class="reports-analytics-header">'
        '<h1 class="reports-analytics-title">Reports &amp; Analytics</h1>'
        '<p class="reports-analytics-subtitle">'
        'Security trends, scan statistics, and compliance reporting.</p></div>'
        '<div class="file-scanner-header-tools">'
        '<span class="file-scanner-header-alert" title="Report notifications">'
        '&#128276;</span><span class="dashboard-avatar">LA</span>'
        '<span class="file-scanner-header-user">Local workspace &nbsp;⌄</span>'
        '</div></div>',
        unsafe_allow_html=True,
    )
    overview_tab, trends_tab, users_tab, compliance_tab = st.tabs(
        ["Overview", "Threat Trends", "User Activity", "Compliance"]
    )
    report_records = get_all_scans()
    report_verdicts = get_verdict_metrics()
    with overview_tab:
        report_cutoff = pd.Timestamp.now().normalize() - pd.Timedelta(days=29)
        report_dates = pd.to_datetime(report_records["scan_date"], errors="coerce")
        report_30_days = report_records.loc[report_dates >= report_cutoff].copy()
        recent_dates = report_dates.loc[report_dates >= report_cutoff]
        report_30_days["scan_timestamp"] = recent_dates
        recent_total = len(report_30_days)
        recent_scores = pd.to_numeric(report_30_days["score"], errors="coerce").fillna(0)
        recent_verdicts = report_30_days["verdict"].fillna("").astype(str)
        malicious_mask = recent_scores.ge(50) | recent_verdicts.isin(
            ["Malicious", "High risk"]
        )
        suspicious_mask = ~malicious_mask & (
            recent_scores.ge(15)
            | recent_verdicts.isin(["Suspicious", "Review needed"])
        )
        clean_mask = ~(malicious_mask | suspicious_mask)
        clean_count = int(clean_mask.sum())
        suspicious_count = int(suspicious_mask.sum())
        malicious_count = int(malicious_mask.sum())
        clean_rate = clean_count / recent_total * 100 if recent_total else 0
        suspicious_rate = (
            suspicious_count / recent_total * 100 if recent_total else 0
        )
        malicious_rate = malicious_count / recent_total * 100 if recent_total else 0

        st.markdown(
            '<div class="reports-overview-section">Key Metrics (Last 30 Days)</div>',
            unsafe_allow_html=True,
        )
        metrics_col, chart_col = st.columns([1.05, 1.3], gap="medium")
        with metrics_col:
            metric_definitions = [
                ("Files Scanned", f"{recent_total:,}", "▤", "blue"),
                ("Clean Rate", f"{clean_rate:.1f}%", "✓", "green"),
                ("Suspicious", f"{suspicious_rate:.1f}%", "▲", "amber"),
                ("Malicious", f"{malicious_rate:.1f}%", "☣", "red"),
            ]
            for start in (0, 2):
                metric_columns = st.columns(2, gap="small")
                for column, (label, value, icon, tone) in zip(
                    metric_columns,
                    metric_definitions[start:start + 2],
                ):
                    column.markdown(
                        f'<div class="reports-metric-card">'
                        f'<div class="reports-metric-label">{icon} &nbsp;{label}</div>'
                        f'<div class="reports-metric-value">{value}</div></div>',
                        unsafe_allow_html=True,
                    )

        with chart_col:
            st.markdown(
                '<div class="reports-overview-section">Scan Results Over Time</div>',
                unsafe_allow_html=True,
            )
            with st.container(key="reports-scan-chart"):
                if recent_total:
                    chart_source = report_30_days.copy()
                    chart_source["Result"] = "Clean"
                    chart_source.loc[suspicious_mask.to_numpy(), "Result"] = "Suspicious"
                    chart_source.loc[malicious_mask.to_numpy(), "Result"] = "Malicious"
                    period_start = pd.Timestamp.now().normalize() - pd.Timedelta(days=29)
                    days_from_start = (
                        chart_source["scan_timestamp"].dt.normalize() - period_start
                    ).dt.days
                    chart_source["Week"] = (
                        (days_from_start.clip(lower=0, upper=29) // 7 + 1)
                        .clip(upper=4)
                        .map(lambda value: f"Week {int(value)}")
                    )
                    chart_summary = (
                        chart_source.groupby(["Week", "Result"])
                        .size()
                        .rename("Scans")
                        .reset_index()
                    )
                    chart = (
                        alt.Chart(chart_summary)
                        .mark_bar(cornerRadiusTopLeft=3, cornerRadiusTopRight=3)
                        .encode(
                            x=alt.X(
                                "Week:N",
                                sort=["Week 1", "Week 2", "Week 3", "Week 4"],
                                title=None,
                                axis=alt.Axis(labelAngle=0, tickSize=0),
                            ),
                            y=alt.Y(
                                "Scans:Q",
                                title=None,
                                stack="zero",
                                axis=alt.Axis(tickMinStep=1, grid=True),
                            ),
                            color=alt.Color(
                                "Result:N",
                                sort=["Clean", "Suspicious", "Malicious"],
                                scale=alt.Scale(
                                    domain=["Clean", "Suspicious", "Malicious"],
                                    range=["#57b45f", "#f0bf3f", "#e34d4d"],
                                ),
                                legend=alt.Legend(
                                    orient="top",
                                    direction="horizontal",
                                    title=None,
                                    symbolType="circle",
                                ),
                            ),
                            tooltip=[
                                alt.Tooltip("Week:N", title="Period"),
                                alt.Tooltip("Result:N", title="Result"),
                                alt.Tooltip("Scans:Q", title="Files scanned"),
                            ],
                        )
                        .properties(height=185)
                    )
                    st.altair_chart(chart, width="stretch")
                else:
                    st.info("Scan results will appear here after files are scanned.")

        report_export_records = report_records.drop(
            columns=["findings_json"], errors="ignore"
        )
        report_csv = report_export_records.to_csv(index=False).encode("utf-8")
        report_pdf = build_analytics_pdf(
            recent_total,
            clean_rate,
            suspicious_rate,
            malicious_rate,
            report_records,
        )
        report_snapshot = st.session_state.get("analytics_report_snapshot", {})
        downloadable_csv = report_snapshot.get("csv", report_csv)
        downloadable_pdf = report_snapshot.get("pdf", report_pdf)
        action_columns = st.columns([1.05, .75, .75, 2.45], gap="small")
        generated_now = False
        with action_columns[0]:
            if st.button(
                "Generate Report ⌄",
                key="reports-generate",
                type="primary",
                use_container_width=True,
            ):
                st.session_state.analytics_report_snapshot = {
                    "csv": report_csv,
                    "pdf": report_pdf,
                    "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                }
                downloadable_csv = report_csv
                downloadable_pdf = report_pdf
                generated_now = True
        with action_columns[1]:
            st.download_button(
                "Export (PDF)",
                data=downloadable_pdf,
                file_name="liteaudit-analytics-report.pdf",
                mime="application/pdf",
                key="reports-export-pdf",
                use_container_width=True,
            )
        with action_columns[2]:
            st.download_button(
                "Export (CSV)",
                data=downloadable_csv,
                file_name="liteaudit-analytics-report.csv",
                mime="text/csv",
                key="reports-export-csv",
                use_container_width=True,
            )
        if generated_now:
            st.success(
                "Analytics report generated. Choose PDF or CSV to download it."
            )

    with trends_tab:
        st.markdown("#### Threat trends over time")
        daily_metrics = get_daily_scan_metrics()
        if daily_metrics.empty:
            st.info("Trend charts will appear after scans are recorded.")
        else:
            render_daily_scan_chart(daily_metrics, height=320)
            st.dataframe(
                daily_metrics,
                width="stretch",
                hide_index=True,
                column_config={
                    "scan_day": st.column_config.TextColumn("DATE", width="medium"),
                    "total_scans": st.column_config.NumberColumn("SCANS"),
                    "malicious_count": st.column_config.NumberColumn(
                        "MALICIOUS VERDICTS"
                    ),
                },
            )
            st.caption(
                "Malicious trend counts use verdicts labeled Malicious in the "
                "existing report query."
            )

    with users_tab:
        st.markdown("#### Directory overview")
        directory = get_users()
        user_metric_cols = st.columns(3, gap="medium")
        user_metric_cols[0].metric("Directory users", f"{len(directory):,}")
        user_metric_cols[1].metric(
            "Active users",
            f"{int(directory['status'].eq('Active').sum()):,}",
        )
        user_metric_cols[2].metric(
            "Inactive users",
            f"{int(directory['status'].eq('Inactive').sum()):,}",
        )
        if directory.empty:
            st.info("Add directory entries in User Management to see them here.")
        else:
            st.dataframe(
                directory.drop(columns=["id"]),
                width="stretch",
                hide_index=True,
            )
        st.caption(
            "Scan records are local and are not associated with a user identity, "
            "so this view does not attribute scan events to individual users."
        )

    with compliance_tab:
        st.markdown("#### Audit evidence")
        audit_cols = st.columns(3, gap="medium")
        audit_cols[0].metric("Retained scan records", f"{len(report_records):,}")
        audit_cols[1].metric(
            "Records with SHA-256",
            f"{int(report_records['sha256'].fillna('').ne('').sum()):,}",
        )
        audit_cols[2].metric(
            "Latest scan",
            str(report_records.iloc[0]["scan_date"])
            if not report_records.empty
            else "No scans",
        )
        st.caption(
            "These are local audit summaries, not a compliance certification. "
            "Records can be reviewed or deleted in Audit History."
        )
        st.download_button(
            "Export audit report (CSV)",
            data=report_records.drop(
                columns=["findings_json"], errors="ignore"
            ).to_csv(index=False).encode("utf-8"),
            file_name="liteaudit-security-report.csv",
            mime="text/csv",
            type="primary",
            disabled=report_records.empty,
        )

if selected_section not in {
    "Dashboard",
    "File Scanner",
    "Threat Detection",
    "User Management",
    "Reports & Analytics",
    "Settings",
}:
    st.caption("LiteAudit · Local document verification prototype · v0.8.2")
