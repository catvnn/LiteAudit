# database.py
import sqlite3
import pandas as pd
import streamlit as st

DB_FILE = "my_data.db"

@st.cache_resource
def get_db_connection():
    """Establishes a cached, thread-safe link to the local SQLite database file."""
    # check_same_thread=False is essential for multi-threaded Streamlit apps
    conn = sqlite3.connect(DB_FILE, check_same_thread=False)
    
    # Automatically bootstrap your table structure if running for the first time
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            verdict TEXT NOT NULL,
            score INTEGER NOT NULL,
            sha256 TEXT NOT NULL,
            tone TEXT NOT NULL,
            scan_date TEXT NOT NULL
        )
    """)
    conn.commit()
    return conn

# ==============================================================================
# WRAPPERS FOR YOUR SQL QUERIES
# ==============================================================================

@st.cache_data
def get_recent_scans():
    """Query 1: Fetch the 5 most recent records chronologically."""
    query = """
    SELECT filename, verdict, score, scan_date
    FROM scans
    ORDER BY scan_date DESC
    LIMIT 5;
    """
    return pd.read_sql_query(query, get_db_connection())


@st.cache_data
def search_executables(search_term="exe"):
    """Query 2: Isolate files containing specific pattern terms like '%exe%'."""
    query = "SELECT * FROM scans WHERE filename LIKE ?;"
    # Binds strings safely to prevent SQL injection risks
    return pd.read_sql_query(query, get_db_connection(), params=(f"%{search_term}%",))


@st.cache_data
def get_critical_threats(min_score=80):
    """Query 3: Fetch dangerous threat metrics scoring above a defined threshold."""
    query = """
    SELECT filename, sha256, score, tone
    FROM scans
    WHERE score >= ?
    ORDER BY score DESC;
    """
    return pd.read_sql_query(query, get_db_connection(), params=(min_score,))


@st.cache_data
def get_verdict_metrics():
    """Query 4: Aggregate grouped metrics totals across threat states."""
    query = """
    SELECT verdict, COUNT(*) AS total_files
    FROM scans
    GROUP BY verdict;
    """
    return pd.read_sql_query(query, get_db_connection())


@st.cache_data
def lookup_file_hash(sha256_hash):
    """Query 5: Exact string lookups across distinct binary hashes."""
    query = "SELECT * FROM scans WHERE sha256 = ?;"
    return pd.read_sql_query(query, get_db_connection(), params=(sha256_hash.strip(),))


# ➕ ADDED: REQUIRED FOR YOUR FULL AUDIT HISTORY VIEW TAB
@st.cache_data
def get_all_scans():
    """Query 6: Fetch every single record from the database, newest first."""
    query = """
    SELECT id, filename, verdict, score, sha256, tone, scan_date
    FROM scans
    ORDER BY scan_date DESC;
    """
    return pd.read_sql_query(query, get_db_connection())


def delete_scans(scan_ids: list[int]) -> int:
    """Delete selected scan records by their unique database IDs."""
    if not scan_ids:
        return 0

    unique_ids = tuple(dict.fromkeys(scan_ids))
    placeholders = ", ".join("?" for _ in unique_ids)
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        f"DELETE FROM scans WHERE id IN ({placeholders});",
        unique_ids,
    )
    conn.commit()
    st.cache_data.clear()
    return cursor.rowcount


# ==============================================================================
# LOG ENTRY DATA-WRITING FUNCTION
# ==============================================================================
def insert_scan_result(filename, verdict, score, sha256, tone, scan_date):
    """Inserts an analyzed file tracking record down into the tracking index."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO scans (filename, verdict, score, sha256, tone, scan_date)
        VALUES (?, ?, ?, ?, ?, ?);
    """, (filename, verdict, score, sha256, tone, scan_date))
    conn.commit()
    
    # Crucial step: Clear data caches so new rows show up in queries instantly!
    st.cache_data.clear()
