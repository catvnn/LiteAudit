# database.py
import sqlite3
import json
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
            scan_date TEXT NOT NULL,
            findings_json TEXT NOT NULL DEFAULT '[]',
            file_size_bytes INTEGER NOT NULL DEFAULT 0
        )
    """)
    scan_columns = {
        row[1] for row in cursor.execute("PRAGMA table_info(scans);").fetchall()
    }
    if "findings_json" not in scan_columns:
        cursor.execute(
            "ALTER TABLE scans ADD COLUMN findings_json TEXT NOT NULL DEFAULT '[]';"
        )
    if "file_size_bytes" not in scan_columns:
        cursor.execute(
            "ALTER TABLE scans ADD COLUMN file_size_bytes INTEGER NOT NULL DEFAULT 0;"
        )
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL COLLATE NOCASE UNIQUE,
            role TEXT NOT NULL CHECK (
                role IN ('Administrator', 'Security Analyst', 'Employee')
            ),
            status TEXT NOT NULL CHECK (status IN ('Active', 'Inactive')),
            created_at TEXT NOT NULL
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS app_settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
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


@st.cache_data(ttl=5)
def get_verdict_metrics():
    """Query 4: Aggregate grouped metrics totals across threat states."""
    query = """
    SELECT verdict, COUNT(*) AS total_files
    FROM scans
    GROUP BY verdict;
    """
    return pd.read_sql_query(query, get_db_connection())


@st.cache_data
def get_duplicate_uploads():
    """Find hashes uploaded more than once, ordered by upload count."""
    query = """
    SELECT sha256, filename, COUNT(*) AS upload_count, MAX(scan_date) AS last_seen
    FROM scans
    GROUP BY sha256
    HAVING COUNT(*) > 1
    ORDER BY upload_count DESC;
    """
    return pd.read_sql_query(query, get_db_connection())


@st.cache_data(ttl=5)
def get_daily_scan_metrics(days: int | None = None):
    """Count scans and threat verdicts by day, optionally limiting the date range."""
    date_filter = ""
    params = ()
    if days is not None:
        day_count = max(1, min(366, int(days)))
        date_filter = "WHERE DATE(scan_date) >= DATE('now', ?)"
        params = (f"-{day_count - 1} days",)

    query = """
    SELECT DATE(scan_date) AS scan_day,
           COUNT(*) AS total_scans,
           SUM(CASE WHEN verdict = 'Malicious' THEN 1 ELSE 0 END) AS malicious_count,
           SUM(
               CASE
                   WHEN score >= 15
                     OR verdict IN ('Suspicious', 'Malicious', 'High risk')
                   THEN 1
                   ELSE 0
               END
           ) AS threat_count
    FROM scans
    {date_filter}
    GROUP BY scan_day
    ORDER BY scan_day DESC;
    """.format(date_filter=date_filter)
    return pd.read_sql_query(query, get_db_connection(), params=params)


@st.cache_data
def get_executable_scans():
    """Find scans whose filenames indicate executable or script extensions."""
    query = """
    SELECT id AS scan_id, filename, verdict, score, scan_date
    FROM scans
    WHERE filename LIKE '%.exe%'
       OR filename LIKE '%.bat%'
       OR filename LIKE '%.sh%';
    """
    return pd.read_sql_query(query, get_db_connection())


@st.cache_data
def get_suspicious_scans():
    """Return records explicitly labeled Suspicious, newest first."""
    query = """
    SELECT id AS scan_id, filename, score, scan_date, sha256
    FROM scans
    WHERE verdict = 'Suspicious'
    ORDER BY scan_date DESC;
    """
    return pd.read_sql_query(query, get_db_connection())


@st.cache_data
def lookup_file_hash(sha256_hash):
    """Return scans matching an exact SHA-256 hash."""
    query = "SELECT * FROM scans WHERE sha256 = ?;"
    return pd.read_sql_query(query, get_db_connection(), params=(sha256_hash.strip(),))


# ➕ ADDED: REQUIRED FOR YOUR FULL AUDIT HISTORY VIEW TAB
@st.cache_data(ttl=5)
def get_all_scans():
    """Query 6: Fetch every single record from the database, newest first."""
    query = """
    SELECT id, filename, verdict, score, sha256, tone, scan_date, findings_json,
           file_size_bytes
    FROM scans
    ORDER BY scan_date DESC;
    """
    return pd.read_sql_query(query, get_db_connection())


def get_users():
    """Return local user directory entries, newest first."""
    query = """
    SELECT id, name, email, role, status, created_at
    FROM users
    ORDER BY id DESC;
    """
    return pd.read_sql_query(query, get_db_connection())


def insert_user(name: str, email: str, role: str, status: str) -> int:
    """Create one local user directory entry."""
    cursor = get_db_connection().cursor()
    cursor.execute(
        """
        INSERT INTO users (name, email, role, status, created_at)
        VALUES (?, ?, ?, ?, datetime('now', 'localtime'));
        """,
        (name.strip(), email.strip(), role, status),
    )
    cursor.connection.commit()
    st.cache_data.clear()
    return int(cursor.lastrowid)


def update_user(user_id: int, name: str, email: str, role: str, status: str) -> None:
    """Update an existing local user directory entry."""
    cursor = get_db_connection().cursor()
    cursor.execute(
        """
        UPDATE users
        SET name = ?, email = ?, role = ?, status = ?
        WHERE id = ?;
        """,
        (name.strip(), email.strip(), role, status, user_id),
    )
    if cursor.rowcount != 1:
        raise ValueError(f"User record {user_id} was not found.")
    cursor.connection.commit()
    st.cache_data.clear()


def delete_users(user_ids: list[int]) -> int:
    """Delete selected local user directory entries by their IDs."""
    if not user_ids:
        return 0

    unique_ids = tuple(dict.fromkeys(user_ids))
    placeholders = ", ".join("?" for _ in unique_ids)
    cursor = get_db_connection().cursor()
    cursor.execute(
        f"DELETE FROM users WHERE id IN ({placeholders});",
        unique_ids,
    )
    cursor.connection.commit()
    st.cache_data.clear()
    return cursor.rowcount


def get_app_setting(key: str, default: str) -> str:
    """Read a persisted app setting or return its supplied default."""
    cursor = get_db_connection().cursor()
    cursor.execute("SELECT value FROM app_settings WHERE key = ?;", (key,))
    row = cursor.fetchone()
    return str(row[0]) if row else default


def set_app_setting(key: str, value: str) -> None:
    """Persist one app setting."""
    cursor = get_db_connection().cursor()
    cursor.execute(
        """
        INSERT INTO app_settings (key, value)
        VALUES (?, ?)
        ON CONFLICT(key) DO UPDATE SET value = excluded.value;
        """,
        (key, value),
    )
    cursor.connection.commit()


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


def delete_scans_before(cutoff_date: str) -> int:
    """Delete scans older than an ISO date after the caller confirms retention cleanup."""
    cursor = get_db_connection().cursor()
    cursor.execute(
        "DELETE FROM scans WHERE DATE(scan_date) < DATE(?);",
        (cutoff_date,),
    )
    cursor.connection.commit()
    st.cache_data.clear()
    return cursor.rowcount


# ==============================================================================
# LOG ENTRY DATA-WRITING FUNCTION
# ==============================================================================
def insert_scan_result(
    filename,
    verdict,
    score,
    sha256,
    tone,
    scan_date,
    findings: list[dict] | None = None,
    file_size_bytes: int = 0,
):
    """Inserts an analyzed file tracking record down into the tracking index."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO scans (
            filename, verdict, score, sha256, tone, scan_date, findings_json,
            file_size_bytes
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?);
    """, (
        filename,
        verdict,
        score,
        sha256,
        tone,
        scan_date,
        json.dumps(findings or []),
        max(0, int(file_size_bytes)),
    ))
    conn.commit()
    
    # Crucial step: Clear data caches so new rows show up in queries instantly!
    st.cache_data.clear()
