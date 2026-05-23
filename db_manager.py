"""
SOAR SQLite Database Manager
=============================
Handles local storage and querying for accounts and emails.
Enables persistence and instant display of triaged email classifications.
"""

import os
import sqlite3
import json
import uuid
import logging
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import List, Dict, Any, Optional

from email_parser import html_to_text

logger = logging.getLogger(__name__)

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "soar_mail.db")
MAIL_CACHE_LIMIT = 25


def _coerce_received_ts(value: Any = None, date_value: str = "") -> int:
    """Return a millisecond epoch timestamp for stable arrival-time sorting."""
    if value not in (None, ""):
        try:
            ts = int(float(value))
            if ts > 0:
                return ts * 1000 if ts < 10_000_000_000 else ts
        except (TypeError, ValueError):
            pass

    raw_date = (date_value or "").strip()
    if not raw_date:
        return 0

    try:
        dt = datetime.fromisoformat(raw_date.replace("Z", "+00:00"))
    except ValueError:
        try:
            dt = parsedate_to_datetime(raw_date)
        except (TypeError, ValueError, IndexError, OverflowError):
            return 0

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp() * 1000)


def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _prune_account_emails_with_cursor(cursor, account_id: str, keep: int = MAIL_CACHE_LIMIT):
    cursor.execute("""
        SELECT id FROM emails
        WHERE account_id = ?
        ORDER BY COALESCE(received_ts, 0) DESC, COALESCE(date, '') DESC, COALESCE(processed_at, '') DESC
        LIMIT ?
    """, (account_id, keep))
    keep_ids = [row["id"] for row in cursor.fetchall()]
    if keep_ids:
        placeholders = ",".join("?" for _ in keep_ids)
        cursor.execute(
            f"DELETE FROM emails WHERE account_id = ? AND id NOT IN ({placeholders})",
            [account_id, *keep_ids]
        )


def prune_account_emails(account_id: str, keep: int = MAIL_CACHE_LIMIT):
    """Keep only the newest local messages for the active mail-client view."""
    if not account_id:
        return
    conn = get_db_connection()
    cursor = conn.cursor()
    _prune_account_emails_with_cursor(cursor, account_id, keep)
    conn.commit()
    conn.close()


def init_db():
    """Initializes the database schema."""
    logger.info(f"Initializing database at: {DB_PATH}")
    conn = get_db_connection()
    cursor = conn.cursor()

    # Enable foreign keys
    cursor.execute("PRAGMA foreign_keys = ON;")

    # Create accounts table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS accounts (
        id TEXT PRIMARY KEY,
        email TEXT UNIQUE NOT NULL,
        provider TEXT NOT NULL,          -- 'gmail' or 'outlook'
        status TEXT DEFAULT 'linked',    -- 'linked', 'active', 'disconnected'
        token_data TEXT,                 -- Serialized token JSON (if applicable)
        last_history_id TEXT,            -- Gmail history cursor for live polling
        initial_sync_complete INTEGER DEFAULT 0
    );
    """)

    # Create emails table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS emails (
        id TEXT PRIMARY KEY,
        account_id TEXT NOT NULL,
        sender TEXT NOT NULL,
        recipient TEXT NOT NULL,
        subject TEXT,
        date TEXT,
        received_ts INTEGER DEFAULT 0,
        body_plain TEXT,
        body_html TEXT,
        snippet TEXT,
        folder TEXT DEFAULT 'inbox',     -- 'inbox', 'marketing', 'archive', 'malicious', 'suspicious'
        verdict TEXT DEFAULT 'PENDING',  -- 'PENDING', 'MALICIOUS', 'SUSPICIOUS', 'CLEAN'
        score INTEGER DEFAULT 0,
        ai_verdict TEXT DEFAULT 'UNKNOWN',
        ai_score INTEGER DEFAULT 0,
        ai_reason TEXT,
        ticket_id TEXT,
        gemma_advisory TEXT,
        processed_at TEXT,
        is_read INTEGER DEFAULT 0,
        FOREIGN KEY(account_id) REFERENCES accounts(id) ON DELETE CASCADE
    );
    """)

    conn.commit()

    # Lightweight migrations for databases created before the real-provider flow.
    cursor.execute("PRAGMA table_info(accounts)")
    account_columns = {row["name"] for row in cursor.fetchall()}
    if "last_history_id" not in account_columns:
        cursor.execute("ALTER TABLE accounts ADD COLUMN last_history_id TEXT")
    if "initial_sync_complete" not in account_columns:
        cursor.execute("ALTER TABLE accounts ADD COLUMN initial_sync_complete INTEGER DEFAULT 0")

    cursor.execute("PRAGMA table_info(emails)")
    email_columns = {row["name"] for row in cursor.fetchall()}
    if "ai_verdict" not in email_columns:
        cursor.execute("ALTER TABLE emails ADD COLUMN ai_verdict TEXT DEFAULT 'UNKNOWN'")
    if "ai_score" not in email_columns:
        cursor.execute("ALTER TABLE emails ADD COLUMN ai_score INTEGER DEFAULT 0")
    if "ai_reason" not in email_columns:
        cursor.execute("ALTER TABLE emails ADD COLUMN ai_reason TEXT")
    if "received_ts" not in email_columns:
        cursor.execute("ALTER TABLE emails ADD COLUMN received_ts INTEGER DEFAULT 0")

    cursor.execute("SELECT id, date FROM emails WHERE COALESCE(received_ts, 0) = 0")
    for row in cursor.fetchall():
        received_ts = _coerce_received_ts(date_value=row["date"])
        if received_ts:
            cursor.execute("UPDATE emails SET received_ts = ? WHERE id = ?", (received_ts, row["id"]))

    cursor.execute("""
        SELECT id, body_html FROM emails
        WHERE COALESCE(body_plain, '') = ''
          AND COALESCE(body_html, '') != ''
    """)
    for row in cursor.fetchall():
        text = html_to_text(row["body_html"])
        if text:
            cursor.execute("UPDATE emails SET body_plain = ? WHERE id = ?", (text, row["id"]))

    # The dedicated client must never surface old mock/demo accounts.
    cursor.execute("DELETE FROM accounts WHERE LOWER(provider) NOT IN ('gmail', 'outlook')")
    cursor.execute("""
        DELETE FROM emails
        WHERE account_id NOT IN (SELECT id FROM accounts)
           OR id LIKE 'mock_%'
           OR id LIKE 'demo-%'
    """)
    conn.commit()
    conn.close()
    logger.info("Database initialized successfully.")


def add_account(email: str, provider: str, status: str = "linked", token_data: dict = None) -> str:
    """Adds a new email account to manage."""
    provider = (provider or "").lower()
    if provider not in ("gmail", "outlook"):
        raise ValueError("Only Gmail and Outlook accounts are supported in this client.")

    conn = get_db_connection()
    cursor = conn.cursor()
    account_id = f"acc_{str(uuid.uuid4())[:8]}"
    token_str = json.dumps(token_data) if token_data else None

    try:
        cursor.execute(
            """
            INSERT INTO accounts (id, email, provider, status, token_data, initial_sync_complete)
            VALUES (?, ?, ?, ?, ?, 0)
            """,
            (account_id, email, provider, status, token_str)
        )
        conn.commit()
        logger.info(f"Account {email} ({provider}) added with ID: {account_id}")
        return account_id
    except sqlite3.IntegrityError:
        # Account already exists, fetch existing ID
        cursor.execute("SELECT id FROM accounts WHERE email = ?", (email,))
        row = cursor.fetchone()
        if row:
            account_id = row["id"]
            # Update token if provided
            if token_str:
                cursor.execute("UPDATE accounts SET token_data = ?, status = ? WHERE id = ?", (token_str, status, account_id))
                conn.commit()
            return account_id
    finally:
        conn.close()
    return account_id


def delete_account(account_id: str):
    """Deletes an account and its associated emails."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("PRAGMA foreign_keys = ON;")
    try:
        cursor.execute("DELETE FROM accounts WHERE id = ?", (account_id,))
        conn.commit()
        logger.info(f"Account {account_id} deleted successfully.")
    finally:
        conn.close()


def get_accounts() -> List[Dict[str, Any]]:
    """Retrieves all linked email accounts."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, email, provider, status, last_history_id, initial_sync_complete
        FROM accounts
        WHERE LOWER(provider) IN ('gmail', 'outlook')
        ORDER BY email COLLATE NOCASE
    """)
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_account_by_email(email: str) -> Optional[Dict[str, Any]]:
    """Retrieves account details by email address."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM accounts WHERE email = ?", (email,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


def get_account_by_id(account_id: str) -> Optional[Dict[str, Any]]:
    """Retrieves account details by local account ID."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM accounts WHERE id = ?", (account_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


def update_account_sync_state(account_id: str, last_history_id: str = None, initial_sync_complete: bool = None):
    """Persists Gmail sync cursor metadata for an account."""
    updates = []
    params = []
    if last_history_id is not None:
        updates.append("last_history_id = ?")
        params.append(str(last_history_id))
    if initial_sync_complete is not None:
        updates.append("initial_sync_complete = ?")
        params.append(1 if initial_sync_complete else 0)

    if not updates:
        return

    params.append(account_id)
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(f"UPDATE accounts SET {', '.join(updates)} WHERE id = ?", params)
    conn.commit()
    conn.close()


def route_folder(verdict: str, subject: str, body: str) -> str:
    """Categorizes an email into a standard folder based on verdict and keywords."""
    if verdict == "MALICIOUS":
        return "malicious"
    if verdict == "SUSPICIOUS":
        return "suspicious"
    text = f"{subject or ''} {body or ''}".lower()
    
    # Marketing keywords
    marketing_keywords = ["deal", "discount", "sale", "newsletter", "offer", "coupon", "marketing", "subscribe", "promo"]
    if any(kw in text for kw in marketing_keywords):
        return "marketing"
        
    return "inbox"


def save_email(
    email_data: dict,
    account_id: str,
    verdict: str,
    score: int,
    ticket_id: str,
    gemma_advisory: str,
    ai_analysis: dict = None,
    folder: str = None
) -> str:
    """Saves or updates a triaged email inside the database."""
    conn = get_db_connection()
    cursor = conn.cursor()

    subject = email_data.get("subject", "")
    body_html = email_data.get("body_html", "")
    body_plain = email_data.get("body_plain", "") or html_to_text(body_html) or email_data.get("snippet", "")
    ai_analysis = ai_analysis or {}
    ai_verdict = ai_analysis.get("verdict", "UNKNOWN")
    ai_score = int(ai_analysis.get("confidence", 0) or 0)
    ai_reason = ai_analysis.get("reason", "")
    
    if not folder:
        folder = route_folder(verdict, subject, body_plain)

    msg_id = email_data.get("id")
    received_ts = _coerce_received_ts(email_data.get("received_ts"), email_data.get("date", ""))
    processed_at = datetime.now(timezone.utc).isoformat()

    try:
        cursor.execute("""
            INSERT INTO emails (
                id, account_id, sender, recipient, subject, date, received_ts, body_plain, body_html,
                snippet, folder, verdict, score, ai_verdict, ai_score, ai_reason,
                ticket_id, gemma_advisory, processed_at, is_read
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                received_ts = CASE
                    WHEN excluded.received_ts > 0 THEN excluded.received_ts
                    ELSE emails.received_ts
                END,
                sender = excluded.sender,
                recipient = excluded.recipient,
                subject = excluded.subject,
                date = excluded.date,
                body_plain = excluded.body_plain,
                body_html = excluded.body_html,
                snippet = excluded.snippet,
                folder = excluded.folder,
                verdict = excluded.verdict,
                score = excluded.score,
                ai_verdict = excluded.ai_verdict,
                ai_score = excluded.ai_score,
                ai_reason = excluded.ai_reason,
                ticket_id = excluded.ticket_id,
                gemma_advisory = excluded.gemma_advisory,
                processed_at = excluded.processed_at
        """, (
            msg_id,
            account_id,
            email_data.get("from", ""),
            email_data.get("to", ""),
            subject,
            email_data.get("date", ""),
            received_ts,
            body_plain,
            body_html,
            email_data.get("snippet", ""),
            folder,
            verdict,
            score,
            ai_verdict,
            ai_score,
            ai_reason,
            ticket_id,
            gemma_advisory,
            processed_at,
            0  # is_read default to unread (0)
        ))
        _prune_account_emails_with_cursor(cursor, account_id)
        conn.commit()
        logger.info(f"Email {msg_id} saved to folder '{folder}' with verdict {verdict}")
    except Exception as e:
        logger.error(f"Failed to save email {msg_id}: {e}", exc_info=True)
    finally:
        conn.close()
    return folder


def cache_email_metadata(email_data: dict, account_id: str, folder: str = "inbox") -> str:
    """
    Save an email immediately before slow enrichment/LLM triage.
    Existing analyzed rows are left intact so verdicts are not overwritten.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    msg_id = email_data.get("id")
    if not msg_id:
        conn.close()
        return folder
    received_ts = _coerce_received_ts(email_data.get("received_ts"), email_data.get("date", ""))
    body_html = email_data.get("body_html", "")
    body_plain = email_data.get("body_plain", "") or html_to_text(body_html) or email_data.get("snippet", "")

    try:
        cursor.execute("""
            INSERT INTO emails (
                id, account_id, sender, recipient, subject, date, received_ts, body_plain, body_html,
                snippet, folder, verdict, score, ai_verdict, ai_score, ai_reason,
                ticket_id, gemma_advisory, processed_at, is_read
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'PENDING', 0, 'PENDING', 0,
                      'Queued for SOAR analysis', '', '', NULL, 0)
            ON CONFLICT(id) DO UPDATE SET
                received_ts = CASE
                    WHEN excluded.received_ts > 0 THEN excluded.received_ts
                    ELSE emails.received_ts
                END,
                sender = excluded.sender,
                recipient = excluded.recipient,
                subject = excluded.subject,
                date = excluded.date,
                body_plain = excluded.body_plain,
                body_html = excluded.body_html,
                snippet = excluded.snippet
        """, (
            msg_id,
            account_id,
            email_data.get("from", ""),
            email_data.get("to", ""),
            email_data.get("subject", ""),
            email_data.get("date", ""),
            received_ts,
            body_plain,
            body_html,
            email_data.get("snippet", ""),
            folder,
        ))
        _prune_account_emails_with_cursor(cursor, account_id)
        conn.commit()
    except Exception as e:
        logger.error(f"Failed to cache email {msg_id}: {e}", exc_info=True)
    finally:
        conn.close()
    return folder


def update_email_content(email_id: str, email_data: dict):
    """Update only message content/metadata after on-demand body hydration."""
    body_html = email_data.get("body_html", "")
    body_plain = email_data.get("body_plain", "") or html_to_text(body_html) or email_data.get("snippet", "")
    received_ts = _coerce_received_ts(email_data.get("received_ts"), email_data.get("date", ""))

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE emails
        SET sender = COALESCE(NULLIF(?, ''), sender),
            recipient = COALESCE(NULLIF(?, ''), recipient),
            subject = COALESCE(NULLIF(?, ''), subject),
            date = COALESCE(NULLIF(?, ''), date),
            received_ts = CASE WHEN ? > 0 THEN ? ELSE received_ts END,
            body_plain = ?,
            body_html = ?,
            snippet = COALESCE(NULLIF(?, ''), snippet)
        WHERE id = ?
    """, (
        email_data.get("from", ""),
        email_data.get("to", ""),
        email_data.get("subject", ""),
        email_data.get("date", ""),
        received_ts,
        received_ts,
        body_plain,
        body_html,
        email_data.get("snippet", ""),
        email_id,
    ))
    conn.commit()
    conn.close()


def get_emails(account_id: str = None, folder: str = None, limit: int = 25) -> List[Dict[str, Any]]:
    """Retrieves emails filtered by account and/or folder."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    query = "SELECT id, account_id, sender, recipient, subject, date, received_ts, snippet, folder, verdict, score, ai_verdict, ai_score, ai_reason, is_read, processed_at FROM emails"
    params = []
    
    conditions = []
    if account_id:
        conditions.append("account_id = ?")
        params.append(account_id)
    if folder == "malicious":
        conditions.append("verdict = ?")
        params.append("MALICIOUS")
    elif folder == "suspicious":
        conditions.append("verdict = ?")
        params.append("SUSPICIOUS")
    elif folder == "marketing":
        conditions.append("folder = ?")
        params.append("marketing")
    elif folder and folder != "inbox":
        conditions.append("folder = ?")
        params.append(folder)
        
    if conditions:
        query += " WHERE " + " AND ".join(conditions)
        
    query += " ORDER BY COALESCE(received_ts, 0) DESC, COALESCE(date, '') DESC, COALESCE(processed_at, '') DESC LIMIT ?"
    params.append(max(1, min(int(limit or 25), 100)))
    
    cursor.execute(query, params)
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_email_details(email_id: str) -> Optional[Dict[str, Any]]:
    """Retrieves full body and ticket metadata for a specific email."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM emails WHERE id = ?", (email_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


def mark_email_as_read(email_id: str):
    """Marks an email as read in the database."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE emails SET is_read = 1 WHERE id = ?", (email_id,))
    conn.commit()
    conn.close()


def load_processed_emails_for_account(account_id: str) -> set:
    """Returns message IDs that already completed SOAR analysis."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id FROM emails
        WHERE account_id = ?
          AND ticket_id IS NOT NULL
          AND ticket_id != ''
          AND verdict != 'PENDING'
    """, (account_id,))
    rows = cursor.fetchall()
    conn.close()
    return set(r["id"] for r in rows)


def load_cached_emails_for_account(account_id: str) -> set:
    """Returns every locally cached message ID, including pending rows."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM emails WHERE account_id = ?", (account_id,))
    rows = cursor.fetchall()
    conn.close()
    return set(r["id"] for r in rows)


# Initialize DB on load
init_db()
