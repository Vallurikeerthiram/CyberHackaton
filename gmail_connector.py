"""
Gmail Connector Module
======================
Authenticates via OAuth 2.0 and fetches/manages phishing emails
from a real Gmail inbox.

Person 1 Role: Email ingestion via Gmail API
MITRE ATT&CK: T1566 - Phishing (initial vector)
"""

import os
import base64
import hashlib
import json
import logging
import shutil
from typing import Optional, List, Tuple

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

from config import (
    CREDENTIALS_FILE, TOKEN_FILE, GMAIL_SCOPES,
    GMAIL_LABEL, QUARANTINE_LABEL
)
from email_parser import html_to_text

logger = logging.getLogger(__name__)


def _token_file_for(account_email: str = None) -> str:
    """Return the token path used for a Gmail account."""
    if account_email:
        return os.path.join(os.path.dirname(TOKEN_FILE), f"token_gmail_{account_email}.json")
    return TOKEN_FILE


def get_gmail_service(account_email: str = None):
    """
    Authenticate with Gmail API using OAuth 2.0.
    Opens browser on first run, uses cached token on subsequent runs.
    Returns authenticated Gmail service object.
    """
    creds = None
    token_file = _token_file_for(account_email)

    # Load cached token if it exists
    if os.path.exists(token_file):
        creds = Credentials.from_authorized_user_file(token_file, GMAIL_SCOPES)

    # Refresh or re-authenticate if needed
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            logger.info("Refreshing expired OAuth token...")
            creds.refresh(Request())
        else:
            logger.info("Starting OAuth flow — browser will open for login...")
            flow = InstalledAppFlow.from_client_secrets_file(
                CREDENTIALS_FILE, GMAIL_SCOPES
            )
            creds = flow.run_local_server(port=0)

        # Save token for future runs
        with open(token_file, "w") as tf:
            tf.write(creds.to_json())
        logger.info(f"Token saved to {token_file}")

    service = build("gmail", "v1", credentials=creds)
    logger.info("Gmail service authenticated successfully")
    return service


def get_gmail_profile(service) -> dict:
    """Return the authenticated Gmail profile email and current history cursor."""
    profile = service.users().getProfile(userId="me").execute()
    return {
        "email": profile.get("emailAddress", ""),
        "history_id": profile.get("historyId"),
        "messages_total": profile.get("messagesTotal"),
        "threads_total": profile.get("threadsTotal"),
    }


def authenticate_gmail_account() -> Tuple[object, dict]:
    """
    Run Gmail OAuth, detect the real signed-in Gmail address, and persist a
    per-account token file so the worker can poll without asking again.
    """
    service = get_gmail_service()
    profile = get_gmail_profile(service)
    email = profile.get("email")
    if not email:
        raise RuntimeError("Gmail OAuth succeeded but no profile email was returned.")

    default_token = _token_file_for()
    account_token = _token_file_for(email)
    if os.path.exists(default_token) and os.path.abspath(default_token) != os.path.abspath(account_token):
        shutil.copyfile(default_token, account_token)

    account_service = get_gmail_service(email)
    profile = get_gmail_profile(account_service)
    return account_service, profile


def list_inbox_message_ids(service, query: str = None, page_size: int = 100) -> List[str]:
    """List all Gmail message IDs currently carrying the INBOX label."""
    message_ids = []
    page_token = None

    while True:
        kwargs = {
            "userId": "me",
            "labelIds": ["INBOX"],
            "maxResults": page_size,
        }
        if query:
            kwargs["q"] = query
        if page_token:
            kwargs["pageToken"] = page_token

        result = service.users().messages().list(**kwargs).execute()
        message_ids.extend(m["id"] for m in result.get("messages", []))
        page_token = result.get("nextPageToken")
        if not page_token:
            break

    return message_ids


def list_new_inbox_message_ids_since(service, start_history_id: str) -> Tuple[List[str], Optional[str]]:
    """
    Return message IDs added to INBOX since the stored Gmail history cursor.
    Raises HttpError when Gmail history is too old so callers can full-resync.
    """
    if not start_history_id:
        return [], None

    seen = set()
    latest_history_id = None
    page_token = None

    while True:
        kwargs = {
            "userId": "me",
            "startHistoryId": str(start_history_id),
            "labelId": "INBOX",
            "historyTypes": ["messageAdded"],
            "maxResults": 100,
        }
        if page_token:
            kwargs["pageToken"] = page_token

        result = service.users().history().list(**kwargs).execute()
        latest_history_id = result.get("historyId") or latest_history_id

        for history in result.get("history", []):
            latest_history_id = history.get("id") or latest_history_id
            for added in history.get("messagesAdded", []):
                message = added.get("message", {})
                if message.get("id") and "INBOX" in message.get("labelIds", []):
                    seen.add(message["id"])

        page_token = result.get("nextPageToken")
        if not page_token:
            break

    return list(seen), latest_history_id


def fetch_latest_phishing_email(service, label: str = GMAIL_LABEL) -> Optional[dict]:
    """
    Fetch the most recent unread email from the specified label/folder.
    Returns a parsed email dict or None if no emails found.
    """
    try:
        # Search for unread emails - can filter by label or subject
        query = "is:unread"
        if label != "INBOX":
            query += f" label:{label}"

        result = service.users().messages().list(
            userId="me",
            labelIds=["INBOX"],
            q=query,
            maxResults=1
        ).execute()

        messages = result.get("messages", [])
        if not messages:
            logger.warning("No unread emails found in inbox")
            return None

        msg_id = messages[0]["id"]
        logger.info(f"Found email with ID: {msg_id}")
        return fetch_email_by_id(service, msg_id)

    except HttpError as e:
        logger.error(f"Gmail API error: {e}")
        return None


def fetch_email_by_id(service, msg_id: str) -> Optional[dict]:
    """
    Fetch full email content by message ID.
    Returns structured dict with headers, body, attachments.
    """
    try:
        msg = service.users().messages().get(
            userId="me",
            id=msg_id,
            format="full"
        ).execute()

        parsed = _parse_gmail_message(msg)
        _hydrate_gmail_attachment_hashes(service, msg_id, parsed)
        return parsed

    except HttpError as e:
        logger.error(f"Failed to fetch email {msg_id}: {e}")
        return None


def fetch_email_metadata_by_id(service, msg_id: str) -> Optional[dict]:
    """Fetch lightweight Gmail metadata for fast mailbox display."""
    try:
        msg = service.users().messages().get(
            userId="me",
            id=msg_id,
            format="metadata",
            metadataHeaders=["From", "To", "Subject", "Date", "Reply-To", "Return-Path"],
        ).execute()
        return _parse_gmail_message(msg)
    except HttpError as e:
        logger.error(f"Failed to fetch Gmail metadata {msg_id}: {e}")
        return None


def _parse_gmail_message(msg: dict) -> dict:
    """
    Parse a raw Gmail API message into a structured dict.
    Extracts: headers, body (plain/html), attachments.
    """
    headers = {}
    for h in msg.get("payload", {}).get("headers", []):
        headers[h["name"].lower()] = h["value"]

    body_plain = ""
    body_html  = ""
    attachments = []

    def _decode_bytes(data: str) -> bytes:
        if not data:
            return b""
        padded = data + "=" * (-len(data) % 4)
        return base64.urlsafe_b64decode(padded)

    def _decode_body(data: str) -> str:
        return _decode_bytes(data).decode("utf-8", errors="replace")

    def _attach_hashes(att: dict, raw: bytes):
        if not raw:
            return
        att["size"] = len(raw)
        att["sha256"] = hashlib.sha256(raw).hexdigest()
        att["md5"] = hashlib.md5(raw).hexdigest()

    def _extract_parts(parts):
        nonlocal body_plain, body_html
        for part in parts:
            mime = part.get("mimeType", "")
            filename = part.get("filename", "")
            body_data = part.get("body", {})

            if mime == "text/plain" and not filename:
                data = body_data.get("data", "")
                if data:
                    body_plain += _decode_body(data)

            elif mime == "text/html" and not filename:
                data = body_data.get("data", "")
                if data:
                    body_html += _decode_body(data)

            elif filename:
                att = {
                    "filename": filename,
                    "mimeType": mime,
                    "size": body_data.get("size", 0),
                    "attachmentId": body_data.get("attachmentId", ""),
                    "messageId": msg.get("id", "")
                }
                data = body_data.get("data", "")
                if data:
                    _attach_hashes(att, _decode_bytes(data))
                attachments.append(att)

            # Recurse into multipart
            if "parts" in part:
                _extract_parts(part["parts"])

    payload = msg.get("payload", {})
    if "parts" in payload:
        _extract_parts(payload["parts"])
    else:
        # Single-part message
        data = payload.get("body", {}).get("data", "")
        if data:
            decoded = _decode_body(data)
            if payload.get("mimeType") == "text/html":
                body_html = decoded
            else:
                body_plain = decoded

    if not body_plain and body_html:
        body_plain = html_to_text(body_html)
    if not body_plain:
        body_plain = msg.get("snippet", "")

    return {
        "id":           msg.get("id"),
        "thread_id":    msg.get("threadId"),
        "received_ts":  int(msg.get("internalDate", "0") or 0),
        "snippet":      msg.get("snippet", ""),
        "from":         headers.get("from", ""),
        "to":           headers.get("to", ""),
        "subject":      headers.get("subject", ""),
        "date":         headers.get("date", ""),
        "reply_to":     headers.get("reply-to", ""),
        "return_path":  headers.get("return-path", ""),
        "received":     headers.get("received", ""),
        "body_plain":   body_plain,
        "body_html":    body_html,
        "attachments":  attachments,
        "raw_headers":  headers,
    }


def _hydrate_gmail_attachment_hashes(service, msg_id: str, parsed: dict):
    """Fetch Gmail attachment bytes only long enough to hash them for VT lookup."""
    for att in parsed.get("attachments", []):
        if att.get("sha256") or not att.get("attachmentId"):
            continue
        try:
            data = service.users().messages().attachments().get(
                userId="me",
                messageId=msg_id,
                id=att["attachmentId"],
            ).execute().get("data", "")
            if not data:
                continue
            padded = data + "=" * (-len(data) % 4)
            raw = base64.urlsafe_b64decode(padded)
            att["size"] = len(raw)
            att["sha256"] = hashlib.sha256(raw).hexdigest()
            att["md5"] = hashlib.md5(raw).hexdigest()
        except HttpError as e:
            logger.warning(f"Could not fetch Gmail attachment {att.get('filename')}: {e}")


def quarantine_email(service, msg_id: str) -> dict:
    """
    Quarantine an email by:
    1. Moving it to Trash
    2. Applying SOAR-Quarantined label
    3. Marking as read
    Returns result dict with status.
    """
    result = {"msg_id": msg_id, "actions": [], "success": False}
    try:
        # Ensure the quarantine label exists
        label_id = _get_or_create_label(service, QUARANTINE_LABEL)

        # Apply quarantine label + remove from INBOX + mark as read
        service.users().messages().modify(
            userId="me",
            id=msg_id,
            body={
                "addLabelIds": [label_id],
                "removeLabelIds": ["INBOX", "UNREAD"]
            }
        ).execute()
        result["actions"].append(f"Label '{QUARANTINE_LABEL}' applied")

        # Move to trash
        service.users().messages().trash(userId="me", id=msg_id).execute()
        result["actions"].append("Moved to Trash")

        result["success"] = True
        logger.info(f"Email {msg_id} quarantined successfully")

    except HttpError as e:
        logger.error(f"Failed to quarantine email {msg_id}: {e}")
        result["error"] = str(e)

    return result


def _get_or_create_label(service, label_name: str) -> str:
    """
    Get existing label ID or create a new one.
    Returns the label ID string.
    """
    labels = service.users().labels().list(userId="me").execute()
    for label in labels.get("labels", []):
        if label["name"] == label_name:
            return label["id"]

    # Create label if not found
    new_label = service.users().labels().create(
        userId="me",
        body={
            "name": label_name,
            "labelListVisibility": "labelShow",
            "messageListVisibility": "show",
            "color": {"backgroundColor": "#cc3a21", "textColor": "#ffffff"}
        }
    ).execute()
    logger.info(f"Created Gmail label: {label_name}")
    return new_label["id"]
