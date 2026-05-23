"""
Automated Response Actions Module
===================================
Executes response actions based on triage verdict:
1. Email quarantine via Gmail API (real)
2. URL/Domain blocklist update (mock proxy block)
3. Slack/webhook notification (optional)

Person 4 Role: Automated response
MITRE ATT&CK: Response to T1566 - Phishing
"""

import os
import json
import logging
import requests
from datetime import datetime, timezone
from typing import Dict, Any

from config import (
    BLOCKLIST_FILE, QUARANTINE_LOG, SLACK_WEBHOOK_URL
)

logger = logging.getLogger(__name__)


def execute_response(
    gmail_service,
    email_data: dict,
    iocs: dict,
    triage_result: dict,
    outlook_service=None
) -> Dict[str, Any]:
    """
    Execute all response actions based on triage verdict.
    Returns a dict of all actions taken and their results.
    """
    verdict = triage_result.get("verdict", "CLEAN")
    actions_taken = []
    response_log  = {
        "timestamp":    datetime.now(timezone.utc).isoformat(),
        "email_id":     email_data.get("id", ""),
        "subject":      email_data.get("subject", ""),
        "sender":       email_data.get("from", ""),
        "verdict":      verdict,
        "actions":      [],
        "success":      True,
    }

    logger.info(f"Executing response actions for verdict: {verdict}")

    # ── Action 1: Quarantine Email ────────────────────────────
    if verdict in ("MALICIOUS", "SUSPICIOUS"):
        quarantine_result = quarantine_email(gmail_service, email_data, outlook_service)
        response_log["actions"].append(quarantine_result)
        actions_taken.append("email_quarantined")
        logger.info(f"Quarantine result: {quarantine_result['status']}")

    # ── Action 2: Block IoCs ──────────────────────────────────
    if verdict == "MALICIOUS":
        block_result = block_iocs(iocs)
        response_log["actions"].append(block_result)
        actions_taken.append("iocs_blocked")

    # ── Action 3: Slack Notification ─────────────────────────
    slack_result = send_slack_notification(email_data, triage_result)
    response_log["actions"].append(slack_result)

    # ── Save quarantine log ───────────────────────────────────
    _append_quarantine_log(response_log)

    response_log["actions_taken"]  = actions_taken
    response_log["total_actions"]  = len(actions_taken)

    return response_log


def quarantine_email(gmail_service, email_data: dict, outlook_service=None) -> Dict[str, Any]:
    """
    Quarantine email using Gmail or Microsoft Graph API.
    Falls back to mock if service is unavailable.
    """
    msg_id  = email_data.get("id", "")
    subject = email_data.get("subject", "")

    action = {
        "action":    "email_quarantine",
        "target":    f"Email: {subject[:50]}",
        "msg_id":    msg_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    # Check if this is an Outlook email
    is_outlook = msg_id.startswith("outlook-") or outlook_service is not None or "no-reply@office365-verify.com" in email_data.get("from", "")

    if is_outlook:
        try:
            from outlook_connector import quarantine_outlook_email
            result = quarantine_outlook_email(msg_id)
            action["status"]  = "SUCCESS" if result.get("success") else "FAILED"
            action["details"] = result.get("actions", [])
            action["mode"]    = "real_outlook" if outlook_service is not None else "outlook"
            logger.info(f"Outlook quarantine: {action['status']}")
        except Exception as e:
            logger.error(f"Outlook quarantine failed: {e}")
            action["status"]  = "FAILED"
            action["error"]   = str(e)
            action["mode"]    = "outlook"
    elif gmail_service and msg_id:
        try:
            from gmail_connector import quarantine_email as gmail_quarantine
            result = gmail_quarantine(gmail_service, msg_id)
            action["status"]  = "SUCCESS" if result["success"] else "FAILED"
            action["details"] = result.get("actions", [])
            action["mode"]    = "real_gmail"
            logger.info(f"Real Gmail quarantine: {action['status']}")
        except Exception as e:
            logger.error(f"Gmail quarantine failed: {e}")
            action["status"]  = "FAILED"
            action["error"]   = str(e)
            action["mode"]    = "real_gmail"
    else:
        # Mock quarantine (no Gmail service)
        action["status"]  = "SUCCESS"
        action["details"] = [
            "MOCK: Email marked as quarantined",
            "MOCK: Label 'SOAR-Quarantined' applied",
            "MOCK: Moved to trash"
        ]
        action["mode"] = "mock"
        logger.info("Mock quarantine executed (no active mail services)")

    return action


def block_iocs(iocs: dict) -> Dict[str, Any]:
    """
    Block malicious IoCs by adding to proxy blocklist file.
    In production, this would call a firewall/proxy API.
    """
    blocked_items = []
    action = {
        "action":    "ioc_block",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "mode":      "mock_proxy",
    }

    # Collect IoCs to block
    items_to_block = []
    items_to_block.extend(iocs.get("urls", [])[:10])
    items_to_block.extend(iocs.get("domains", [])[:5])

    if not items_to_block:
        action["status"]  = "SKIPPED"
        action["details"] = ["No IoCs to block"]
        return action

    try:
        # Ensure blocklist file exists
        os.makedirs(os.path.dirname(BLOCKLIST_FILE), exist_ok=True) if os.path.dirname(BLOCKLIST_FILE) else None

        # Load existing blocklist
        existing = set()
        if os.path.exists(BLOCKLIST_FILE):
            with open(BLOCKLIST_FILE, "r") as f:
                existing = set(line.strip() for line in f if line.strip())

        # Append new IoCs
        new_items = [i for i in items_to_block if i not in existing]
        if new_items:
            with open(BLOCKLIST_FILE, "a") as f:
                timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                for item in new_items:
                    f.write(f"{item}  # SOAR-blocked {timestamp}\n")
                    blocked_items.append(item)

        action["status"]       = "SUCCESS"
        action["blocked"]      = blocked_items
        action["total_blocked"] = len(blocked_items)
        action["blocklist_file"] = BLOCKLIST_FILE
        action["details"] = [
            f"MOCK PROXY: {len(blocked_items)} IoCs added to blocklist",
            f"File: {BLOCKLIST_FILE}",
            "In production: would call Proxy/Firewall API to enforce block"
        ]
        logger.info(f"Blocked {len(blocked_items)} IoCs in {BLOCKLIST_FILE}")

    except Exception as e:
        logger.error(f"Block IoCs failed: {e}")
        action["status"] = "FAILED"
        action["error"]  = str(e)

    return action


def send_slack_notification(email_data: dict, triage_result: dict) -> Dict[str, Any]:
    """
    Send alert notification via Slack webhook.
    Falls back to console log if webhook not configured.
    """
    verdict = triage_result.get("verdict", "UNKNOWN")
    score   = triage_result.get("score", 0)
    subject = email_data.get("subject", "Unknown Subject")
    sender  = email_data.get("from", "Unknown Sender")

    # Emoji based on verdict
    emoji_map = {"MALICIOUS": "🔴", "SUSPICIOUS": "🟡", "CLEAN": "🟢"}
    emoji = emoji_map.get(verdict, "⚪")

    message = {
        "text": f"{emoji} *SOAR Phishing Alert* — {verdict}",
        "attachments": [{
            "color": "#ef4444" if verdict == "MALICIOUS" else "#f59e0b" if verdict == "SUSPICIOUS" else "#10b981",
            "fields": [
                {"title": "Verdict",  "value": f"{emoji} {verdict} (Score: {score}/100)", "short": True},
                {"title": "Subject",  "value": subject[:80], "short": True},
                {"title": "Sender",   "value": sender[:80],  "short": True},
                {"title": "Action",   "value": triage_result.get("action", "N/A"), "short": True},
            ],
            "footer": "SOAR Phishing Playbook",
            "ts": int(datetime.now(timezone.utc).timestamp())
        }]
    }

    action = {
        "action":    "slack_notification",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    if SLACK_WEBHOOK_URL:
        try:
            resp = requests.post(SLACK_WEBHOOK_URL, json=message, timeout=10)
            action["status"]  = "SUCCESS" if resp.status_code == 200 else "FAILED"
            action["details"] = [f"Webhook HTTP {resp.status_code}"]
            action["mode"]    = "real_slack"
        except Exception as e:
            action["status"]  = "FAILED"
            action["error"]   = str(e)
            action["mode"]    = "real_slack"
    else:
        # Log to console as fallback
        logger.info(f"\n{'='*60}\nSLACK NOTIFICATION (mock):\n{emoji} SOAR Alert: {verdict}\nSubject: {subject}\nSender: {sender}\nScore: {score}/100\n{'='*60}")
        action["status"]  = "SUCCESS"
        action["details"] = ["Notification logged to console (add SLACK_WEBHOOK_URL to .env for real Slack alerts)"]
        action["mode"]    = "console_log"

    return action


def _append_quarantine_log(entry: dict):
    """Append response log entry to quarantine log JSON file."""
    try:
        log_data = []
        if os.path.exists(QUARANTINE_LOG):
            with open(QUARANTINE_LOG, "r") as f:
                log_data = json.load(f)
        log_data.append(entry)
        with open(QUARANTINE_LOG, "w") as f:
            json.dump(log_data, f, indent=2)
        logger.info(f"Quarantine log updated: {QUARANTINE_LOG}")
    except Exception as e:
        logger.error(f"Failed to update quarantine log: {e}")
