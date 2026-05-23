"""
SOAR Playbook Orchestrator
===========================
Main entry point — orchestrates the full phishing response pipeline.
Runs all 5 modules in sequence and tracks execution state.

Pipeline stages:
  1. Gmail ingestion
  2. IoC extraction
  3. Threat intel enrichment
  4. Triage + decision
  5. Response actions
  6. Report generation

Usage:
  python main.py              # Process latest inbox email
  python main.py --demo       # Run with built-in phishing demo email
  python main.py --email-id X # Process specific Gmail message ID
"""

import os
import sys
import time
import json
import logging
import argparse
import threading
import random
import uuid
from datetime import datetime, timezone
from typing import Optional

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S"
)
logger = logging.getLogger("SOAR")

# Shared state for web dashboard (thread-safe)
PLAYBOOK_STATE = {
    "running":     False,
    "stage":       "idle",
    "stages":      [],
    "result":      None,
    "started_at":  None,
    "elapsed":     0,
    "error":       None,
    "queue_size":  0,
    "queue_index": 0,
    "mode":        "idle",  # "idle" / "backfill" / "monitoring"
    "source":      "idle",  # "gmail" / "outlook" / "both"
}
STATE_LOCK = threading.Lock()
MONITOR_ACTIVE = False
MAIL_SYNC_LIMIT = 25


def update_state(stage: str, status: str, data: dict = None):
    """Update shared playbook state (thread-safe)."""
    with STATE_LOCK:
        PLAYBOOK_STATE["stage"] = stage
        entry = {
            "name":      stage,
            "status":    status,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data":      data or {}
        }
        # Update or append stage
        for existing in PLAYBOOK_STATE["stages"]:
            if existing["name"] == stage:
                existing.update(entry)
                return
        PLAYBOOK_STATE["stages"].append(entry)


def get_demo_email() -> dict:
    """Return a realistic phishing demo email for testing."""
    return {
        "id":          "demo-001",
        "thread_id":   "thread-demo-001",
        "snippet":     "Urgent: Your account has been compromised. Click here to verify.",
        "from":        "security-alert@paypaI-verify.tk",
        "to":          "victim@company.com",
        "subject":     "⚠️ URGENT: Your PayPal Account Has Been Suspended",
        "date":        datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S +0000"),
        "reply_to":    "support@totally-not-phishing.xyz",
        "return_path": "<bounce@spammer-server.ga>",
        "received":    "from unknown-host-123.xyz (45.33.32.156)",
        "body_plain":  """Dear Valued Customer,

We have detected unusual activity on your PayPal account.
Your account has been temporarily suspended for your security.

To restore access, please click here immediately:
http://paypaI-secure-login.tk/verify?token=abc123&user=victim

If you do not verify within 24 hours, your account will be PERMANENTLY CLOSED.

Also, please download and complete the attached verification form:
See attachment: account_verification_form.exe

Your account details:
- Account: victim@company.com
- Last login from: 185.220.101.5 (suspicious IP)
- Status: SUSPENDED

Click here to verify your identity: http://login.paypaI.com.phishing-site.xyz/restore

Act now to avoid losing access to your PayPal account!

Best regards,
PayPal Security Team
security@paypaI-verify.tk
""",
        "body_html":   """<html><body>
<p>Dear Valued Customer,</p>
<p>We have detected unusual activity. <a href="http://paypaI-secure-login.tk/verify?token=abc123">Click here to verify your account</a></p>
<p>Alternatively: <a href="http://login.paypaI.com.phishing-site.xyz/restore">http://www.paypal.com/restore</a></p>
<p>Download form: <a href="http://paypaI-secure-login.tk/form.exe">account_verification_form.exe</a></p>
</body></html>""",
        "attachments": [
            {
                "filename":     "account_verification_form.exe",
                "mimeType":     "application/x-msdownload",
                "size":         102400,
                "attachmentId": "demo-att-001",
                "messageId":    "demo-001"
            }
        ],
        "raw_headers": {
            "from":         "security-alert@paypaI-verify.tk",
            "to":           "victim@company.com",
            "subject":      "⚠️ URGENT: Your PayPal Account Has Been Suspended",
            "reply-to":     "support@totally-not-phishing.xyz",
            "return-path":  "<bounce@spammer-server.ga>",
            "received":     "from unknown-host-123.xyz (45.33.32.156)",
        }
    }


def run_playbook(
    email_data: Optional[dict] = None,
    gmail_service=None,
    email_id: Optional[str] = None,
    use_demo: bool = False,
    outlook_service=None,
    is_queue_run: bool = False
) -> dict:
    """
    Execute the full SOAR phishing response playbook.
    Returns complete result dict.
    """
    start_time = time.time()

    if not is_queue_run:
        with STATE_LOCK:
            PLAYBOOK_STATE.update({
                "running":    True,
                "stage":      "starting",
                "stages":     [],
                "result":     None,
                "started_at": datetime.now(timezone.utc).isoformat(),
                "elapsed":    0,
                "error":      None,
            })

    try:
        # ═══════════════════════════════════════════════════════
        # STAGE 1: Email Ingestion
        # ═══════════════════════════════════════════════════════
        update_state("ingestion", "running")
        logger.info("=" * 60)
        logger.info("SOAR PHISHING PLAYBOOK — STARTING")
        logger.info("=" * 60)

        if use_demo:
            logger.info("Using demo phishing email")
            email_data = get_demo_email()
        elif email_data is None and gmail_service:
            logger.info("Fetching latest email from Gmail...")
            from gmail_connector import fetch_latest_phishing_email
            email_data = fetch_latest_phishing_email(gmail_service)
        elif email_data is None and email_id and gmail_service:
            from gmail_connector import fetch_email_by_id
            email_data = fetch_email_by_id(gmail_service, email_id)

        if not email_data:
            raise ValueError("No email to process — use --demo flag or check Gmail connection")

        update_state("ingestion", "complete", {
            "subject": email_data.get("subject", ""),
            "from":    email_data.get("from", ""),
            "has_attachments": len(email_data.get("attachments", [])) > 0
        })
        logger.info(f"Email ingested: '{email_data.get('subject', 'No subject')}'")

        # ═══════════════════════════════════════════════════════
        # STAGE 2: IoC Extraction
        # ═══════════════════════════════════════════════════════
        update_state("extraction", "running")
        logger.info("Stage 2: Extracting IoCs...")

        from email_parser import extract_iocs
        iocs = extract_iocs(email_data)

        update_state("extraction", "complete", {
            "urls":        len(iocs.get("urls", [])),
            "domains":     len(iocs.get("domains", [])),
            "attachments": len(iocs.get("attachments", [])),
            "keywords":    len(iocs.get("keywords_found", [])),
            "risks":       len(iocs.get("risk_indicators", [])),
        })
        logger.info(f"IoCs extracted: {len(iocs.get('urls',[]))} URLs, {len(iocs.get('domains',[]))} domains")

        # ═══════════════════════════════════════════════════════
        # STAGE 3: Threat Intel Enrichment
        # ═══════════════════════════════════════════════════════
        update_state("enrichment", "running")
        logger.info("Stage 3: Enriching IoCs via threat intel APIs...")

        from threat_intel import enrich_iocs
        enrichment = enrich_iocs(iocs)

        update_state("enrichment", "complete", {
            "total_checked": enrichment["summary"]["total_checked"],
            "malicious":     enrichment["summary"]["malicious"],
            "suspicious":    enrichment["summary"]["suspicious"],
            "clean":         enrichment["summary"]["clean"],
        })
        logger.info(f"Enrichment done: {enrichment['summary']['malicious']} malicious found")

        ai_analysis = {
            "verdict": "UNKNOWN",
            "confidence": 0,
            "reason": "Gemma security verdict was not run.",
            "source": "none",
        }
        try:
            update_state("gemma_verdict", "running")
            from gemma_advisor import classify_security_verdict
            ai_analysis = classify_security_verdict(
                sender=email_data.get("from", ""),
                subject=email_data.get("subject", ""),
                body=email_data.get("body_plain", "") or email_data.get("body_html", ""),
                urls=iocs.get("urls", []),
                sender_trust=enrichment.get("sender_trust") or {},
                enrichment_summary=enrichment.get("summary") or {},
            )
            update_state("gemma_verdict", "complete", ai_analysis)
            logger.info(
                f"Gemma security verdict: {ai_analysis.get('verdict')} "
                f"({ai_analysis.get('confidence', 0)}/100)"
            )
        except Exception as e:
            update_state("gemma_verdict", "error", {"error": str(e)})
            logger.error(f"Gemma security verdict failed: {e}")

        # ═══════════════════════════════════════════════════════
        # STAGE 4: Triage
        # ═══════════════════════════════════════════════════════
        update_state("triage", "running")
        logger.info("Stage 4: Running triage decision engine...")

        from triage import triage as run_triage
        triage_result = run_triage(iocs, enrichment, ai_analysis)

        update_state("triage", "complete", {
            "verdict": triage_result["verdict"],
            "score":   triage_result["score"],
            "action":  triage_result["action"],
        })
        logger.info(f"Triage verdict: {triage_result['verdict']} (score: {triage_result['score']}/100)")

        # ═══════════════════════════════════════════════════════
        # STAGE 5: Response Actions
        # ═══════════════════════════════════════════════════════
        update_state("response", "running")
        logger.info("Stage 5: Executing response actions...")

        from response_actions import execute_response
        response_log = execute_response(gmail_service, email_data, iocs, triage_result, outlook_service)

        update_state("response", "complete", {
            "actions_taken": response_log.get("actions_taken", []),
            "quarantined":   response_log.get("actions", [{}])[0].get("status") == "SUCCESS" if response_log.get("actions") else False,
        })
        logger.info(f"Response actions: {response_log.get('actions_taken', [])}")

        # ═══════════════════════════════════════════════════════
        # STAGE 6: Report Generation
        # ═══════════════════════════════════════════════════════
        elapsed = time.time() - start_time
        update_state("reporting", "running")
        logger.info("Stage 6: Generating incident report...")

        # Generate local Gemma AI security advisory warning
        gemma_advisory = ""
        if triage_result.get("verdict") in ("MALICIOUS", "SUSPICIOUS"):
            try:
                from gemma_advisor import generate_gemma_advisory
                gemma_advisory = generate_gemma_advisory(
                    sender=email_data.get("from", ""),
                    subject=email_data.get("subject", ""),
                    verdict=triage_result.get("verdict", ""),
                    urls=iocs.get("urls", []),
                    attachments=[a.get("filename", "") for a in iocs.get("attachments", [])]
                )
            except Exception as e:
                logger.error(f"Gemma advisory generation failed: {e}")
                gemma_advisory = "Could not generate Gemma AI warning advisory."

        from report_generator import generate_report
        report = generate_report(email_data, iocs, enrichment, triage_result, response_log, elapsed, gemma_advisory)

        update_state("reporting", "complete", {
            "ticket_id": report["ticket_id"],
            "html_path": report["html_path"],
        })

        # ═══════════════════════════════════════════════════════
        # DONE
        # ═══════════════════════════════════════════════════════
        elapsed = time.time() - start_time
        logger.info("=" * 60)
        logger.info(f"PLAYBOOK COMPLETE in {elapsed:.1f}s")
        logger.info(f"Verdict: {triage_result['verdict']} | Score: {triage_result['score']}/100")
        logger.info(f"Ticket: {report['ticket_id']}")
        logger.info(f"Report: {report['html_path']}")
        logger.info("=" * 60)

        final_result = {
            "success":      True,
            "ticket_id":    report["ticket_id"],
            "verdict":      triage_result["verdict"],
            "score":        triage_result["score"],
            "elapsed_sec":  round(elapsed, 2),
            "within_sla":   elapsed <= 60,
            "html_path":    report["html_path"],
            "ticket_path":  report["ticket_path"],
            "ticket":       report["ticket"],
            "iocs":         iocs,
            "enrichment":   enrichment,
            "triage":       triage_result,
            "response":     response_log,
            "gemma_advisory": gemma_advisory,
            "ai_analysis": ai_analysis
        }

        if not is_queue_run:
            with STATE_LOCK:
                PLAYBOOK_STATE["running"] = False
                PLAYBOOK_STATE["stage"]   = "complete"
                PLAYBOOK_STATE["result"]  = final_result
                PLAYBOOK_STATE["elapsed"] = round(elapsed, 2)

        return final_result

    except Exception as e:
        elapsed = time.time() - start_time
        logger.error(f"Playbook failed: {e}", exc_info=True)
        error_result = {
            "success":     False,
            "error":       str(e),
            "elapsed_sec": round(elapsed, 2),
        }
        if not is_queue_run:
            with STATE_LOCK:
                PLAYBOOK_STATE["running"] = False
                PLAYBOOK_STATE["stage"]   = "error"
                PLAYBOOK_STATE["error"]   = str(e)
                PLAYBOOK_STATE["result"]  = error_result
        return error_result


        return error_result


# ─────────────────────────────────────────────────────────────
# Database-Driven Multi-Account Polling Daemon
# ─────────────────────────────────────────────────────────────


def run_mail_monitoring_worker(gmail_service=None, outlook_service=None, source="real_mail"):
    """
    Run real Gmail/Outlook ingestion in a background thread.
    Gmail uses history cursors after the first full INBOX sync; Outlook uses
    Microsoft Graph Inbox pagination plus local duplicate tracking.
    """
    global MONITOR_ACTIVE
    if MONITOR_ACTIVE:
        logger.info("Background real-mail monitoring worker is already running.")
        return
    MONITOR_ACTIVE = True

    logger.info("Starting real Gmail/Outlook background mail monitoring worker...")

    import db_manager
    from googleapiclient.errors import HttpError
    from gmail_connector import (
        fetch_email_by_id,
        fetch_email_metadata_by_id,
        get_gmail_profile,
        get_gmail_service,
        list_inbox_message_ids,
        list_new_inbox_message_ids_since,
    )
    from outlook_connector import fetch_outlook_inbox_emails

    def _set_worker_state(mode, stage, running=False, queue_size=0, queue_index=0):
        with STATE_LOCK:
            PLAYBOOK_STATE.update({
                "running": running,
                "stage": stage,
                "mode": mode,
                "source": source,
                "queue_size": queue_size,
                "queue_index": queue_index,
            })

    def _process_email(account, parsed_email, gmail_service_for_msg=None, outlook_service_for_msg=None,
                       queue_index=0, queue_size=0, mode="monitoring"):
        provider = account.get("provider", "").lower()
        msg_id = parsed_email if isinstance(parsed_email, str) else parsed_email.get("id")
        if not msg_id or msg_id in db_manager.load_processed_emails_for_account(account["id"]):
            return None

        if isinstance(parsed_email, str) and provider == "gmail":
            parsed_email = fetch_email_by_id(gmail_service_for_msg, msg_id)
            if not parsed_email:
                logger.warning(f"Could not fetch full Gmail message {msg_id}; skipping triage.")
                return None

        if queue_size:
            _set_worker_state(mode, f"processing {queue_index}/{queue_size}", True, queue_size, queue_index)
        else:
            _set_worker_state(mode, "processing", True)

        logger.info(f"SOAR {provider} ingestion: processing {msg_id} for {account['email']}")
        result = run_playbook(
            email_data=parsed_email,
            gmail_service=gmail_service_for_msg,
            outlook_service=outlook_service_for_msg,
            is_queue_run=True,
        )

        if result.get("success"):
            db_manager.save_email(
                email_data=parsed_email,
                account_id=account["id"],
                verdict=result.get("verdict", "CLEAN"),
                score=result.get("score", 0),
                ticket_id=result.get("ticket_id", ""),
                gemma_advisory=result.get("gemma_advisory", ""),
                ai_analysis=result.get("ai_analysis", {}),
            )
            with STATE_LOCK:
                PLAYBOOK_STATE["result"] = result
        else:
            logger.error(f"SOAR processing failed for message {msg_id}: {result.get('error')}")

        return result

    with STATE_LOCK:
        PLAYBOOK_STATE.update({
            "running": False,
            "stage": "starting",
            "stages": [],
            "result": None,
            "error": None,
            "queue_size": 0,
            "queue_index": 0,
            "mode": "idle",
            "source": source,
            "started_at": datetime.now(timezone.utc).isoformat(),
        })

    try:
        accounts = db_manager.get_accounts()
        backfill_items = []
        gmail_services = {}

        for account in accounts:
            provider = account.get("provider", "").lower()
            try:
                processed_ids = db_manager.load_processed_emails_for_account(account["id"])
                if provider == "gmail":
                    service = gmail_service if gmail_service and len(accounts) == 1 else get_gmail_service(account["email"])
                    gmail_services[account["id"]] = service

                    if not account.get("initial_sync_complete"):
                        message_ids = list_inbox_message_ids(service)[:MAIL_SYNC_LIMIT]
                        for cache_idx, msg_id in enumerate(message_ids, 1):
                            if msg_id not in processed_ids:
                                _set_worker_state("backfill", f"caching inbox {cache_idx}/{len(message_ids)}", True, len(message_ids), cache_idx)
                                parsed = fetch_email_metadata_by_id(service, msg_id)
                                if parsed:
                                    db_manager.cache_email_metadata(parsed, account["id"], "inbox")
                                    backfill_items.append((account, msg_id, service, None))
                    elif not account.get("last_history_id"):
                        profile = get_gmail_profile(service)
                        db_manager.update_account_sync_state(account["id"], profile.get("history_id"), True)

                elif provider == "outlook":
                    if not account.get("initial_sync_complete"):
                        outlook_items = fetch_outlook_inbox_emails(account["email"], unread_only=False)[:MAIL_SYNC_LIMIT]
                        for cache_idx, parsed in enumerate(outlook_items, 1):
                            if parsed.get("id") not in processed_ids:
                                _set_worker_state("backfill", f"caching outlook {cache_idx}/{len(outlook_items)}", True, len(outlook_items), cache_idx)
                                db_manager.cache_email_metadata(parsed, account["id"], "inbox")
                                backfill_items.append((account, parsed, None, outlook_service or True))
            except Exception as e:
                logger.error(f"Initial sync setup failed for {account.get('email')} ({provider}): {e}")

        queue_size = len(backfill_items)
        _set_worker_state("backfill", "backfill", queue_size > 0, queue_size, 0)

        for idx, (account, parsed, gmail_svc, outlook_svc) in enumerate(backfill_items, 1):
            if not MONITOR_ACTIVE:
                break
            _process_email(account, parsed, gmail_svc, outlook_svc, idx, queue_size, "backfill")
            time.sleep(0.5)

        for account in db_manager.get_accounts():
            provider = account.get("provider", "").lower()
            try:
                if provider == "gmail":
                    service = gmail_services.get(account["id"]) or get_gmail_service(account["email"])
                    profile = get_gmail_profile(service)
                    db_manager.update_account_sync_state(account["id"], profile.get("history_id"), True)
                elif provider == "outlook":
                    db_manager.update_account_sync_state(
                        account["id"],
                        last_history_id=datetime.now(timezone.utc).isoformat(),
                        initial_sync_complete=True,
                    )
            except Exception as e:
                logger.error(f"Could not update sync cursor for {account.get('email')}: {e}")

        logger.info("Real-mail backfill complete. Switching to live monitoring.")
        _set_worker_state("monitoring", "monitoring", False)

        while MONITOR_ACTIVE:
            for account in db_manager.get_accounts():
                provider = account.get("provider", "").lower()
                try:
                    processed_ids = db_manager.load_processed_emails_for_account(account["id"])
                    if provider == "gmail":
                        service = get_gmail_service(account["email"])
                        cursor = account.get("last_history_id")
                        latest_history_id = None

                        if cursor:
                            try:
                                new_ids, latest_history_id = list_new_inbox_message_ids_since(service, cursor)
                            except HttpError as e:
                                status = getattr(getattr(e, "resp", None), "status", None)
                                if status == 404:
                                    logger.warning(f"Gmail history expired for {account['email']}; falling back to full INBOX diff.")
                                    new_ids = list_inbox_message_ids(service)[:MAIL_SYNC_LIMIT]
                                else:
                                    raise
                        else:
                            new_ids = list_inbox_message_ids(service)[:MAIL_SYNC_LIMIT]

                        parsed_items = []
                        for msg_id in new_ids:
                            if msg_id not in processed_ids:
                                parsed = fetch_email_metadata_by_id(service, msg_id)
                                if parsed:
                                    db_manager.cache_email_metadata(parsed, account["id"], "inbox")
                                    parsed_items.append((msg_id, service, None))

                        for idx, (parsed, gmail_svc, outlook_svc) in enumerate(parsed_items, 1):
                            if not MONITOR_ACTIVE:
                                break
                            _process_email(account, parsed, gmail_svc, outlook_svc, idx, len(parsed_items), "monitoring")

                        profile = get_gmail_profile(service)
                        db_manager.update_account_sync_state(account["id"], latest_history_id or profile.get("history_id"), True)

                    elif provider == "outlook":
                        parsed_items = [
                            parsed for parsed in fetch_outlook_inbox_emails(account["email"], unread_only=False)[:MAIL_SYNC_LIMIT]
                            if parsed.get("id") not in processed_ids
                        ]
                        for parsed in parsed_items:
                            db_manager.cache_email_metadata(parsed, account["id"], "inbox")
                        for idx, parsed in enumerate(parsed_items, 1):
                            if not MONITOR_ACTIVE:
                                break
                            _process_email(account, parsed, None, outlook_service or True, idx, len(parsed_items), "monitoring")
                        db_manager.update_account_sync_state(
                            account["id"],
                            last_history_id=datetime.now(timezone.utc).isoformat(),
                            initial_sync_complete=True,
                        )
                except Exception as e:
                    logger.error(f"Live polling error for {account.get('email')} ({provider}): {e}")
                finally:
                    _set_worker_state("monitoring", "monitoring", False)

            time.sleep(10)
    finally:
        MONITOR_ACTIVE = False
        logger.info("Real-mail background monitoring worker terminated.")
        with STATE_LOCK:
            PLAYBOOK_STATE["running"] = False
            PLAYBOOK_STATE["stage"] = "idle"


# ─────────────────────────────────────────────────────────────
# CLI Entry Point
# ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="SOAR Phishing Response Playbook",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --demo             # Run with built-in phishing demo email
  python main.py                    # Process latest Gmail inbox email
  python main.py --email-id MSG_ID  # Process specific Gmail message
        """
    )
    parser.add_argument("--demo",     action="store_true", help="Use demo phishing email")
    parser.add_argument("--email-id", type=str,            help="Gmail message ID to process")
    parser.add_argument("--no-gmail", action="store_true", help="Skip Gmail auth (use with --demo)")
    args = parser.parse_args()

    gmail_service = None
    if not args.demo and not args.no_gmail:
        try:
            from gmail_connector import get_gmail_service
            gmail_service = get_gmail_service()
        except Exception as e:
            logger.warning(f"Could not connect to Gmail: {e}")
            logger.info("Tip: Use --demo flag to run without Gmail")

    result = run_playbook(
        gmail_service=gmail_service,
        email_id=args.email_id,
        use_demo=args.demo or gmail_service is None,
    )

    print(f"\n{'='*60}")
    print(f"[DONE] Completed in {result.get('elapsed_sec', 0)}s")
    print(f"[VERDICT] {result.get('verdict', 'N/A')}")
    print(f"[TICKET] {result.get('ticket_id', 'N/A')}")
    if result.get("html_path"):
        print(f"[REPORT] {result['html_path']}")
    print(f"{'='*60}\n")
