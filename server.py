"""
SOAR Dashboard Server — Final version with working static file serving
"""

import os, sys, json, threading, webbrowser, logging
from datetime import datetime, timezone

DASHBOARD_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dashboard")
REPORTS_DIR   = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports")
FLASK_PORT    = int(os.getenv("FLASK_PORT", 5000))

from flask import Flask, jsonify, request, send_from_directory, send_file, Response
from flask_cors import CORS

app = Flask(__name__)
CORS(app)


@app.after_request
def add_no_cache_headers(response):
    if request.path in ("/", "/app.js", "/style.css"):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
    return response

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from main import run_mail_monitoring_worker, PLAYBOOK_STATE, STATE_LOCK

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────
# Static file serving — explicit routes for dashboard assets
# ─────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return send_from_directory(DASHBOARD_DIR, "index.html")

@app.route("/style.css")
def serve_css():
    return send_from_directory(DASHBOARD_DIR, "style.css", mimetype="text/css")

@app.route("/app.js")
def serve_js():
    return send_from_directory(DASHBOARD_DIR, "app.js", mimetype="application/javascript")

@app.route("/favicon.ico")
def favicon():
    return Response(status=204)

# ─────────────────────────────────────────────────────────────
# API: Run Playbook
# ─────────────────────────────────────────────────────────────

@app.route("/api/run", methods=["POST"])
def api_run():
    _start_mail_monitor()
    return jsonify({"status": "started", "source": "real_mail", "demo": False,
                    "timestamp": datetime.now(timezone.utc).isoformat()})


def _start_mail_monitor(gmail_service=None, outlook_service=None):
    def _run_monitor():
        run_mail_monitoring_worker(
            gmail_service=gmail_service,
            outlook_service=outlook_service,
            source="real_mail"
        )
    threading.Thread(target=_run_monitor, daemon=True).start()

# ─────────────────────────────────────────────────────────────
# API: Status
# ─────────────────────────────────────────────────────────────

@app.route("/api/status")
def api_status():
    with STATE_LOCK:
        state = dict(PLAYBOOK_STATE)
    state["stages"] = [
        {"name": s["name"], "status": s["status"],
         "timestamp": s["timestamp"], "data": s.get("data", {})}
        for s in state.get("stages", [])
    ]
    # Return additional worker metadata
    state["queue_size"] = PLAYBOOK_STATE.get("queue_size", 0)
    state["queue_index"] = PLAYBOOK_STATE.get("queue_index", 0)
    state["mode"] = PLAYBOOK_STATE.get("mode", "idle")
    state["source"] = PLAYBOOK_STATE.get("source", "idle")
    return jsonify(state)

# ─────────────────────────────────────────────────────────────
# API: Multi-Accounts & Mailing Client Mode
# ─────────────────────────────────────────────────────────────

@app.route("/api/accounts")
def api_get_accounts():
    import db_manager
    return jsonify(db_manager.get_accounts())

@app.route("/api/auth/gmail", methods=["POST"])
def api_auth_gmail():
    import db_manager
    try:
        from gmail_connector import authenticate_gmail_account
        service, profile = authenticate_gmail_account()
        email = profile.get("email")
        if not email:
            return jsonify({"error": "Gmail sign-in did not return an email address."}), 400

        acc_id = db_manager.add_account(email, "gmail", status="active", token_data=profile)
        db_manager.update_account_sync_state(
            acc_id,
            last_history_id=profile.get("history_id"),
            initial_sync_complete=False,
        )
        _start_mail_monitor(gmail_service=service)
        return jsonify({"status": "success", "id": acc_id, "email": email, "provider": "gmail"})
    except Exception as e:
        logger.error(f"Gmail authentication failed: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


@app.route("/api/auth/outlook", methods=["POST"])
def api_auth_outlook():
    import db_manager
    try:
        from outlook_connector import authenticate_outlook_account
        token, profile = authenticate_outlook_account()
        email = profile.get("email")
        if not token or not email:
            return jsonify({"error": "Outlook sign-in did not return an authenticated mailbox."}), 400

        acc_id = db_manager.add_account(email, "outlook", status="active", token_data=profile)
        db_manager.update_account_sync_state(acc_id, initial_sync_complete=False)
        _start_mail_monitor(outlook_service=token)
        return jsonify({"status": "success", "id": acc_id, "email": email, "provider": "outlook"})
    except Exception as e:
        logger.error(f"Outlook authentication failed: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


@app.route("/api/accounts/add", methods=["POST"])
def api_add_account():
    data = request.json or {}
    provider = (data.get("provider") or "").lower()
    if provider == "gmail":
        return api_auth_gmail()
    if provider == "outlook":
        return api_auth_outlook()
    return jsonify({"error": "Only real Gmail and Outlook OAuth accounts are supported."}), 400

@app.route("/api/accounts/delete", methods=["POST"])
def api_delete_account():
    import db_manager
    data = request.json or {}
    account_id = data.get("id")
    if not account_id:
        return jsonify({"error": "Account ID is required"}), 400
    db_manager.delete_account(account_id)
    return jsonify({"status": "success"})

@app.route("/api/mails")
def api_get_mails():
    import db_manager
    account_id = request.args.get("account_id")
    folder = request.args.get("folder")
    limit = request.args.get("limit", 25)
    return jsonify(db_manager.get_emails(account_id, folder, limit))

@app.route("/api/mails/<id>")
def api_get_mail_details(id):
    import db_manager
    email = db_manager.get_email_details(id)
    if not email:
        return jsonify({"error": "Email not found"}), 404

    if not (email.get("body_plain") or email.get("body_html")):
        account = db_manager.get_account_by_id(email.get("account_id"))
        parsed = None
        try:
            if account and account.get("provider") == "gmail":
                from gmail_connector import get_gmail_service, fetch_email_by_id
                service = get_gmail_service(account.get("email"))
                parsed = fetch_email_by_id(service, id)
            elif account and account.get("provider") == "outlook":
                from outlook_connector import fetch_outlook_email_by_id
                parsed = fetch_outlook_email_by_id(account.get("email"), id)

            if parsed:
                db_manager.update_email_content(id, parsed)
                email = db_manager.get_email_details(id) or email
        except Exception as e:
            logger.error(f"Body hydration failed for email {id}: {e}", exc_info=True)
        
    ticket = None
    if email.get("ticket_id"):
        ticket_file = os.path.join(REPORTS_DIR, f"ticket_{email['ticket_id']}.json")
        if os.path.exists(ticket_file):
            try:
                ticket = json.load(open(ticket_file))
            except Exception as e:
                logger.error(f"Error loading ticket file: {e}")
                
    response_data = dict(email)
    response_data["ticket"] = ticket
    return jsonify(response_data)

@app.route("/api/mails/<id>/read", methods=["POST"])
def api_mark_read(id):
    import db_manager
    db_manager.mark_email_as_read(id)
    return jsonify({"status": "success"})

# ─────────────────────────────────────────────────────────────
# API: Reports
# ─────────────────────────────────────────────────────────────

@app.route("/api/report/<ticket_id>")
def api_report(ticket_id):
    f = os.path.join(REPORTS_DIR, f"report_{ticket_id}.html")
    return send_file(f) if os.path.exists(f) else (jsonify({"error": "Not found"}), 404)

@app.route("/api/ticket/<ticket_id>")
def api_ticket(ticket_id):
    f = os.path.join(REPORTS_DIR, f"ticket_{ticket_id}.json")
    if os.path.exists(f):
        return jsonify(json.load(open(f)))
    return jsonify({"error": "Not found"}), 404

@app.route("/api/reports")
def api_list_reports():
    reports = []
    if os.path.exists(REPORTS_DIR):
        for f in sorted(os.listdir(REPORTS_DIR), reverse=True):
            if f.startswith("ticket_") and f.endswith(".json"):
                tid = f[7:-5]
                reports.append({"ticket_id": tid,
                                 "json_url": f"/api/ticket/{tid}",
                                 "html_url": f"/api/report/{tid}"})
    return jsonify(reports)

# ─────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print(f"""
+------------------------------------------------------+
|        SOAR Security Mail Client                     |
|  Open in browser -> http://localhost:{FLASK_PORT}           |
+------------------------------------------------------+
""")
    # Start background mail monitoring daemon on startup
    def _start_monitoring():
        try:
            logger.info("Initializing background mail monitor daemon on startup...")
            run_mail_monitoring_worker(source="real_mail")
        except Exception as e:
            logger.error(f"Error in background mail monitoring: {e}")
            
    threading.Thread(target=_start_monitoring, daemon=True).start()

    def _open():
        import time; time.sleep(1.5)
        webbrowser.open(f"http://localhost:{FLASK_PORT}")

    threading.Thread(target=_open, daemon=True).start()
    app.run(host="0.0.0.0", port=FLASK_PORT, debug=False, use_reloader=False)
