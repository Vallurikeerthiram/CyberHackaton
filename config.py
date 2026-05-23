# ============================================================
# SOAR Playbook - Configuration
# ============================================================
import os
from dotenv import load_dotenv

load_dotenv()

# --- API Keys ---
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
URLSCAN_API_KEY    = os.getenv("URLSCAN_API_KEY", "")
URLSCAN_MAX_URLS   = int(os.getenv("URLSCAN_MAX_URLS", "2"))
SLACK_WEBHOOK_URL  = os.getenv("SLACK_WEBHOOK_URL", "")

# --- Gmail Settings ---
GMAIL_LABEL       = os.getenv("GMAIL_LABEL", "INBOX")
QUARANTINE_LABEL  = os.getenv("QUARANTINE_LABEL", "SOAR-Quarantined")
CREDENTIALS_FILE  = os.path.join(os.path.dirname(__file__), "credentials.json")
TOKEN_FILE        = os.path.join(os.path.dirname(__file__), "token.json")

# --- Outlook Settings ---
OUTLOOK_CLIENT_ID     = os.getenv("OUTLOOK_CLIENT_ID", "")
OUTLOOK_CLIENT_SECRET = os.getenv("OUTLOOK_CLIENT_SECRET", "")
OUTLOOK_TENANT_ID     = os.getenv("OUTLOOK_TENANT_ID", "common")
OUTLOOK_TOKEN_FILE    = os.path.join(os.path.dirname(__file__), "outlook_token.json")
OUTLOOK_SCOPES        = ["Mail.ReadWrite", "Mail.Send", "User.Read"]


# OAuth Scopes required
GMAIL_SCOPES = [
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/gmail.modify",
    "https://www.googleapis.com/auth/gmail.labels",
]

# --- Triage Thresholds ---
MALICIOUS_THRESHOLD  = 3   # VT detections to be malicious
SUSPICIOUS_THRESHOLD = 1   # VT detections to be suspicious

# --- Paths ---
BASE_DIR        = os.path.dirname(__file__)
REPORTS_DIR     = os.path.join(BASE_DIR, "reports")
BLOCKLIST_FILE  = os.path.join(BASE_DIR, "blocklist.txt")
QUARANTINE_LOG  = os.path.join(BASE_DIR, "quarantine_log.json")

# --- Flask ---
FLASK_PORT = int(os.getenv("FLASK_PORT", 5000))

# --- MITRE ATT&CK Mappings ---
MITRE_MAPPING = {
    "phishing":         {"id": "T1566",   "name": "Phishing"},
    "spear_phishing":   {"id": "T1566.001","name": "Spearphishing Attachment"},
    "phishing_link":    {"id": "T1566.002","name": "Spearphishing Link"},
    "info_gathering":   {"id": "T1598",   "name": "Phishing for Information"},
    "credential_theft": {"id": "T1056",   "name": "Input Capture"},
}
