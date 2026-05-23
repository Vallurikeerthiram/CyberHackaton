"""
Email Parser & IoC Extractor
=============================
Extracts Indicators of Compromise (IoCs) from email content:
- URLs (from body and HTML)
- Sender domain analysis
- Attachment metadata and hashes
- Email header anomalies

Person 1-2 Role: IoC extraction
MITRE ATT&CK: T1566 - Phishing, T1566.001 - Spearphishing Attachment
"""

import re
import hashlib
import logging
from html import unescape
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from typing import Dict, List, Any

logger = logging.getLogger(__name__)

# --- Regex Patterns ---
URL_PATTERN = re.compile(
    r'https?://[^\s<>"\')\]]+|www\.[^\s<>"\')\]]+',
    re.IGNORECASE
)

IP_PATTERN = re.compile(
    r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
)

EMAIL_PATTERN = re.compile(
    r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
)

# Suspicious keywords indicating phishing intent
PHISHING_KEYWORDS = [
    "verify your account", "confirm your identity", "click here",
    "urgent", "suspended", "limited time", "act now", "unusual activity",
    "password reset", "update payment", "security alert", "login attempt",
    "congratulations you won", "claim your prize", "verify email",
    "account compromised", "immediate action required", "sign in",
    "banking", "paypal", "amazon", "microsoft", "apple", "google",
    "irs", "fedex", "dhl", "invoice", "refund", "tax return"
]

# Suspicious TLDs often used in phishing
SUSPICIOUS_TLDS = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".club", ".work", ".online"]

# Trusted domains (whitelist)
TRUSTED_DOMAINS = [
    "google.com", "microsoft.com", "apple.com", "amazon.com",
    "github.com", "linkedin.com", "twitter.com", "facebook.com"
]

IGNORED_RESOURCE_DOMAINS = {
    "www.w3.org",
    "w3.org",
    "fonts.googleapis.com",
    "fonts.gstatic.com",
}

IGNORED_RESOURCE_EXTENSIONS = (
    ".css", ".woff", ".woff2", ".ttf", ".otf", ".eot", ".svg",
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico",
)


def html_to_text(html: str) -> str:
    """Convert HTML-only email bodies into readable text for display and triage."""
    if not html:
        return ""
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup(["script", "style", "noscript", "svg", "head"]):
        tag.decompose()
    text = soup.get_text("\n")
    text = unescape(text)
    text = re.sub(r"\r", "\n", text)
    text = re.sub(r"\n[ \t]+", "\n", text)
    text = re.sub(r"[ \t]{2,}", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def extract_iocs(email_data: dict) -> Dict[str, Any]:
    """
    Main IoC extraction function.
    Takes parsed email dict, returns all extracted IoCs with metadata.
    """
    logger.info("Starting IoC extraction...")
    iocs = {
        "urls":              [],
        "domains":           [],
        "sender_domain":     "",
        "sender_email":      "",
        "reply_to_domain":   "",
        "attachments":       [],
        "embedded_emails":   [],
        "ips":               [],
        "keywords_found":    [],
        "header_anomalies":  [],
        "risk_indicators":   [],
        "raw_text":          "",
    }

    # 1. Sender analysis
    _extract_sender_info(email_data, iocs)

    # 2. Extract from plain text body
    plain = email_data.get("body_plain", "")
    _extract_from_text(plain, iocs)

    # 3. Extract from HTML body
    html = email_data.get("body_html", "")
    _extract_from_html(html, iocs)

    # 4. Attachment metadata
    _extract_attachment_info(email_data.get("attachments", []), iocs)

    # 5. Header anomaly detection
    _detect_header_anomalies(email_data, iocs)

    # 6. Keyword scanning
    full_text = (plain + " " + html).lower()
    iocs["raw_text"] = full_text[:500]  # first 500 chars for display
    _scan_keywords(full_text, iocs)

    # Deduplicate
    iocs["urls"]    = list(dict.fromkeys(url for url in iocs["urls"] if not _is_ignored_resource_url(url)))
    iocs["domains"] = list(dict.fromkeys(domain for domain in iocs["domains"] if not _is_ignored_resource_domain(domain)))
    iocs["ips"]     = list(dict.fromkeys(iocs["ips"]))

    for domain in iocs["domains"]:
        if any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS):
            iocs["risk_indicators"].append(f"Suspicious URL/domain TLD: {domain}")
    iocs["risk_indicators"] = list(dict.fromkeys(iocs["risk_indicators"]))

    logger.info(
        f"IoC extraction complete — "
        f"URLs: {len(iocs['urls'])}, "
        f"Domains: {len(iocs['domains'])}, "
        f"Attachments: {len(iocs['attachments'])}, "
        f"Keywords: {len(iocs['keywords_found'])}"
    )
    return iocs


def _extract_sender_info(email_data: dict, iocs: dict):
    """Parse sender and reply-to for domain analysis."""
    sender = email_data.get("from", "")
    reply_to = email_data.get("reply_to", "")
    return_path = email_data.get("return_path", "")

    # Extract sender email and domain
    sender_emails = EMAIL_PATTERN.findall(sender)
    if sender_emails:
        iocs["sender_email"] = sender_emails[0]
        iocs["sender_domain"] = _extract_domain(sender_emails[0])
        if iocs["sender_domain"]:
            iocs["domains"].append(iocs["sender_domain"])

    # Check reply-to mismatch (common phishing indicator)
    reply_emails = EMAIL_PATTERN.findall(reply_to)
    if reply_emails:
        reply_domain = _extract_domain(reply_emails[0])
        iocs["reply_to_domain"] = reply_domain
        if reply_domain and reply_domain != iocs["sender_domain"]:
            iocs["risk_indicators"].append(
                f"Reply-to domain mismatch: sender={iocs['sender_domain']} reply-to={reply_domain}"
            )
            if reply_domain:
                iocs["domains"].append(reply_domain)

    # Return-path mismatch
    rp_emails = EMAIL_PATTERN.findall(return_path)
    if rp_emails:
        rp_domain = _extract_domain(rp_emails[0])
        if rp_domain and rp_domain != iocs["sender_domain"]:
            iocs["risk_indicators"].append(
                f"Return-path domain mismatch: {rp_domain}"
            )


def _extract_from_text(text: str, iocs: dict):
    """Extract URLs and IPs from plain text body."""
    if not text:
        return

    # Extract URLs
    for url in URL_PATTERN.findall(text):
        url = url.rstrip(".,;:!?")
        iocs["urls"].append(url)
        domain = _extract_domain_from_url(url)
        if domain:
            iocs["domains"].append(domain)

    # Extract IPs
    for ip in IP_PATTERN.findall(text):
        if not _is_private_ip(ip):
            iocs["ips"].append(ip)

    # Extract emails mentioned in body
    for email in EMAIL_PATTERN.findall(text):
        iocs["embedded_emails"].append(email)


def _extract_from_html(html: str, iocs: dict):
    """Extract URLs from HTML — catches hidden/obfuscated links."""
    if not html:
        return

    soup = BeautifulSoup(html, "html.parser")

    # Extract all href links
    for tag in soup.find_all(href=True):
        href = tag.get("href", "")
        if href.startswith("http") or href.startswith("www"):
            href = href.rstrip(".,;:!?")
            iocs["urls"].append(href)
            domain = _extract_domain_from_url(href)
            if domain:
                iocs["domains"].append(domain)

        # Check for display text vs actual link mismatch (phishing indicator)
        display_text = tag.get_text(strip=True)
        if display_text.startswith("http") and href and display_text not in href:
            iocs["risk_indicators"].append(
                f"Link text/href mismatch: displayed='{display_text[:60]}' actual='{href[:60]}'"
            )

    # Resource URLs are tracked as domains only; they should not dominate verdicts.
    for attr in ("src", "background"):
        for tag in soup.find_all(attrs={attr: True}):
            src = tag.get(attr, "")
            if src.startswith("http"):
                domain = _extract_domain_from_url(src)
                if domain and not _is_ignored_resource_domain(domain):
                    iocs["domains"].append(domain)


def _extract_attachment_info(attachments: List[dict], iocs: dict):
    """Process attachment metadata and flag suspicious types."""
    DANGEROUS_EXTENSIONS = [
        ".exe", ".js", ".vbs", ".bat", ".cmd", ".ps1", ".hta",
        ".scr", ".pif", ".jar", ".zip", ".rar", ".7z", ".doc",
        ".docm", ".xlsm", ".xls", ".ppt", ".pdf"
    ]

    for att in attachments:
        filename = att.get("filename", "")
        mime     = att.get("mimeType", "")
        size     = att.get("size", 0)
        ext      = "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else ""

        is_suspicious = ext in DANGEROUS_EXTENSIONS

        attachment_ioc = {
            "filename":     filename,
            "mimeType":     mime,
            "size":         size,
            "extension":    ext,
            "suspicious":   is_suspicious,
            "attachmentId": att.get("attachmentId", ""),
            "messageId":    att.get("messageId", ""),
            "sha256":       att.get("sha256", ""),
            "md5":          att.get("md5", ""),
        }

        if is_suspicious:
            iocs["risk_indicators"].append(
                f"Suspicious attachment: {filename} ({mime})"
            )

        iocs["attachments"].append(attachment_ioc)


def _detect_header_anomalies(email_data: dict, iocs: dict):
    """Detect anomalous email headers that indicate phishing."""
    headers = email_data.get("raw_headers", {})

    # Check for missing common headers
    for expected in ["message-id", "mime-version"]:
        if expected not in headers:
            iocs["header_anomalies"].append(f"Missing header: {expected}")

    # Check sender domain vs received-from mismatch
    received = headers.get("received", "")
    sender_domain = iocs.get("sender_domain", "")
    if sender_domain and received and sender_domain not in received:
        iocs["header_anomalies"].append(
            f"Sender domain '{sender_domain}' not in Received header"
        )

    # Flag suspicious TLDs in sender domain
    if sender_domain:
        for tld in SUSPICIOUS_TLDS:
            if sender_domain.endswith(tld):
                iocs["risk_indicators"].append(
                    f"Sender uses suspicious TLD: {sender_domain}"
                )

    # Check for homograph/lookalike domains
    for domain in iocs.get("domains", []):
        if _is_ignored_resource_domain(domain):
            continue
        for trusted in TRUSTED_DOMAINS:
            if domain == trusted or domain.endswith("." + trusted):
                continue
            trusted_base = trusted.split(".")[0]
            if trusted_base in domain and domain != trusted:
                iocs["risk_indicators"].append(
                    f"Possible lookalike domain: {domain} (similar to {trusted})"
                )


def _scan_keywords(text: str, iocs: dict):
    """Scan email body for phishing keywords."""
    found = []
    for keyword in PHISHING_KEYWORDS:
        if keyword.lower() in text:
            found.append(keyword)
    iocs["keywords_found"] = found
    if len(found) >= 3:
        iocs["risk_indicators"].append(
            f"High keyword density: {len(found)} phishing keywords detected"
        )


def _extract_domain(email_address: str) -> str:
    """Extract domain from email address."""
    try:
        return email_address.split("@")[1].strip().strip(">").strip("<")
    except (IndexError, AttributeError):
        return ""


def _extract_domain_from_url(url: str) -> str:
    """Extract domain from URL."""
    try:
        parsed = urlparse(url if "://" in url else "http://" + url)
        return parsed.netloc.split(":")[0].lower()
    except Exception:
        return ""


def _is_ignored_resource_domain(domain: str) -> bool:
    domain = (domain or "").lower().strip()
    return domain in IGNORED_RESOURCE_DOMAINS


def _is_ignored_resource_url(url: str) -> bool:
    try:
        domain = _extract_domain_from_url(url)
        path = urlparse(url if "://" in url else "http://" + url).path.lower()
        if _is_ignored_resource_domain(domain):
            return True
        return path.endswith(IGNORED_RESOURCE_EXTENSIONS)
    except Exception:
        return False


def _is_private_ip(ip: str) -> bool:
    """Check if IP is private/local."""
    parts = ip.split(".")
    if len(parts) != 4:
        return True
    first, second = int(parts[0]), int(parts[1])
    return (
        first == 10 or
        (first == 172 and 16 <= second <= 31) or
        (first == 192 and second == 168) or
        first == 127
    )
