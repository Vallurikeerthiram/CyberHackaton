"""
Triage Decision Engine
=======================
Scores and classifies phishing emails based on IoC enrichment results.
Produces a final verdict: MALICIOUS / SUSPICIOUS / CLEAN

Person 3-4 Role: Automated triage
MITRE ATT&CK: T1566, T1598
"""

import logging
from typing import Dict, Any
from urllib.parse import urlparse
from config import MALICIOUS_THRESHOLD, SUSPICIOUS_THRESHOLD, MITRE_MAPPING

logger = logging.getLogger(__name__)

COMMON_TRACKING_DOMAINS = (
    "pstmrk.it",
    "engage.canva.com",
    "email.adobe.com",
    "awstrack.me",
    "sendgrid.net",
    "stripocdn.email",
    "useinsider.com",
)


def _domain_from_url(url: str) -> str:
    try:
        return urlparse(url if "://" in url else "http://" + url).netloc.lower().split(":")[0]
    except Exception:
        return ""


def _is_common_tracking_domain(domain: str) -> bool:
    domain = (domain or "").lower()
    return any(domain == known or domain.endswith("." + known) for known in COMMON_TRACKING_DOMAINS)


def _only_common_tracking_urls(iocs: dict) -> bool:
    urls = iocs.get("urls", [])
    if not urls:
        return False
    return all(_is_common_tracking_domain(_domain_from_url(url)) for url in urls)


def _has_strong_risk(iocs: dict, enrichment: dict) -> bool:
    risk_text = " | ".join(iocs.get("risk_indicators", [])).lower()
    if any(marker in risk_text for marker in ("suspicious url/domain tld", "suspicious tld", "lookalike", "reply-to domain mismatch")):
        return True
    if any(att.get("suspicious") for att in iocs.get("attachments", [])):
        return True

    sender_trust = enrichment.get("sender_trust") or {}
    if sender_trust.get("trust_level") in ("SPOOFED", "UNTRUSTED"):
        return True

    return False


def triage(iocs: dict, enrichment: dict, ai_analysis: dict = None) -> Dict[str, Any]:
    """
    Run triage on extracted IoCs and enrichment results.
    Returns verdict with score, reasons, and MITRE ATT&CK mappings.
    """
    logger.info("Running triage decision engine...")

    score         = 0
    reasons       = []
    mitre_tags    = []
    attack_types  = []

    # ── 1. Enrichment-based scoring ──────────────────────────
    vt_malicious_count = 0
    vt_suspicious_count = 0
    urlscan_malicious_count = 0
    vt_attachment_malicious_count = 0
    vt_attachment_suspicious_count = 0

    for url_result in enrichment.get("url_results", []):
        vt = url_result.get("virustotal", {})
        mal = vt.get("malicious", 0)
        sus = vt.get("suspicious", 0)
        vt_malicious_count  += mal
        vt_suspicious_count += sus

        if mal >= MALICIOUS_THRESHOLD:
            score += 40
            reasons.append(f"URL flagged malicious by {mal} VT vendors: {url_result['url'][:60]}")
        elif mal > 0:
            score += 20
            reasons.append(f"URL flagged by {mal} VT vendor(s): {url_result['url'][:60]}")
        elif sus > 0:
            score += 10
            reasons.append(f"URL flagged suspicious by {sus} VT vendor(s): {url_result['url'][:60]}")

        # URLScan verdict
        urlscan = url_result.get("urlscan", {})
        if urlscan.get("malicious"):
            urlscan_malicious_count += 1
            score += 30
            reasons.append(f"URLScan flagged URL as malicious (score: {urlscan.get('score', 0)})")
            if urlscan.get("brands"):
                reasons.append(f"URLScan detected brand impersonation: {', '.join(urlscan['brands'])}")
                attack_types.append("spear_phishing")

    for domain_result in enrichment.get("domain_results", []):
        vt = domain_result.get("virustotal", {})
        mal = vt.get("malicious", 0)
        sus = vt.get("suspicious", 0)

        if mal >= MALICIOUS_THRESHOLD:
            score += 35
            reasons.append(f"Domain flagged malicious by {mal} VT vendors: {domain_result['domain']}")
        elif mal > 0:
            score += 15
            reasons.append(f"Domain flagged by {mal} VT vendor(s): {domain_result['domain']}")
        elif sus > 0:
            score += 8
            reasons.append(f"Domain flagged suspicious: {domain_result['domain']}")

    for attachment_result in enrichment.get("attachment_results", []):
        vt = attachment_result.get("virustotal", {})
        mal = vt.get("malicious", 0)
        sus = vt.get("suspicious", 0)
        vt_attachment_malicious_count += mal
        vt_attachment_suspicious_count += sus
        filename = attachment_result.get("filename", "attachment")

        if mal >= MALICIOUS_THRESHOLD:
            score += 45
            reasons.append(f"Attachment flagged malicious by {mal} VT vendors: {filename}")
            attack_types.append("spear_phishing")
        elif mal > 0:
            score += 25
            reasons.append(f"Attachment flagged by {mal} VT vendor(s): {filename}")
            attack_types.append("spear_phishing")
        elif sus > 0:
            score += 15
            reasons.append(f"Attachment flagged suspicious by {sus} VT vendor(s): {filename}")

    # ── 2. IoC-based scoring ──────────────────────────────────
    risk_indicators = iocs.get("risk_indicators", [])
    for indicator in risk_indicators[:2]:
        score += 10
        reasons.append(f"Risk indicator: {indicator}")
    if len(risk_indicators) > 2:
        reasons.append(f"Additional risk indicators observed: {len(risk_indicators) - 2}")

    header_anomalies = iocs.get("header_anomalies", [])
    for anomaly in header_anomalies[:1]:
        score += 5
        reasons.append(f"Header anomaly: {anomaly}")

    # Keyword density
    keywords = iocs.get("keywords_found", [])
    if len(keywords) >= 5:
        score += 20
        reasons.append(f"High phishing keyword density: {len(keywords)} keywords")
        attack_types.append("phishing")
    elif len(keywords) >= 2:
        score += 10
        reasons.append(f"Moderate keyword count: {len(keywords)} phishing keywords")

    # Suspicious attachments
    suspicious_attachments = [a for a in iocs.get("attachments", []) if a.get("suspicious")]
    if suspicious_attachments:
        score += 25
        fnames = [a["filename"] for a in suspicious_attachments]
        reasons.append(f"Suspicious attachments: {', '.join(fnames)}")
        attack_types.append("spear_phishing")

    # ── 3. Sender domain trust scoring ────────────────────────
    sender_trust = enrichment.get("sender_trust")
    if sender_trust:
        trust_score = sender_trust.get("trust_score", 100)
        trust_level = sender_trust.get("trust_level", "TRUSTED")
        risk_flags = sender_trust.get("risk_flags", [])

        if trust_level != "TRUSTED":
            reasons.append(f"Sender domain authenticity is {trust_level} (Trust Score: {trust_score}/100)")
            if trust_level == "SPOOFED":
                score += 45
                attack_types.append("phishing")
            elif trust_level == "UNTRUSTED":
                score += 20
            elif trust_level == "SUSPICIOUS":
                score += 8

        for flag in risk_flags:
            reasons.append(f"Sender Auth Flag: {flag}")

    # Local model is a secondary analyst signal after URL/API and TLS checks.
    ai_analysis = ai_analysis or {}
    ai_verdict = ai_analysis.get("verdict")
    ai_confidence = int(ai_analysis.get("confidence", 0) or 0)
    api_bad = (
        vt_malicious_count > 0
        or vt_suspicious_count > 0
        or urlscan_malicious_count > 0
        or vt_attachment_malicious_count > 0
        or vt_attachment_suspicious_count > 0
    )
    strong_risk = _has_strong_risk(iocs, enrichment)
    if ai_verdict in ("MALICIOUS", "SUSPICIOUS"):
        if ai_verdict == "MALICIOUS":
            score += 35 if (ai_confidence >= 70 and (api_bad or strong_risk)) else 12
            if api_bad or strong_risk:
                attack_types.append("phishing")
        else:
            score += 20 if (ai_confidence >= 70 and (api_bad or strong_risk)) else 8
            if api_bad or strong_risk:
                attack_types.append("info_gathering")
        reasons.append(
            f"Local security model classified the email as {ai_verdict} "
            f"({ai_confidence}/100): {ai_analysis.get('reason', 'No reason provided')}"
        )

    # ── 4. Determine verdict ──────────────────────────────────
    has_urls = bool(iocs.get("urls"))
    has_attachments = bool(iocs.get("attachments"))
    if not has_urls and not has_attachments:
        score = min(score, 25)
        reasons.append("No URLs or attachments found; body-only message capped as low-risk.")
    elif not api_bad and not strong_risk:
        score = min(score, 25)
        reasons.append("No high-confidence URL/API, sender, or attachment evidence; capped as clean/low-risk.")
    elif not (vt_malicious_count or urlscan_malicious_count) and _only_common_tracking_urls(iocs):
        score = min(score, 35)
        reasons.append("Only common marketing/tracking URLs were observed; capped below malicious.")

    score = min(score, 100)  # Cap at 100

    if score >= 60:
        verdict = "MALICIOUS"
        action  = "QUARANTINE + BLOCK"
        color   = "#ef4444"
        attack_types.append("phishing")
    elif score >= 30:
        verdict = "SUSPICIOUS"
        action  = "QUARANTINE + ANALYST REVIEW"
        color   = "#f59e0b"
        attack_types.append("info_gathering")
    else:
        verdict = "CLEAN"
        action  = "NO ACTION"
        color   = "#10b981"

    # ── 4. MITRE ATT&CK mappings ──────────────────────────────
    if not attack_types:
        attack_types = ["phishing"]

    for attack_type in set(attack_types):
        if attack_type in MITRE_MAPPING:
            mitre_tags.append(MITRE_MAPPING[attack_type])

    # Always include base phishing technique
    if MITRE_MAPPING["phishing"] not in mitre_tags:
        mitre_tags.append(MITRE_MAPPING["phishing"])

    result = {
        "verdict":      verdict,
        "score":        score,
        "action":       action,
        "color":        color,
        "reasons":      reasons,
        "mitre_tags":   mitre_tags,
        "attack_types": list(set(attack_types)),
        "stats": {
            "vt_malicious":   vt_malicious_count,
            "vt_suspicious":  vt_suspicious_count,
            "vt_attachment_malicious": vt_attachment_malicious_count,
            "vt_attachment_suspicious": vt_attachment_suspicious_count,
            "urlscan_malicious": urlscan_malicious_count,
            "risk_indicators": len(risk_indicators),
            "keywords":       len(keywords),
            "suspicious_attachments": len(suspicious_attachments),
            "gemma_verdict": ai_verdict or "UNKNOWN",
            "gemma_confidence": ai_confidence,
        }
    }

    logger.info(
        f"Triage complete — Verdict: {verdict} | Score: {score}/100 | "
        f"Reasons: {len(reasons)}"
    )
    return result
