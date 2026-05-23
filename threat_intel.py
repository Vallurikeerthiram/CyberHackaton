"""
Threat Intelligence Enrichment Module
=======================================
Enriches extracted IoCs using:
- VirusTotal API (URL/domain/file reputation)
- URLScan.io API (URL scanning and screenshot)

Person 3 Role: Threat intel enrichment
MITRE ATT&CK: T1566.002 - Spearphishing Link
"""

import time
import logging
import requests
from typing import Dict, Any, Optional
from urllib.parse import urlparse, urlunparse

from config import VIRUSTOTAL_API_KEY, URLSCAN_API_KEY, URLSCAN_MAX_URLS
from cert_checker import analyze_sender_trust

logger = logging.getLogger(__name__)

# --- API Base URLs ---
VT_BASE_URL      = "https://www.virustotal.com/api/v3"
URLSCAN_BASE_URL = "https://urlscan.io/api/v1"


# ─────────────────────────────────────────────────────────────
#  VIRUSTOTAL FUNCTIONS
# ─────────────────────────────────────────────────────────────

def sanitize_url_for_api(url: str) -> str:
    """
    Sanitize URL by stripping query parameters and fragment to prevent leaking sensitive information
    like user emails, passwords, tokens, or session IDs.
    Returns cleaned URL string.
    """
    if not url:
        return ""
    try:
        parsed = urlparse(url)
        cleaned_parts = list(parsed)
        cleaned_parts[4] = ""  # query
        cleaned_parts[5] = ""  # fragment
        return urlunparse(cleaned_parts)
    except Exception as e:
        logger.warning(f"Error sanitizing URL '{url}': {e}")
        return url


def vt_check_url(url: str) -> Dict[str, Any]:
    """
    Submit a URL to VirusTotal for analysis.
    Returns detection stats and vendor results.
    """
    if not VIRUSTOTAL_API_KEY:
        logger.warning("VirusTotal API key not configured — skipping")
        return _vt_mock_result(url, "no_api_key")

    headers = {"x-apikey": VIRUSTOTAL_API_KEY, "accept": "application/json"}

    sanitized_url = sanitize_url_for_api(url)

    try:
        # Submit URL for scanning
        import base64
        url_id = base64.urlsafe_b64encode(sanitized_url.encode()).decode().strip("=")

        resp = requests.get(
            f"{VT_BASE_URL}/urls/{url_id}",
            headers=headers,
            timeout=15
        )

        if resp.status_code == 404:
            # URL not in VT cache — submit for scan
            scan_resp = requests.post(
                f"{VT_BASE_URL}/urls",
                headers={**headers, "content-type": "application/x-www-form-urlencoded"},
                data=f"url={requests.utils.quote(sanitized_url)}",
                timeout=15
            )
            if scan_resp.status_code == 200:
                time.sleep(3)  # Wait for analysis
                resp = requests.get(
                    f"{VT_BASE_URL}/urls/{url_id}",
                    headers=headers,
                    timeout=15
                )

        if resp.status_code != 200:
            return _vt_mock_result(url, f"http_{resp.status_code}")

        data = resp.json().get("data", {}).get("attributes", {})
        stats = data.get("last_analysis_stats", {})

        return {
            "source":       "virustotal",
            "ioc":          url,
            "type":         "url",
            "malicious":    stats.get("malicious", 0),
            "suspicious":   stats.get("suspicious", 0),
            "harmless":     stats.get("harmless", 0),
            "undetected":   stats.get("undetected", 0),
            "total":        sum(stats.values()),
            "reputation":   data.get("reputation", 0),
            "categories":   data.get("categories", {}),
            "last_analysis_date": data.get("last_analysis_date", ""),
            "status":       "success",
            "vendors": {
                k: v["result"]
                for k, v in data.get("last_analysis_results", {}).items()
                if v.get("category") in ("malicious", "suspicious")
            }
        }

    except requests.RequestException as e:
        logger.error(f"VirusTotal API error for {url}: {e}")
        return _vt_mock_result(url, "connection_error")


def vt_check_domain(domain: str) -> Dict[str, Any]:
    """Check a domain against VirusTotal."""
    if not VIRUSTOTAL_API_KEY:
        return _vt_mock_result(domain, "no_api_key")

    headers = {"x-apikey": VIRUSTOTAL_API_KEY, "accept": "application/json"}

    try:
        resp = requests.get(
            f"{VT_BASE_URL}/domains/{domain}",
            headers=headers,
            timeout=15
        )

        if resp.status_code != 200:
            return _vt_mock_result(domain, f"http_{resp.status_code}")

        data = resp.json().get("data", {}).get("attributes", {})
        stats = data.get("last_analysis_stats", {})

        return {
            "source":       "virustotal",
            "ioc":          domain,
            "type":         "domain",
            "malicious":    stats.get("malicious", 0),
            "suspicious":   stats.get("suspicious", 0),
            "harmless":     stats.get("harmless", 0),
            "undetected":   stats.get("undetected", 0),
            "total":        sum(stats.values()),
            "reputation":   data.get("reputation", 0),
            "categories":   data.get("categories", {}),
            "whois":        data.get("whois", "")[:300],
            "registrar":    data.get("registrar", ""),
            "creation_date": data.get("creation_date", ""),
            "status":       "success",
        }

    except requests.RequestException as e:
        logger.error(f"VirusTotal domain check error for {domain}: {e}")
        return _vt_mock_result(domain, "connection_error")


def vt_check_file_hash(file_hash: str, filename: str = "") -> Dict[str, Any]:
    """Check an attachment hash against VirusTotal file reputation."""
    if not file_hash:
        return _vt_mock_result(filename or "attachment", "missing_hash")
    if not VIRUSTOTAL_API_KEY:
        return _vt_mock_result(file_hash, "no_api_key")

    headers = {"x-apikey": VIRUSTOTAL_API_KEY, "accept": "application/json"}
    try:
        resp = requests.get(
            f"{VT_BASE_URL}/files/{file_hash}",
            headers=headers,
            timeout=15
        )
        if resp.status_code != 200:
            return _vt_mock_result(file_hash, f"http_{resp.status_code}")

        data = resp.json().get("data", {}).get("attributes", {})
        stats = data.get("last_analysis_stats", {})
        return {
            "source": "virustotal",
            "ioc": file_hash,
            "filename": filename,
            "type": "file",
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "total": sum(stats.values()),
            "reputation": data.get("reputation", 0),
            "meaningful_name": data.get("meaningful_name", filename),
            "status": "success",
            "vendors": {
                k: v["result"]
                for k, v in data.get("last_analysis_results", {}).items()
                if v.get("category") in ("malicious", "suspicious")
            }
        }
    except requests.RequestException as e:
        logger.error(f"VirusTotal file hash error for {filename or file_hash}: {e}")
        return _vt_mock_result(file_hash, "connection_error")


# ─────────────────────────────────────────────────────────────
#  URLSCAN.IO FUNCTIONS
# ─────────────────────────────────────────────────────────────

def urlscan_submit(url: str) -> Dict[str, Any]:
    """
    Submit a URL to URLScan.io for scanning.
    Returns scan UUID and result link.
    """
    if not URLSCAN_API_KEY:
        logger.warning("URLScan.io API key not configured — skipping")
        return _urlscan_mock_result(url, "no_api_key")

    headers = {
        "API-Key": URLSCAN_API_KEY,
        "Content-Type": "application/json"
    }

    sanitized_url = sanitize_url_for_api(url)

    try:
        # Submit URL
        resp = requests.post(
            f"{URLSCAN_BASE_URL}/scan/",
            headers=headers,
            json={"url": sanitized_url, "visibility": "private"},
            timeout=15
        )

        if resp.status_code not in (200, 201):
            return _urlscan_mock_result(url, f"http_{resp.status_code}")

        data = resp.json()
        scan_id = data.get("uuid", "")
        result_url = data.get("result", "")

        # Wait for scan to complete
        logger.info(f"URLScan submitted: {scan_id} — waiting 10s for results...")
        time.sleep(10)

        # Fetch results
        result_resp = requests.get(
            f"{URLSCAN_BASE_URL}/result/{scan_id}/",
            timeout=15
        )

        if result_resp.status_code == 200:
            result = result_resp.json()
            verdict = result.get("verdicts", {}).get("overall", {})
            page    = result.get("page", {})
            return {
                "source":       "urlscan",
                "ioc":          url,
                "type":         "url",
                "scan_id":      scan_id,
                "result_url":   result_url,
                "malicious":    verdict.get("malicious", False),
                "score":        verdict.get("score", 0),
                "brands":       verdict.get("brands", []),
                "categories":   verdict.get("categories", []),
                "country":      page.get("country", ""),
                "server":       page.get("server", ""),
                "ip":           page.get("ip", ""),
                "screenshot":   f"https://urlscan.io/screenshots/{scan_id}.png",
                "status":       "success",
            }

        return _urlscan_mock_result(url, "result_not_ready")

    except requests.RequestException as e:
        logger.error(f"URLScan error for {url}: {e}")
        return _urlscan_mock_result(url, "connection_error")


# ─────────────────────────────────────────────────────────────
#  MAIN ENRICHMENT ORCHESTRATOR
# ─────────────────────────────────────────────────────────────

def enrich_iocs(iocs: dict) -> Dict[str, Any]:
    """
    Enrich all extracted IoCs using available threat intel APIs.
    Returns enrichment results dict.
    """
    logger.info("Starting threat intel enrichment...")
    results = {
        "url_results":    [],
        "domain_results": [],
        "attachment_results": [],
        "summary": {
            "total_checked": 0,
            "malicious":     0,
            "suspicious":    0,
            "clean":         0,
        }
    }

    # Enrich top 5 URLs (rate limit protection)
    urls_to_check = iocs.get("urls", [])[:5]
    for url in urls_to_check:
        logger.info(f"Checking URL: {url}")
        vt_result  = vt_check_url(url)
        url_result = {"url": url, "virustotal": vt_result}

        # URLScan is the dedicated URL scanning source. Limit count to protect
        # the 60-second demo SLA and free-tier rate limits.
        if urls_to_check.index(url) < URLSCAN_MAX_URLS:
            url_result["urlscan"] = urlscan_submit(url)

        results["url_results"].append(url_result)
        _update_summary(results["summary"], vt_result)
        time.sleep(0.5)  # Rate limiting

    # Enrich sender domain + top 3 other domains
    domains_to_check = list(dict.fromkeys(
        [iocs.get("sender_domain", "")] +
        [d for d in iocs.get("domains", []) if d != iocs.get("sender_domain")]
    ))
    domains_to_check = [d for d in domains_to_check if d][:4]

    for domain in domains_to_check:
        logger.info(f"Checking domain: {domain}")
        vt_result = vt_check_domain(domain)
        results["domain_results"].append({"domain": domain, "virustotal": vt_result})
        _update_summary(results["summary"], vt_result)
        time.sleep(0.5)

    for att in iocs.get("attachments", [])[:5]:
        file_hash = att.get("sha256") or att.get("md5")
        filename = att.get("filename", "attachment")
        logger.info(f"Checking attachment hash with VT: {filename}")
        vt_result = vt_check_file_hash(file_hash, filename)
        results["attachment_results"].append({
            "filename": filename,
            "sha256": att.get("sha256", ""),
            "md5": att.get("md5", ""),
            "virustotal": vt_result,
        })
        _update_summary(results["summary"], vt_result)
        time.sleep(0.5)

    # Perform Sender Cryptographic Trust & Verification Checks
    sender_domain = iocs.get("sender_domain", "")
    if sender_domain:
        logger.info(f"Performing sender authenticity validation for: {sender_domain}")
        try:
            results["sender_trust"] = analyze_sender_trust(sender_domain)
        except Exception as e:
            logger.error(f"Sender trust validation failed: {e}", exc_info=True)
            results["sender_trust"] = {
                "domain": sender_domain,
                "trust_score": 0,
                "trust_level": "ERROR",
                "risk_flags": [f"Analysis error: {str(e)[:100]}"],
                "checks": {}
            }
    else:
        results["sender_trust"] = None

    logger.info(
        f"Enrichment complete — "
        f"Malicious: {results['summary']['malicious']}, "
        f"Suspicious: {results['summary']['suspicious']}, "
        f"Clean: {results['summary']['clean']}"
    )
    return results


def _update_summary(summary: dict, vt_result: dict):
    """Update running summary counts."""
    summary["total_checked"] += 1
    mal = vt_result.get("malicious", 0)
    sus = vt_result.get("suspicious", 0)
    if mal > 0:
        summary["malicious"] += 1
    elif sus > 0:
        summary["suspicious"] += 1
    else:
        summary["clean"] += 1


def _vt_mock_result(ioc: str, reason: str) -> Dict[str, Any]:
    """Return a structured mock result when VT API is unavailable."""
    if reason == "no_api_key":
        note = "Add VIRUSTOTAL_API_KEY to .env for real results"
    elif str(reason).startswith("http_429"):
        note = "VirusTotal rate limit/quota reached; result treated as inconclusive"
    else:
        note = f"VirusTotal lookup unavailable: {reason}"
    return {
        "source":     "virustotal",
        "ioc":        ioc,
        "type":       "unknown",
        "malicious":  0,
        "suspicious": 0,
        "harmless":   0,
        "undetected": 0,
        "total":      0,
        "status":     f"skipped:{reason}",
        "note":       note
    }


def _urlscan_mock_result(url: str, reason: str) -> Dict[str, Any]:
    """Return a structured mock result when URLScan API is unavailable."""
    return {
        "source":    "urlscan",
        "ioc":       url,
        "type":      "url",
        "malicious": False,
        "score":     0,
        "status":    f"skipped:{reason}",
        "note":      "Add URLSCAN_API_KEY to .env for real results"
    }
