"""
Certificate & Email Authentication Checker
===========================================
Checks sender domain trustworthiness via:
  1. SSL/TLS Certificate — validity, issuer, expiry, SANs
  2. SPF  — Sender Policy Framework (DNS TXT)
  3. DKIM — DomainKeys Identified Mail (DNS TXT)
  4. DMARC — Domain-based Message Authentication (DNS TXT)
  5. MX   — Mail Exchange records exist?

Person 3 Role: Threat intel enrichment
MITRE ATT&CK: T1566 - Phishing (authentication bypass)
"""

import ssl
import socket
import logging
import datetime
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

# Common DKIM selectors to try
DKIM_SELECTORS = ["default", "google", "mail", "smtp", "dkim", "s1", "s2", "k1"]


# ─────────────────────────────────────────────────────────────
# TLS / SSL CERTIFICATE CHECK
# ─────────────────────────────────────────────────────────────

def check_tls_certificate(domain: str) -> Dict[str, Any]:
    """
    Connect to domain:443 and inspect the TLS certificate.
    Returns certificate details: issuer, validity, SANs, self-signed flag.
    """
    result = {
        "domain":       domain,
        "check":        "tls_certificate",
        "tls_enabled":  False,
        "cert_valid":   False,
        "self_signed":  False,
        "expired":      False,
        "days_remaining": 0,
        "issuer":       "",
        "subject_cn":   "",
        "not_before":   "",
        "not_after":    "",
        "san_domains":  [],
        "error":        "",
        "risk":         "UNKNOWN",
    }

    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode    = ssl.CERT_REQUIRED

        with socket.create_connection((domain, 443), timeout=8) as raw_sock:
            with ctx.wrap_socket(raw_sock, server_hostname=domain) as tls_sock:
                cert = tls_sock.getpeercert()

        # Parse subject / issuer
        subject = dict(x[0] for x in cert.get("subject", []))
        issuer  = dict(x[0] for x in cert.get("issuer",  []))

        subject_cn  = subject.get("commonName", "")
        issuer_org  = issuer.get("organizationName", "")
        issuer_cn   = issuer.get("commonName", "")

        # Validity dates
        not_before_str = cert.get("notBefore", "")
        not_after_str  = cert.get("notAfter",  "")

        not_after_dt = datetime.datetime.strptime(
            not_after_str, "%b %d %H:%M:%S %Y %Z"
        ) if not_after_str else None

        now = datetime.datetime.utcnow()
        expired = not_after_dt < now if not_after_dt else False
        days_remaining = int((not_after_dt - now).days) if (not_after_dt and not expired) else 0

        # SANs
        san_list = [v for t, v in cert.get("subjectAltName", []) if t == "DNS"]

        # Self-signed: issuer == subject
        self_signed = (issuer_cn == subject_cn) or (issuer_org in ["", subject_cn])

        result.update({
            "tls_enabled":    True,
            "cert_valid":     True,
            "self_signed":    self_signed,
            "expired":        expired,
            "days_remaining": days_remaining,
            "issuer":         issuer_org or issuer_cn,
            "subject_cn":     subject_cn,
            "not_before":     not_before_str,
            "not_after":      not_after_str,
            "san_domains":    san_list[:10],
        })

        # Risk assessment
        if expired:
            result["risk"] = "HIGH"
            result["error"] = "Certificate is EXPIRED"
        elif self_signed:
            result["risk"] = "HIGH"
            result["error"] = "Self-signed certificate — not trusted"
        elif days_remaining < 7:
            result["risk"] = "MEDIUM"
            result["error"] = f"Certificate expires in {days_remaining} days"
        elif domain not in san_list and f"*.{'.'.join(domain.split('.')[-2:])}" not in san_list:
            result["risk"] = "MEDIUM"
            result["error"] = f"Domain '{domain}' not in certificate SANs"
        else:
            result["risk"] = "LOW"

    except ssl.SSLCertVerificationError as e:
        result["tls_enabled"] = True
        result["cert_valid"]  = False
        result["risk"]        = "HIGH"
        result["error"]       = f"Certificate verification FAILED: {str(e)[:120]}"

    except ssl.SSLError as e:
        result["tls_enabled"] = True
        result["cert_valid"]  = False
        result["risk"]        = "HIGH"
        result["error"]       = f"SSL error: {str(e)[:120]}"

    except (socket.timeout, ConnectionRefusedError, OSError):
        # Domain doesn't have HTTPS at all — big red flag for a sender
        result["tls_enabled"] = False
        result["cert_valid"]  = False
        result["risk"]        = "HIGH"
        result["error"]       = "No HTTPS/TLS on port 443 — suspicious sender domain"

    except Exception as e:
        result["risk"]  = "UNKNOWN"
        result["error"] = str(e)[:120]

    logger.info(f"TLS check [{domain}]: risk={result['risk']} valid={result['cert_valid']} issuer='{result['issuer']}'")
    return result


# ─────────────────────────────────────────────────────────────
# DNS EMAIL AUTHENTICATION CHECKS
# ─────────────────────────────────────────────────────────────

def check_spf(domain: str) -> Dict[str, Any]:
    """
    Look up SPF TXT record for sender domain.
    SPF tells mail servers which IPs are allowed to send for this domain.
    """
    result = {
        "domain":   domain,
        "check":    "spf",
        "has_spf":  False,
        "record":   "",
        "policy":   "",
        "pass":     False,
        "risk":     "HIGH",
        "detail":   "",
    }
    try:
        import socket as _s
        # Use getaddrinfo as a lightweight DNS TXT lookup proxy
        # Use dnspython if available, else fallback
        try:
            import dns.resolver
            answers = dns.resolver.resolve(domain, "TXT", lifetime=5)
            for rdata in answers:
                txt = "".join(s.decode() if isinstance(s, bytes) else s
                              for s in rdata.strings)
                if txt.startswith("v=spf1"):
                    result["has_spf"] = True
                    result["record"]  = txt
                    # Extract policy: ~all, -all, +all, ?all
                    for token in txt.split():
                        if token.endswith("all"):
                            result["policy"] = token
                            result["pass"]   = token in ("+all", "~all")
                    result["risk"]   = "LOW" if result["pass"] else "HIGH"
                    result["detail"] = f"SPF policy: {result['policy']}"
                    return result
        except ImportError:
            pass

        result["has_spf"] = False
        result["risk"]    = "HIGH"
        result["detail"]  = "No SPF record — anyone can spoof this domain"

    except Exception as e:
        result["detail"] = f"DNS lookup failed: {str(e)[:80]}"
        result["risk"]   = "UNKNOWN"

    return result


def check_dmarc(domain: str) -> Dict[str, Any]:
    """
    Look up DMARC TXT record at _dmarc.<domain>.
    DMARC tells receivers what to do with failed SPF/DKIM emails.
    """
    result = {
        "domain":      domain,
        "check":       "dmarc",
        "has_dmarc":   False,
        "record":      "",
        "policy":      "",          # none / quarantine / reject
        "pct":         100,
        "risk":        "HIGH",
        "detail":      "",
    }
    try:
        import dns.resolver
        dmarc_domain = f"_dmarc.{domain}"
        answers = dns.resolver.resolve(dmarc_domain, "TXT", lifetime=5)
        for rdata in answers:
            txt = "".join(s.decode() if isinstance(s, bytes) else s
                          for s in rdata.strings)
            if "v=DMARC1" in txt:
                result["has_dmarc"] = True
                result["record"]    = txt

                # Extract policy
                for tag in txt.split(";"):
                    tag = tag.strip()
                    if tag.startswith("p="):
                        result["policy"] = tag[2:].lower()
                    elif tag.startswith("pct="):
                        try:
                            result["pct"] = int(tag[4:])
                        except ValueError:
                            pass

                policy = result["policy"]
                if policy == "reject":
                    result["risk"]   = "LOW"
                    result["detail"] = "DMARC: reject — unauthorized emails are rejected"
                elif policy == "quarantine":
                    result["risk"]   = "LOW"
                    result["detail"] = "DMARC: quarantine — unauthorized emails go to spam"
                else:
                    result["risk"]   = "MEDIUM"
                    result["detail"] = "DMARC: none — monitoring only, no enforcement"
                return result

        result["detail"] = "No DMARC record — domain is vulnerable to spoofing"

    except Exception as e:
        err = str(e)
        if "NXDOMAIN" in err or "NoAnswer" in err:
            result["detail"] = "No DMARC record found"
        else:
            result["detail"] = f"DNS error: {err[:80]}"
        result["risk"] = "HIGH"

    return result


def check_dkim(domain: str) -> Dict[str, Any]:
    """
    Attempt to find a DKIM public key by trying common selectors.
    DKIM proves email content hasn't been tampered with.
    """
    result = {
        "domain":    domain,
        "check":     "dkim",
        "has_dkim":  False,
        "selector":  "",
        "record":    "",
        "key_type":  "",
        "risk":      "HIGH",
        "detail":    "No DKIM record found (tried common selectors)",
    }
    try:
        import dns.resolver
        for selector in DKIM_SELECTORS:
            dkim_host = f"{selector}._domainkey.{domain}"
            try:
                answers = dns.resolver.resolve(dkim_host, "TXT", lifetime=3)
                for rdata in answers:
                    txt = "".join(s.decode() if isinstance(s, bytes) else s
                                  for s in rdata.strings)
                    if "p=" in txt:  # public key present
                        result["has_dkim"] = True
                        result["selector"] = selector
                        result["record"]   = txt[:200]
                        # Extract key type
                        for tag in txt.split(";"):
                            tag = tag.strip()
                            if tag.startswith("k="):
                                result["key_type"] = tag[2:]
                        result["risk"]   = "LOW"
                        result["detail"] = f"DKIM found (selector: {selector}, key: {result['key_type'] or 'rsa'})"
                        return result
            except Exception:
                continue  # Try next selector

    except ImportError:
        result["detail"] = "dnspython not installed — install with: pip install dnspython"
        result["risk"]   = "UNKNOWN"
    except Exception as e:
        result["detail"] = str(e)[:80]

    return result


def check_mx_records(domain: str) -> Dict[str, Any]:
    """
    Check if domain has MX (mail exchange) records.
    Legitimate senders always have MX records.
    """
    result = {
        "domain":  domain,
        "check":   "mx_records",
        "has_mx":  False,
        "records": [],
        "risk":    "HIGH",
        "detail":  "",
    }
    try:
        import dns.resolver
        answers = dns.resolver.resolve(domain, "MX", lifetime=5)
        mx_list = sorted(
            [(r.preference, str(r.exchange).rstrip(".")) for r in answers],
            key=lambda x: x[0]
        )
        result["has_mx"]  = True
        result["records"] = [{"priority": p, "host": h} for p, h in mx_list]
        result["risk"]    = "LOW"
        result["detail"]  = f"{len(mx_list)} MX record(s): {', '.join(h for _, h in mx_list[:3])}"
    except Exception as e:
        err = str(e)
        if "NXDOMAIN" in err or "NoAnswer" in err:
            result["detail"] = "No MX records — domain cannot receive email (likely spoofed)"
        else:
            result["detail"] = f"MX lookup failed: {err[:80]}"

    return result


# ─────────────────────────────────────────────────────────────
# MASTER SENDER TRUST CHECK
# ─────────────────────────────────────────────────────────────

def analyze_sender_trust(sender_domain: str) -> Dict[str, Any]:
    """
    Run all checks on the sender domain and return a combined trust report.
    Called with ONLY the sender domain string — nothing else is sent to DNS.
    """
    if not sender_domain:
        return {"error": "No sender domain provided", "trust_score": 0, "trust_level": "UNKNOWN"}

    logger.info(f"Analyzing sender trust for domain: {sender_domain}")

    tls   = check_tls_certificate(sender_domain)
    spf   = check_spf(sender_domain)
    dmarc = check_dmarc(sender_domain)
    dkim  = check_dkim(sender_domain)
    mx    = check_mx_records(sender_domain)

    # ── Trust scoring ──────────────────────────────────────────
    score = 100  # Start at 100, deduct for failures

    risk_flags = []

    # TLS (−30 if no valid cert)
    if not tls["cert_valid"]:
        score -= 30
        risk_flags.append(f"TLS FAIL: {tls['error']}")
    elif tls["self_signed"]:
        score -= 20
        risk_flags.append("Self-signed certificate")
    elif tls["expired"]:
        score -= 25
        risk_flags.append("Certificate EXPIRED")

    # SPF (−25 if missing)
    if not spf["has_spf"]:
        score -= 25
        risk_flags.append("No SPF record — domain can be spoofed")

    # DMARC (−20 if missing, −10 if 'none')
    if not dmarc["has_dmarc"]:
        score -= 20
        risk_flags.append("No DMARC record")
    elif dmarc["policy"] == "none":
        score -= 10
        risk_flags.append("DMARC policy=none (no enforcement)")

    # DKIM (−15 if missing)
    if not dkim["has_dkim"]:
        score -= 15
        risk_flags.append("No DKIM record found")

    # MX (−10 if missing)
    if not mx["has_mx"]:
        score -= 10
        risk_flags.append("No MX records — cannot receive email")

    score = max(0, score)

    if score >= 75:
        trust_level = "TRUSTED"
    elif score >= 50:
        trust_level = "SUSPICIOUS"
    elif score >= 25:
        trust_level = "UNTRUSTED"
    else:
        trust_level = "SPOOFED"

    report = {
        "domain":      sender_domain,
        "trust_score": score,
        "trust_level": trust_level,
        "risk_flags":  risk_flags,
        "checks": {
            "tls":   tls,
            "spf":   spf,
            "dmarc": dmarc,
            "dkim":  dkim,
            "mx":    mx,
        }
    }

    logger.info(
        f"Sender trust [{sender_domain}]: "
        f"score={score}/100 level={trust_level} flags={len(risk_flags)}"
    )
    return report
