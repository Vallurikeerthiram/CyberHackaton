"""
Report & Ticket Generator
==========================
Generates structured response artifacts:
1. JSON incident ticket (machine-readable)
2. HTML report with MITRE ATT&CK visualization

Person 5 Role: Ticketing + report generation
"""

import os
import json
import uuid
import logging
from typing import Dict
from datetime import datetime, timezone
from jinja2 import Template

logger = logging.getLogger(__name__)

REPORTS_DIR = os.path.join(os.path.dirname(__file__), "reports")


def generate_report(
    email_data:   dict,
    iocs:         dict,
    enrichment:   dict,
    triage:       dict,
    response_log: dict,
    elapsed_sec:  float = 0.0,
    gemma_advisory: str = ""
) -> Dict:
    """
    Generate both JSON ticket and HTML report.
    Returns dict with paths to generated files.
    """
    os.makedirs(REPORTS_DIR, exist_ok=True)

    # Build incident ticket
    ticket = _build_ticket(email_data, iocs, enrichment, triage, response_log, elapsed_sec, gemma_advisory)

    # Save JSON ticket
    ticket_filename = f"ticket_{ticket['ticket_id']}.json"
    ticket_path = os.path.join(REPORTS_DIR, ticket_filename)
    with open(ticket_path, "w", encoding="utf-8") as f:
        json.dump(ticket, f, indent=2, ensure_ascii=False)
    logger.info(f"JSON ticket saved: {ticket_path}")

    # Generate HTML report
    html_filename = f"report_{ticket['ticket_id']}.html"
    html_path = os.path.join(REPORTS_DIR, html_filename)
    html_content = _render_html_report(ticket)
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html_content)
    logger.info(f"HTML report saved: {html_path}")

    return {
        "ticket":       ticket,
        "ticket_path":  ticket_path,
        "html_path":    html_path,
        "ticket_id":    ticket["ticket_id"],
    }


def _build_ticket(email_data, iocs, enrichment, triage, response_log, elapsed_sec, gemma_advisory):
    """Build structured JSON incident ticket."""
    ticket_id = f"SOAR-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{str(uuid.uuid4())[:8].upper()}"

    return {
        "ticket_id":    ticket_id,
        "created_at":   datetime.now(timezone.utc).isoformat(),
        "severity":     _verdict_to_severity(triage.get("verdict", "CLEAN")),
        "status":       "RESOLVED" if triage.get("verdict") == "MALICIOUS" else "OPEN",
        "elapsed_sec":  round(elapsed_sec, 2),
        "within_sla":   elapsed_sec <= 60,

        "email": {
            "id":       email_data.get("id", ""),
            "subject":  email_data.get("subject", ""),
            "sender":   email_data.get("from", ""),
            "to":       email_data.get("to", ""),
            "date":     email_data.get("date", ""),
        },

        "iocs": {
            "urls":             iocs.get("urls", [])[:10],
            "domains":          iocs.get("domains", [])[:10],
            "sender_domain":    iocs.get("sender_domain", ""),
            "attachments":      iocs.get("attachments", []),
            "keywords_found":   iocs.get("keywords_found", []),
            "risk_indicators":  iocs.get("risk_indicators", []),
            "header_anomalies": iocs.get("header_anomalies", []),
        },

        "enrichment_summary": enrichment.get("summary", {}),
        "threat_intel": {
            "url_results": enrichment.get("url_results", []),
            "domain_results": enrichment.get("domain_results", []),
            "attachment_results": enrichment.get("attachment_results", []),
        },
        "sender_trust": enrichment.get("sender_trust"),

        "triage": {
            "verdict":    triage.get("verdict", ""),
            "score":      triage.get("score", 0),
            "action":     triage.get("action", ""),
            "reasons":    triage.get("reasons", []),
            "mitre_tags": triage.get("mitre_tags", []),
        },

        "response": {
            "actions_taken": response_log.get("actions_taken", []),
            "quarantined":   "email_quarantined" in response_log.get("actions_taken", []),
            "blocked":       "iocs_blocked"       in response_log.get("actions_taken", []),
            "notified":      True,
        },

        "gemma_advisory": gemma_advisory,

        "playbook": {
            "name":    "SOAR-Phishing-Response-v1",
            "version": "1.0.0",
            "team":    "FoSC 23CSE313 Hackathon",
        }
    }


def _verdict_to_severity(verdict: str) -> str:
    return {"MALICIOUS": "CRITICAL", "SUSPICIOUS": "HIGH", "CLEAN": "LOW"}.get(verdict, "UNKNOWN")


def _render_html_report(ticket: dict) -> str:
    """Render full HTML report from ticket data."""
    triage  = ticket["triage"]
    iocs    = ticket["iocs"]
    email   = ticket["email"]
    resp    = ticket["response"]
    verdict = triage["verdict"]

    verdict_colors = {
        "MALICIOUS":  ("#ef4444", "#fef2f2", "🔴"),
        "SUSPICIOUS": ("#f59e0b", "#fffbeb", "🟡"),
        "CLEAN":      ("#10b981", "#f0fdf4", "🟢"),
    }
    vcolor, vbg, vemoji = verdict_colors.get(verdict, ("#6b7280", "#f9fafb", "⚪"))

    mitre_html = ""
    for tag in triage.get("mitre_tags", []):
        mitre_html += f'''
        <span class="mitre-tag">
            <span class="mitre-id">{tag["id"]}</span>
            <span class="mitre-name">{tag["name"]}</span>
        </span>'''

    url_rows = ""
    for url_result in ticket.get("enrichment_summary", {}).get("url_results_preview", []):
        pass  # simplified

    ioc_url_rows = ""
    for url in iocs.get("urls", [])[:8]:
        ioc_url_rows += f'<tr><td class="ioc-type">URL</td><td class="ioc-value">{url[:80]}</td></tr>'

    for domain in iocs.get("domains", [])[:5]:
        ioc_url_rows += f'<tr><td class="ioc-type">Domain</td><td class="ioc-value">{domain}</td></tr>'

    reason_items = ""
    for reason in triage.get("reasons", []):
        reason_items += f'<li class="reason-item">⚠️ {reason}</li>'

    action_badges = ""
    if resp.get("quarantined"):
        action_badges += '<span class="badge badge-quarantine">✅ Email Quarantined</span>'
    if resp.get("blocked"):
        action_badges += '<span class="badge badge-block">🚫 IoCs Blocked</span>'
    if resp.get("notified"):
        action_badges += '<span class="badge badge-notify">📢 Alert Sent</span>'

    keyword_pills = ""
    for kw in iocs.get("keywords_found", []):
        keyword_pills += f'<span class="keyword-pill">{kw}</span>'

    threat_intel = ticket.get("threat_intel", {})
    intel_rows = ""
    for item in threat_intel.get("url_results", [])[:6]:
        vt = item.get("virustotal", {})
        us = item.get("urlscan", {})
        intel_rows += (
            f'<tr><td class="ioc-type">URL</td><td class="ioc-value">{item.get("url", "")[:90]}</td>'
            f'<td>VT: {vt.get("malicious", 0)} malicious / {vt.get("suspicious", 0)} suspicious</td>'
            f'<td>URLScan: {"MALICIOUS" if us.get("malicious") else us.get("status", "not scanned")}</td></tr>'
        )
    for item in threat_intel.get("attachment_results", [])[:6]:
        vt = item.get("virustotal", {})
        intel_rows += (
            f'<tr><td class="ioc-type">Attachment</td><td class="ioc-value">{item.get("filename", "attachment")}</td>'
            f'<td>VT: {vt.get("malicious", 0)} malicious / {vt.get("suspicious", 0)} suspicious</td>'
            f'<td>SHA256: {(item.get("sha256") or "not available")[:24]}</td></tr>'
        )

    # Perform Sender Cryptographic Trust & Verification Checks
    sender_trust = ticket.get("sender_trust")
    sender_trust_html = ""
    if sender_trust:
        trust_score = sender_trust.get("trust_score", 100)
        trust_level = sender_trust.get("trust_level", "TRUSTED")
        checks = sender_trust.get("checks", {})

        tls = checks.get("tls", {})
        spf = checks.get("spf", {})
        dkim = checks.get("dkim", {})
        dmarc = checks.get("dmarc", {})
        mx = checks.get("mx", {})

        def get_status_badge(passed, label):
            if passed:
                return f'<span class="badge badge-notify" style="margin:2px; background:#10b98120; border:1px solid #10b981; color:#34d399">✓ {label}</span>'
            else:
                return f'<span class="badge badge-block" style="margin:2px; background:#ef444420; border:1px solid #ef4444; color:#f87171">✗ {label}</span>'

        tls_badge = get_status_badge(tls.get("cert_valid", False), "TLS Certificate Valid")
        spf_badge = get_status_badge(spf.get("has_spf", False), "SPF")
        dkim_badge = get_status_badge(dkim.get("has_dkim", False), "DKIM")
        dmarc_badge = get_status_badge(dmarc.get("has_dmarc", False), "DMARC")
        mx_badge = get_status_badge(mx.get("has_mx", False), "MX Records")

        trust_colors = {
            "TRUSTED": "#10b981",
            "SUSPICIOUS": "#f59e0b",
            "UNTRUSTED": "#ef4444",
            "SPOOFED": "#ef4444",
            "ERROR": "#6b7280"
        }
        tcolor = trust_colors.get(trust_level, "#6b7280")

        sender_trust_html = f'''
    <div class="card full-width">
      <h2>🔒 Sender Authenticity & Cryptographic Verification</h2>
      <div style="display: flex; gap: 2rem; align-items: center; margin-bottom: 1rem; flex-wrap: wrap;">
        <div style="text-align: center; border: 1px solid var(--border); padding: 1rem; border-radius: 12px; min-width: 150px; background: rgba(99, 102, 241, 0.05);">
          <div style="font-size: 0.75rem; text-transform: uppercase; color: var(--text-muted);">Trust Score</div>
          <div style="font-size: 2.2rem; font-weight: 800; color: {tcolor};">{trust_score}/100</div>
          <div style="font-size: 0.85rem; font-weight: 600; color: {tcolor};">{trust_level}</div>
        </div>
        <div style="flex: 1; min-width: 250px;">
          <div style="margin-bottom: 0.5rem; font-size: 0.85rem; font-weight: 600; color: var(--text);">Authentication Badges:</div>
          <div>
            {tls_badge} {spf_badge} {dkim_badge} {dmarc_badge} {mx_badge}
          </div>
        </div>
      </div>
      <table style="font-size: 0.8rem; margin-top: 1rem;">
        <thead><tr><th>Check</th><th>Result / Details</th><th>Status</th></tr></thead>
        <tbody>
          <tr>
            <td><strong>SSL/TLS Certificate</strong></td>
            <td>CN: <code>{tls.get("subject_cn") or "None"}</code> | Issuer: <code>{tls.get("issuer") or "None"}</code> | Days Left: <code>{tls.get("days_remaining", 0)}</code></td>
            <td><span style="color:{'#34d399' if tls.get('cert_valid') else '#f87171'}">{'VALID' if tls.get('cert_valid') else 'INVALID/NONE'}</span></td>
          </tr>
          <tr>
            <td><strong>SPF (Sender Policy Framework)</strong></td>
            <td>Record: <code>{spf.get("record") or "None"}</code> | Policy: <code>{spf.get("policy") or "None"}</code></td>
            <td><span style="color:{'#34d399' if spf.get('has_spf') else '#f87171'}">{'PASS' if spf.get('has_spf') else 'FAIL'}</span></td>
          </tr>
          <tr>
            <td><strong>DKIM (DomainKeys Mail)</strong></td>
            <td>Selector tried: <code>{dkim.get("selector") or "None"}</code> | Key: <code>{dkim.get("key_type") or "None"}</code></td>
            <td><span style="color:{'#34d399' if dkim.get('has_dkim') else '#f87171'}">{'PASS' if dkim.get('has_dkim') else 'FAIL'}</span></td>
          </tr>
          <tr>
            <td><strong>DMARC (Domain Reporting)</strong></td>
            <td>Record: <code>{dmarc.get("record") or "None"}</code> | Policy: <code>{dmarc.get("policy") or "None"}</code></td>
            <td><span style="color:{'#34d399' if dmarc.get('has_dmarc') else '#f87171'}">{'PASS' if dmarc.get('has_dmarc') else 'FAIL'}</span></td>
          </tr>
          <tr>
            <td><strong>MX (Mail Exchange Records)</strong></td>
            <td>Details: <code>{mx.get("detail") or "None"}</code></td>
            <td><span style="color:{'#34d399' if mx.get('has_mx') else '#f87171'}">{'PASS' if mx.get('has_mx') else 'FAIL'}</span></td>
          </tr>
        </tbody>
      </table>
    </div>
    '''

    gemma_advisory = ticket.get("gemma_advisory", "")
    gemma_advisory_html = ""
    if gemma_advisory:
        gemma_advisory_html = f'''
    <div class="card full-width" style="border-left: 4px solid var(--accent); background: linear-gradient(135deg, rgba(99, 102, 241, 0.04) 0%, var(--surface) 100%);">
      <h2 style="color: #a5b4fc; display: flex; align-items: center; gap: 0.5rem;">Security Advisor</h2>
      <div style="font-size: 0.88rem; line-height: 1.6; color: var(--text); white-space: pre-wrap; font-family: 'Inter', sans-serif;">{gemma_advisory}</div>
    </div>
    '''

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SOAR Incident Report — {ticket['ticket_id']}</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');
  :root {{
    --bg: #0f1117; --surface: #1a1d27; --surface2: #21253a;
    --border: #2d3347; --text: #e2e8f0; --text-muted: #8892a4;
    --accent: #6366f1; --danger: #ef4444; --warning: #f59e0b; --success: #10b981;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--text); font-family: 'Inter', sans-serif; line-height: 1.6; }}
  .container {{ max-width: 1100px; margin: 0 auto; padding: 2rem; }}
  .header {{ display: flex; align-items: center; justify-content: space-between; margin-bottom: 2rem; padding: 1.5rem 2rem; background: var(--surface); border-radius: 16px; border: 1px solid var(--border); }}
  .logo {{ display: flex; align-items: center; gap: 1rem; }}
  .logo-icon {{ width: 48px; height: 48px; background: linear-gradient(135deg, #6366f1, #8b5cf6); border-radius: 12px; display: flex; align-items: center; justify-content: center; font-size: 1.5rem; }}
  .logo-text h1 {{ font-size: 1.25rem; font-weight: 700; }}
  .logo-text p {{ color: var(--text-muted); font-size: 0.8rem; }}
  .ticket-meta {{ text-align: right; }}
  .ticket-id {{ font-family: 'JetBrains Mono', monospace; font-size: 0.85rem; color: var(--accent); font-weight: 600; }}
  .verdict-card {{ padding: 2rem; border-radius: 16px; border: 2px solid {vcolor}; background: linear-gradient(135deg, {vbg}15, {vbg}05); margin-bottom: 2rem; display: flex; align-items: center; gap: 2rem; }}
  .verdict-emoji {{ font-size: 3.5rem; }}
  .verdict-label {{ font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.1em; color: var(--text-muted); margin-bottom: 0.25rem; }}
  .verdict-text {{ font-size: 2.5rem; font-weight: 800; color: {vcolor}; }}
  .verdict-score {{ font-size: 1rem; color: var(--text-muted); }}
  .verdict-action {{ margin-left: auto; padding: 0.75rem 1.5rem; background: {vcolor}20; border: 1px solid {vcolor}; border-radius: 10px; font-weight: 600; color: {vcolor}; font-size: 0.9rem; }}
  .grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem; margin-bottom: 1.5rem; }}
  .card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 16px; padding: 1.5rem; }}
  .card h2 {{ font-size: 0.95rem; text-transform: uppercase; letter-spacing: 0.08em; color: var(--text-muted); margin-bottom: 1rem; display: flex; align-items: center; gap: 0.5rem; }}
  .field {{ margin-bottom: 0.75rem; }}
  .field label {{ display: block; font-size: 0.75rem; color: var(--text-muted); margin-bottom: 0.2rem; text-transform: uppercase; letter-spacing: 0.05em; }}
  .field value {{ display: block; font-size: 0.9rem; word-break: break-all; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.85rem; }}
  th {{ text-align: left; padding: 0.6rem 0.75rem; color: var(--text-muted); font-size: 0.75rem; text-transform: uppercase; border-bottom: 1px solid var(--border); }}
  td {{ padding: 0.6rem 0.75rem; border-bottom: 1px solid var(--border)20; }}
  .ioc-type {{ font-family: 'JetBrains Mono', monospace; background: var(--surface2); border-radius: 4px; padding: 0.2rem 0.5rem; font-size: 0.75rem; color: var(--accent); }}
  .ioc-value {{ font-family: 'JetBrains Mono', monospace; font-size: 0.78rem; color: var(--text); max-width: 600px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
  .mitre-tags {{ display: flex; flex-wrap: wrap; gap: 0.5rem; }}
  .mitre-tag {{ display: flex; align-items: center; gap: 0.4rem; padding: 0.4rem 0.75rem; background: #6366f120; border: 1px solid #6366f140; border-radius: 8px; }}
  .mitre-id {{ font-family: 'JetBrains Mono', monospace; font-size: 0.8rem; color: #818cf8; font-weight: 600; }}
  .mitre-name {{ font-size: 0.8rem; color: var(--text-muted); }}
  .reasons-list {{ list-style: none; }}
  .reason-item {{ padding: 0.5rem 0; border-bottom: 1px solid var(--border)30; font-size: 0.85rem; color: var(--text-muted); }}
  .reason-item:last-child {{ border: none; }}
  .badge {{ display: inline-block; padding: 0.4rem 0.9rem; border-radius: 20px; font-size: 0.8rem; font-weight: 600; margin-right: 0.5rem; margin-bottom: 0.5rem; }}
  .badge-quarantine {{ background: #6366f120; border: 1px solid #6366f1; color: #818cf8; }}
  .badge-block {{ background: #ef444420; border: 1px solid #ef4444; color: #f87171; }}
  .badge-notify {{ background: #10b98120; border: 1px solid #10b981; color: #34d399; }}
  .keyword-pill {{ display: inline-block; padding: 0.2rem 0.6rem; background: var(--surface2); border: 1px solid var(--border); border-radius: 12px; font-size: 0.75rem; color: var(--text-muted); margin: 0.2rem; }}
  .sla-badge {{ display: inline-flex; align-items: center; gap: 0.4rem; padding: 0.4rem 0.9rem; border-radius: 20px; font-size: 0.85rem; font-weight: 600; }}
  .sla-ok {{ background: #10b98120; border: 1px solid #10b981; color: #34d399; }}
  .sla-fail {{ background: #ef444420; border: 1px solid #ef4444; color: #f87171; }}
  .footer {{ text-align: center; padding: 2rem; color: var(--text-muted); font-size: 0.8rem; margin-top: 2rem; }}
  .full-width {{ grid-column: 1 / -1; }}
  @media (max-width: 768px) {{ .grid {{ grid-template-columns: 1fr; }} .header {{ flex-direction: column; gap: 1rem; text-align: center; }} .verdict-card {{ flex-direction: column; text-align: center; }} .verdict-action {{ margin-left: 0; }} }}
</style>
</head>
<body>
<div class="container">

  <!-- Header -->
  <div class="header">
    <div class="logo">
      <div class="logo-icon">🛡️</div>
      <div class="logo-text">
        <h1>SOAR Phishing Response</h1>
        <p>Security Orchestration, Automation & Response</p>
      </div>
    </div>
    <div class="ticket-meta">
      <div class="ticket-id">{ticket['ticket_id']}</div>
      <div style="font-size:0.8rem;color:var(--text-muted)">Generated {ticket['created_at'][:19]} UTC</div>
      <div style="margin-top:0.3rem">
        <span class="sla-badge {'sla-ok' if ticket['within_sla'] else 'sla-fail'}">
          {'✅ SLA Met' if ticket['within_sla'] else '❌ SLA Breached'} ({ticket['elapsed_sec']}s / 60s)
        </span>
      </div>
    </div>
  </div>

  <!-- Verdict Banner -->
  <div class="verdict-card">
    <div class="verdict-emoji">{vemoji}</div>
    <div>
      <div class="verdict-label">Triage Verdict</div>
      <div class="verdict-text">{verdict}</div>
      <div class="verdict-score">Threat Score: {triage['score']}/100 &nbsp;•&nbsp; Severity: {ticket['severity']}</div>
    </div>
    <div class="verdict-action">{triage['action']}</div>
  </div>

  <div class="grid">
    {sender_trust_html}
    {gemma_advisory_html}
    <!-- Email Info -->
    <div class="card">
      <h2>📧 Email Details</h2>
      <div class="field"><label>Subject</label><value>{email['subject'] or 'N/A'}</value></div>
      <div class="field"><label>From</label><value>{email['sender'] or 'N/A'}</value></div>
      <div class="field"><label>To</label><value>{email['to'] or 'N/A'}</value></div>
      <div class="field"><label>Date</label><value>{email['date'] or 'N/A'}</value></div>
    </div>

    <!-- Response Actions -->
    <div class="card">
      <h2>⚡ Response Actions</h2>
      <div style="margin-bottom:1rem">{action_badges}</div>
      <div class="field"><label>Actions Taken</label><value>{', '.join(resp.get('actions_taken', ['none'])) or 'No action required'}</value></div>
      <div class="field"><label>Quarantined</label><value>{'Yes ✅' if resp.get('quarantined') else 'No'}</value></div>
      <div class="field"><label>IoCs Blocked</label><value>{'Yes 🚫' if resp.get('blocked') else 'No'}</value></div>
    </div>

    <!-- MITRE ATT&CK -->
    <div class="card">
      <h2>🎯 MITRE ATT&CK Techniques</h2>
      <div class="mitre-tags">{mitre_html}</div>
    </div>

    <!-- Risk Indicators -->
    <div class="card">
      <h2>⚠️ Triage Reasons</h2>
      <ul class="reasons-list">
        {reason_items if reason_items else '<li class="reason-item">No risk indicators found</li>'}
      </ul>
    </div>

    <!-- IoC Table -->
    <div class="card full-width">
      <h2>🔍 Extracted IoCs</h2>
      <table>
        <thead><tr><th>Type</th><th>Indicator</th></tr></thead>
        <tbody>{ioc_url_rows if ioc_url_rows else '<tr><td colspan="2" style="text-align:center;color:var(--text-muted)">No IoCs extracted</td></tr>'}</tbody>
      </table>
    </div>

    <div class="card full-width">
      <h2>Threat Intel Evidence</h2>
      <table>
        <thead><tr><th>Type</th><th>Indicator</th><th>VirusTotal</th><th>URLScan / Hash</th></tr></thead>
        <tbody>{intel_rows if intel_rows else '<tr><td colspan="4" style="text-align:center;color:var(--text-muted)">No URL or attachment evidence checked</td></tr>'}</tbody>
      </table>
    </div>

    <!-- Keywords -->
    <div class="card full-width">
      <h2>🔑 Phishing Keywords Detected ({len(iocs.get('keywords_found', []))})</h2>
      <div>{keyword_pills if keyword_pills else '<span style="color:var(--text-muted);font-size:0.85rem">No phishing keywords detected</span>'}</div>
    </div>
  </div>

  <div class="footer">
    SOAR Phishing Response Playbook v1.0 &nbsp;•&nbsp; FoSC 23CSE313 Hackathon &nbsp;•&nbsp;
    MITRE ATT&CK® T1566 | T1598 &nbsp;•&nbsp; Processed in {ticket['elapsed_sec']}s
  </div>
</div>
</body>
</html>"""
