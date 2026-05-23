# 🛡️ SOAR Phishing Playbook — Hackathon 2026 Rubric Response Guide

This document maps the **SOAR Secure Mail Client** implementation details directly to the official Hackathon evaluation rubrics to prepare the team for final evaluations, judge demonstrations, and Q&A sessions.

---

## 💻 1. Technical Implementation (10 Marks)

### Core Functionality
- **Multi-Source Ingestion**: The system fetches emails in real-time using secure APIs (**Google Gmail API via OAuth 2.0** and **Microsoft Graph API via OAuth**). It caches the latest 25 messages locally in an SQLite database.
- **Parsing & IoC Extraction**: Extracts links, domain names, file attachments, and metadata, and filters out benign HTML resource URLs (like Google Fonts or W3 namespaces) to prevent false alerts.
- **Threat Intelligence Enrichment**: Enriches IoCs by calling SaaS endpoints (**VirusTotal v3** and **URLScan.io**). Attachment files are hashed (SHA-256/MD5) and checked against VirusTotal malware lists.
- **Triage Decision Engine**: Scores emails from 0 to 100 based on API results, keyword density, and sender SPF/DKIM flags.
- **Automated Responses**: Malicious emails are moved to the spam folder (quarantine) via email APIs, their URLs are blocked locally in `blocklist.txt` (simulating proxy blocks), and alert notifications are dispatched.
- **Report & Advisory Generation**: Local **Gemma** (`gemma4:e2b`) generates text warnings shown in the reading pane, while the engine saves formal JSON and HTML incident tickets.

### Implementation Correctness
- **Thread Safety**: All backend calls, including OAuth requests and continuous inbox checking, run in a background daemon thread synchronized with a `threading.Lock`. This prevents UI thread freezes.
- **Database Consistency**: SQLite tables handle concurrent writes cleanly using `ON CONFLICT DO UPDATE` migrations.

### Complexity
- **Hybrid Security Ingestion**: Merges cloud-hosted security feeds with a local LLM inference backend.
- **Cryptographic Sender Check**: Parses domains to perform public DNS lookups for SPF, DKIM, and DMARC alignments via `cert_checker.py`.

### Code Quality & Engineering Practices
- **Modular Project Structure**:
  - `server.py` (Flask REST Backend & Asset Server)
  - `main.py` (Orchestrator)
  - `db_manager.py` (SQLite persistence manager)
  - `gemma_advisor.py` (Ollama LLM interface)
  - `dashboard/` (Cyberpunk dark/light front-end application)

---

## 🔒 2. Security Depth & Accuracy (8 Marks)

### Threat Model (STRIDE)
- **Spoofing**: Attackers impersonate brand domains (e.g. Canva, Appy Pie). *Defense*: DNS certificate validations and SPF checks flag lookalike domains.
- **Tampering**: Email links altered to malicious endpoints. *Defense*: URLs are sanitized and scanned by URLScan.io.
- **Information Disclosure**: User tokens stored insecurely. *Defense*: Google/Microsoft OAuth tokens are saved locally in the client folder (`token*.json`) and added to `.gitignore` so they are never leaked.
- **Denial of Service**: Rapid polling crashes the client. *Defense*: Ingestion is throttled and capped to a maximum of 25 active cached emails.

### MITRE ATT&CK Alignment
- **T1566 (Phishing)**: Overall detection of incoming malicious emails.
- **T1566.001 (Spearphishing Attachment)**: Hashing and scanning email attachments with VirusTotal.
- **T1566.002 (Spearphishing Link)**: URL extraction and URLScan.io sandbox analysis.
- **T1598 (Phishing for Information)**: Scanning body text for sensitive keywords (password reset, banking logs).

### Attack/Defense Technical Validity
- **Attachment Hashing**: Rather than uploading the file (which leaks data), the system hashes the attachment and checks its reputational score.
- **URL Sanatization**: Before sending URLs to VirusTotal/URLScan, query parameters (e.g. `?token=123&user=victim`) are stripped, ensuring sensitive tokens or emails are never leaked.

### Awareness of Limitations & Bypasses
- *VT API Free Tier*: Restricted to 4 requests/min. The client handles rate-limiting gracefully and falls back to offline rules if needed.
- *Evasion via Redirection*: Threat actors use URL shorteners (bit.ly) or open redirects. *Defense*: URLScan's sandbox resolves the final redirection path.

---

## 🏢 3. Architecture Fit & Feasibility (6 Marks)

### Correct Architecture Targeting
- **Hybrid Cloud-Native Layout**:
  ```
  [Local User Interface] --(REST)--> [Flask Daemon Server]
                                       ↓             ↓
                              [Local SQLite DB]   [Local Ollama Gemma LLM]
                                       ↓             ↓
                              [SaaS Threat APIs]  [Cloud Mail OAuth APIs]
  ```

### Real-World Deployment Viability
- **SaaS API Integration**: Uses standard OAuth client consents.
- **Corporate Proxy Hooks**: In production, the mock `blocklist.txt` append function is replaced with API calls to enterprise web gateways (Palo Alto, Zscaler, or Squid proxy).
- **Inbound Webhooks**: The active polling loop can be swapped for server-side push notifications (Gmail Pub/Sub or Office 365 journal feeds) for enterprise-level scalability.

### Operational Considerations
- **Storage Constraints**: The local DB only stores metadata and text logs. The email body is stored temporarily and old records are pruned.
- **Fault Tolerance**: If Ollama goes offline or the laptop CPU is busy, the advisor falls back to a rule-based advisory template to ensure uninterrupted execution.

---

## 📢 4. Communication & Demo (4 Marks)

### Step-by-Step Demo Script
1. **Reset State**: Open `http://localhost:5000`. Show the dark cyberpunk Onboarding view (prompting for Gmail/Outlook login) since the database is empty.
2. **Real Login**: Enter a Gmail address and click "Sign in with Gmail". Approve the Google OAuth prompt in your browser.
3. **Mailing Client Layout**: The client transitions to the premium 3-pane view, listing folders on the left, emails in the middle, and the reading pane on the right.
4. **Phishing Triage**: Select an email. Point out the colored threat badge (`MALICIOUS`, `SUSPICIOUS`, `CLEAN`), the threat score, and the sender authenticity verification status.
5. **AI Advisory Card**: Show the Security Advisor warning generated by **Gemma** identifying exactly why this mail is risky.
6. **Remediation**: Show that the email was moved to the Spam folder in the Gmail account, and its malicious link was appended to `blocklist.txt`.

### Judges Q&A Cheat Sheet
- **Q: Why use a local LLM instead of OpenAI API?**
  - *A*: **Data Privacy.** Email contents contain private information. Sending them to public APIs violates enterprise compliance (GDPR/HIPAA). Running Gemma locally ensures data never leaves our network boundary.
- **Q: How do you handle false positives on tracking links (e.g. Postmark or Canva)?**
  - *A*: We filter out resource extensions (`.css`, `.png`) and have built-in whitelists for common marketing redirects, capping their threat scores unless the threat intelligence APIs explicitly flag them.
- **Q: How does the system protect against API rate-limiting on VirusTotal?**
  - *A*: The database caches all triage verdicts. If the same link is received multiple times, the threat score is read from the cache instead of calling the API again.

---

## 📄 5. Documentation Checklist (2 Marks)

- [x] **README.md**: Full, non-technical overview and system architecture Mermaid flow committed to `README.md`.
- [x] **Code Comments**: Clear inline comments indicating team roles, MITRE techniques, and structural code documentation.
- [x] **Threat Model**: STRIDE and MITRE ATT&CK validations documented inside the README and this response guide.
