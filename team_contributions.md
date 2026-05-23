# 👥 Team Contribution Division — Hackathon 2026

This document lists the specific task divisions and module ownership for all 5 members of the team, matching the hackathon specifications.

---

### 📧 Person 1: Email Ingestion & OAuth Connectors
- **Primary Responsibility**: API Authentication & Inbound Ingestion.
- **Core Files**:
  - [gmail_connector.py](file:///c:/Users/kamma/OneDrive%20-%20Amrita%20vishwa%20vidyapeetham/Desktop/Cyber%20Hackaton/soar_mail_client/gmail_connector.py) — Integrated Google APIs Client Library, configured OAuth 2.0 flow, and managed token exchanges.
  - [outlook_connector.py](file:///c:/Users/kamma/OneDrive%20-%20Amrita%20vishwa%20vidyapeetham/Desktop/Cyber%20Hackaton/soar_mail_client/outlook_connector.py) — Configured MSAL (Microsoft Authentication Library) Graph endpoints for Outlook mail fetch.
  - Credentials Configuration — Handled `credentials.json` setup, token caching logic (`token*.json`), and environment secrets (`.env`).

### 🔍 Person 2: Email Parsing & IoC Extraction
- **Primary Responsibility**: Text processing, regex parsing, and metadata extraction.
- **Core Files**:
  - [email_parser.py](file:///c:/Users/kamma/OneDrive%20-%20Amrita%20vishwa%20vidyapeetham/Desktop/Cyber%20Hackaton/soar_mail_client/email_parser.py) — Built regex search engines for URLs/IPs/emails and HTML parsing filters using BeautifulSoup.
  - HTML-to-Text Parser — Developed conversion code to extract text bodies from HTML-only newsletters, resolving empty-body rendering issues.
  - Header Anomaly Scanner — Programmed logic to detect mismatches between the sender's domain, Return-Path, and Received headers.

### 🌐 Person 3: Threat Intelligence Enrichment
- **Primary Responsibility**: Threat feeds integration and domain trust audits.
- **Core Files**:
  - [threat_intel.py](file:///c:/Users/kamma/OneDrive%20-%20Amrita%20vishwa%20vidyapeetham/Desktop/Cyber%20Hackaton/soar_mail_client/threat_intel.py) — Built API connectors to VirusTotal (URLs, domains, and attachment file hashes) and URLScan.io (sandbox screenshot & brand lookalike scans).
  - [cert_checker.py](file:///c:/Users/kamma/OneDrive%20-%20Amrita%20vishwa%20vidyapeetham/Desktop/Cyber%20Hackaton/soar_mail_client/cert_checker.py) — Coded DNS resolution checks (SPF, DKIM, and DMARC validations) to verify domain certificate authenticity.
  - Privacy Sanitization — Implemented URL query parameter strippers to ensure corporate tokens or user emails are never leaked to external threat intelligence feeds.

### 🔴 Person 4: Automated Triage & Response Actions
- **Primary Responsibility**: Risk scoring, rule engines, and automated remediation.
- **Core Files**:
  - [triage.py](file:///c:/Users/kamma/OneDrive%20-%20Amrita%20vishwa%20vidyapeetham/Desktop/Cyber%20Hackaton/soar_mail_client/triage.py) — Developed the triage scoring algorithm (0 to 100) and mapped verdicts to MITRE ATT&CK techniques (T1566, T1598).
  - [response_actions.py](file:///c:/Users/kamma/OneDrive%20-%20Amrita%20vishwa%20vidyapeetham/Desktop/Cyber%20Hackaton/soar_mail_client/response_actions.py) — Implemented the Gmail/Outlook API calls to quarantine emails by moving them to the spam folder, updated local firewall blocklists (`blocklist.txt`), and managed Slack alert webhooks.

### 📊 Person 5: Local AI, Database & Web Client UI
- **Primary Responsibility**: Front-end design, local LLM integration, and web serving.
- **Core Files**:
  - [gemma_advisor.py](file:///c:/Users/kamma/OneDrive%20-%20Amrita%20vishwa%20vidyapeetham/Desktop/Cyber%20Hackaton/soar_mail_client/gemma_advisor.py) & [report_generator.py](file:///c:/Users/kamma/OneDrive%20-%20Amrita%20vishwa%20vidyapeetham/Desktop/Cyber%20Hackaton/soar_mail_client/report_generator.py) — Configured the Ollama local connection, structured the Gemma LLM prompt templates for advisories, and handled JSON/HTML incident report ticketing.
  - [server.py](file:///c:/Users/kamma/OneDrive%20-%20Amrita%20vishwa%20vidyapeetham/Desktop/Cyber%20Hackaton/soar_mail_client/server.py) & [db_manager.py](file:///c:/Users/kamma/OneDrive%20-%20Amrita%20vishwa%20vidyapeetham/Desktop/Cyber%20Hackaton/soar_mail_client/db_manager.py) — Setup the Flask web framework and built the local SQLite database cache layers.
  - `dashboard/` ([index.html](file:///c:/Users/kamma/OneDrive%20-%20Amrita%20vishwa%20vidyapeetham/Desktop/Cyber%20Hackaton/soar_mail_client/dashboard/index.html), [style.css](file:///c:/Users/kamma/OneDrive%20-%20Amrita%20vishwa%20vidyapeetham/Desktop/Cyber%20Hackaton/soar_mail_client/dashboard/style.css), [app.js](file:///c:/Users/kamma/OneDrive%20-%20Amrita%20vishwa%20vidyapeetham/Desktop/Cyber%20Hackaton/soar_mail_client/dashboard/app.js)) — Programmed the dark/light cyberpunk theme, onboarding transition logics, dynamic sorting (by actual mail received time), and the IST live clock.
