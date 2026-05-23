/* ============================================================
   SOAR Dedicated Email Client — Frontend JavaScript
   Polls /api/status to update background monitor badge,
   manages multi-account state, folders, search, and reading.
   ============================================================ */

const API = "http://localhost:5000";
let pollInterval   = null;
let lastResult     = null;
let particleCanvas, particleCtx, particles = [];

// Mailing Client State
let currentAccount = null;
let currentFolder  = "inbox";
let allMails       = [];
let activeMailId   = null;
let lastMailRefreshAt = 0;

// ─────────────────────────────────────────────────────────────
// INIT
// ─────────────────────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", () => {
  initTheme();
  initClock();
  initParticles();
  loadAccounts();
  startPolling();
});

function initTheme() {
  const savedTheme = localStorage.getItem("soar-theme") || "dark";
  document.documentElement.dataset.theme = savedTheme;
  updateThemeButton(savedTheme);
}

function toggleTheme() {
  const currentTheme = document.documentElement.dataset.theme || "dark";
  const nextTheme = currentTheme === "light" ? "dark" : "light";
  document.documentElement.dataset.theme = nextTheme;
  localStorage.setItem("soar-theme", nextTheme);
  updateThemeButton(nextTheme);
}

function updateThemeButton(theme) {
  const button = document.getElementById("theme-toggle");
  if (!button) return;
  button.textContent = theme === "light" ? "Dark" : "Light";
}

// ─────────────────────────────────────────────────────────────
// CLOCK
// ─────────────────────────────────────────────────────────────
function initClock() {
  const formatter = new Intl.DateTimeFormat("en-IN", {
    timeZone: "Asia/Kolkata",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: true
  });

  function tick() {
    const clock = document.getElementById("clock");
    if (clock) clock.textContent = `${formatter.format(new Date())} IST`;
  }
  tick();
  setInterval(tick, 1000);
}

// ─────────────────────────────────────────────────────────────
// BACKGROUND PARTICLES
// ─────────────────────────────────────────────────────────────
function initParticles() {
  particleCanvas = document.getElementById("bg-canvas");
  particleCtx    = particleCanvas.getContext("2d");
  resizeCanvas();
  window.addEventListener("resize", resizeCanvas);
  createParticles();
  animateParticles();
}

function resizeCanvas() {
  particleCanvas.width  = window.innerWidth;
  particleCanvas.height = window.innerHeight;
}

function createParticles() {
  particles = [];
  const count = Math.floor((window.innerWidth * window.innerHeight) / 15000);
  for (let i = 0; i < count; i++) {
    particles.push({
      x:  Math.random() * window.innerWidth,
      y:  Math.random() * window.innerHeight,
      vx: (Math.random() - 0.5) * 0.3,
      vy: (Math.random() - 0.5) * 0.3,
      r:  Math.random() * 1.5 + 0.5,
      alpha: Math.random() * 0.5 + 0.1,
    });
  }
}

function animateParticles() {
  particleCtx.clearRect(0, 0, particleCanvas.width, particleCanvas.height);
  const color = "99, 102, 241"; // accent color (indigo)

  particles.forEach(p => {
    p.x += p.vx; p.y += p.vy;
    if (p.x < 0) p.x = particleCanvas.width;
    if (p.x > particleCanvas.width)  p.x = 0;
    if (p.y < 0) p.y = particleCanvas.height;
    if (p.y > particleCanvas.height) p.y = 0;

    particleCtx.beginPath();
    particleCtx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
    particleCtx.fillStyle = `rgba(${color}, ${p.alpha})`;
    particleCtx.fill();
  });

  // Draw connections
  for (let i = 0; i < particles.length; i++) {
    for (let j = i + 1; j < particles.length; j++) {
      const dx = particles[i].x - particles[j].x;
      const dy = particles[i].y - particles[j].y;
      const dist = Math.sqrt(dx*dx + dy*dy);
      if (dist < 120) {
        particleCtx.beginPath();
        particleCtx.moveTo(particles[i].x, particles[i].y);
        particleCtx.lineTo(particles[j].x, particles[j].y);
        particleCtx.strokeStyle = `rgba(${color}, ${0.15 * (1 - dist/120)})`;
        particleCtx.lineWidth = 0.5;
        particleCtx.stroke();
      }
    }
  }
  requestAnimationFrame(animateParticles);
}

// ─────────────────────────────────────────────────────────────
// POLLING (Worker Status Update)
// ─────────────────────────────────────────────────────────────
function startPolling() {
  if (pollInterval) return;
  pollInterval = setInterval(pollStatus, 1500);
  pollStatus();
}

async function pollStatus() {
  try {
    const resp = await fetch(`${API}/api/status`);
    const state = await resp.json();
    
    // Update sidebar bottom status
    const dot = document.querySelector(".status-dot");
    const label = document.querySelector(".status-text");
    if (dot && label) {
      if (state.running) {
        dot.className = "status-dot running";
        label.textContent = `Triage Active: ${formatStageName(state.stage || "processing")}`;
      } else if (state.mode === "monitoring") {
        dot.className = "status-dot idle";
        dot.style.background = "#10b981"; // green for connected/active monitoring
        label.textContent = "Daemon Active";
      } else {
        dot.className = "status-dot idle";
        dot.style.background = "var(--text-muted)";
        label.textContent = "System Idle";
      }
    }

    // If worker finished processing a new email, reload list automatically
    if (state.result && state.result.success) {
      if (!lastResult || lastResult.ticket_id !== state.result.ticket_id) {
        loadMails();
      }
      lastResult = state.result;
    }

    const now = Date.now();
    if (currentAccount && state.mode && state.mode !== "idle" && now - lastMailRefreshAt > 2500) {
      lastMailRefreshAt = now;
      loadMailsWithoutResetSelection();
    }
  } catch (e) {
    console.warn("SOAR daemon offline:", e);
  }
}

function formatStageName(stage) {
  return String(stage || "processing")
    .replace(/gemma[_ -]?verdict/gi, "security verdict")
    .replace(/gemma/gi, "security")
    .replace(/_/g, " ");
}

// ─────────────────────────────────────────────────────────────
// ACCOUNTS MANAGEMENT
// ─────────────────────────────────────────────────────────────
async function loadAccounts() {
  try {
    const resp = await fetch(`${API}/api/accounts`);
    const accounts = await resp.json();
    const listEl = document.getElementById("mail-accounts-list");
    if (!listEl) return;
    
    const onboardingEl = document.getElementById("onboarding-view");
    const mainAppEl = document.getElementById("main-app");
    
    if (accounts.length === 0) {
      if (onboardingEl) onboardingEl.classList.remove("hidden");
      if (mainAppEl) mainAppEl.classList.add("hidden");
      
      listEl.innerHTML = `<div class="empty-state" style="padding:10px; font-size:0.75rem;">No accounts linked</div>`;
      currentAccount = null;
      document.getElementById("mail-list").innerHTML = `<div class="empty-state">Link an account to get started</div>`;
      document.getElementById("mail-read-pane").innerHTML = `<div class="empty-state">No email selected</div>`;
      return;
    }
    
    if (onboardingEl) onboardingEl.classList.add("hidden");
    if (mainAppEl) mainAppEl.classList.remove("hidden");
    
    listEl.innerHTML = accounts.map(acc => {
      const activeClass = currentAccount === acc.id || (!currentAccount && accounts[0].id === acc.id) ? "active" : "";
      if (!currentAccount && activeClass === "active") {
        currentAccount = acc.id;
      }
      return `
        <div class="account-item ${activeClass}" onclick="selectAccount('${acc.id}')">
          <div class="account-email" title="${acc.email}">${acc.email}</div>
          <div style="display:flex; align-items:center; gap:6px;">
            <span class="account-provider">${acc.provider}</span>
            <span style="color:var(--danger); cursor:pointer; font-weight:bold; font-size:0.9rem;" onclick="deleteAccount('${acc.id}', event)">&times;</span>
          </div>
        </div>
      `;
    }).join("");
    
    loadMails();
  } catch (e) {
    console.error("Error loading accounts:", e);
  }
}

function selectAccount(accountId) {
  currentAccount = accountId;
  loadAccounts();
}

function selectFolder(folder) {
  currentFolder = folder;
  document.querySelectorAll(".folder-item").forEach(item => {
    if (item.dataset.folder === folder) {
      item.classList.add("active");
    } else {
      item.classList.remove("active");
    }
  });
  loadMails();
}

// ─────────────────────────────────────────────────────────────
// EMAILS RETRIEVAL
// ─────────────────────────────────────────────────────────────
async function loadMails() {
  if (!currentAccount) return;
  try {
    const resp = await fetch(`${API}/api/mails?account_id=${currentAccount}&folder=${currentFolder}&limit=25`);
    allMails = sortMailsByArrival(await resp.json());
    renderMailsList(allMails);
  } catch (e) {
    console.error("Error loading mails:", e);
  }
}

function sortMailsByArrival(mails) {
  return [...(mails || [])].sort((a, b) => {
    const tsA = Number(a.received_ts || 0);
    const tsB = Number(b.received_ts || 0);
    if (tsA !== tsB) return tsB - tsA;
    return String(b.date || "").localeCompare(String(a.date || ""));
  });
}

function formatMailDate(mail) {
  const ts = Number(mail.received_ts || 0);
  if (!ts) return (mail.date || "").substring(0, 16);
  return new Intl.DateTimeFormat("en-IN", {
    timeZone: "Asia/Kolkata",
    day: "2-digit",
    month: "short",
    hour: "2-digit",
    minute: "2-digit",
    hour12: true
  }).format(new Date(ts));
}

function formatFullMailDate(mail) {
  const ts = Number(mail.received_ts || 0);
  if (!ts) return mail.date || "";
  return `${new Intl.DateTimeFormat("en-IN", {
    timeZone: "Asia/Kolkata",
    dateStyle: "medium",
    timeStyle: "medium",
    hour12: true
  }).format(new Date(ts))} IST`;
}

function renderMailsList(mails) {
  const listEl = document.getElementById("mail-list");
  if (!listEl) return;
  
  if (mails.length === 0) {
    listEl.innerHTML = `<div class="empty-state">No emails in this folder</div>`;
    return;
  }
  
  listEl.innerHTML = mails.map(m => {
    const unreadClass = m.is_read ? "" : "unread";
    const activeClass = activeMailId === m.id ? "active" : "";
    const dateFormatted = formatMailDate(m);
    
    let tagClass = "clean";
    if (m.verdict === "MALICIOUS") tagClass = "malicious";
    else if (m.verdict === "SUSPICIOUS") tagClass = "suspicious";
    else if (m.verdict === "PENDING") tagClass = "pending";
    
    return `
      <div class="mail-list-item ${unreadClass} ${activeClass}" onclick="selectMail('${m.id}')">
        <div class="mail-item-header">
          <span class="mail-item-sender">${escHtml(m.sender)}</span>
          <span class="mail-item-date">${escHtml(dateFormatted)}</span>
        </div>
        <div class="mail-item-subject">${escHtml(m.subject || "(No Subject)")}</div>
        <div class="mail-item-snippet">${escHtml(m.snippet || "")}</div>
        <div class="mail-item-meta">
          <span class="verdict-tag ${tagClass}">${m.verdict}</span>
          <span style="font-family:'JetBrains Mono',monospace; font-size:0.7rem; color:var(--text-muted);">${m.score}/100</span>
        </div>
      </div>
    `;
  }).join("");
}

// ─────────────────────────────────────────────────────────────
// EMAIL READING & SOAR ANALYSIS RENDERING
// ─────────────────────────────────────────────────────────────
async function selectMail(emailId) {
  activeMailId = emailId;
  
  // Update selection style instantly
  document.querySelectorAll(".mail-list-item").forEach(item => {
    item.classList.remove("active");
  });
  
  const readPane = document.getElementById("mail-read-pane");
  if (!readPane) return;
  
  readPane.innerHTML = `<div class="empty-state"><div class="loading-spinner" style="width:24px; height:24px; border-width:2px; margin-bottom:8px;"></div>Loading details...</div>`;
  
  try {
    // Mark as read in database
    await fetch(`${API}/api/mails/${emailId}/read`, { method: "POST" });
    
    // Fetch details
    const resp = await fetch(`${API}/api/mails/${emailId}`);
    const mail = await resp.json();
    
    const ticket = mail.ticket || {};
    const senderTrust = ticket.sender_trust || {};
    const trustScore = senderTrust.trust_score !== undefined ? senderTrust.trust_score : "N/A";
    const trustLevel = senderTrust.trust_level || "UNKNOWN";
    const aiVerdict = mail.ai_verdict || "UNKNOWN";
    const aiScore = mail.ai_score || 0;
    const aiReason = mail.ai_reason || "Security verdict is not available for this message.";
    
    let tagClass = "clean";
    if (mail.verdict === "MALICIOUS") tagClass = "malicious";
    else if (mail.verdict === "SUSPICIOUS") tagClass = "suspicious";
    else if (mail.verdict === "PENDING") tagClass = "pending";
    
    // Load security warnings
    let advisoryHtml = "";
    if (mail.gemma_advisory) {
      let formatted = escHtml(mail.gemma_advisory);
      formatted = formatted.replace(/###\s*(.*?)(?:\r?\n|$)/g, '<h4 style="color: #a5b4fc; margin-top: 10px; margin-bottom: 6px; font-weight: 700; font-size: 0.88rem;">$1</h4>');
      formatted = formatted.replace(/\*\*(.*?)\*\*/g, '<strong style="color: var(--text); font-weight: 600;">$1</strong>');
      formatted = formatted.replace(/(?:^|\n)[-*]\s+(.*?)(?:\r?\n|$)/g, '\n<div style="margin-left: 12px; margin-bottom: 4px; display: flex; align-items: flex-start; gap: 6px;"><span>•</span> <span>$1</span></div>');
      formatted = formatted.replace(/\r?\n\r?\n/g, '<div style="margin-bottom: 8px;"></div>');
      formatted = formatted.replace(/\r?\n/g, '<br>');
      
      advisoryHtml = `
        <div class="card" style="border-left: 3px solid var(--accent); background:rgba(99, 102, 241, 0.04); margin-bottom: 16px; padding: 14px 18px;">
          <div style="display:flex; align-items:center; gap:8px; font-weight:700; font-size:0.8rem; text-transform:uppercase; letter-spacing:0.05em; color:var(--accent); margin-bottom:8px;">
            Security Advisor
          </div>
          <div style="font-size: 0.8rem; line-height: 1.5; color: var(--text);">${formatted}</div>
        </div>
      `;
    }

    // Render Triage Badge Card
    const triageHtml = `
      <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px; margin-bottom: 16px;">
        <div class="intel-item ${tagClass}" style="padding:8px 12px; text-align:center;">
          <div class="intel-count" style="font-size:1.1rem; text-transform: uppercase;">${mail.verdict}</div>
          <div class="intel-label" style="font-size:0.6rem;">SOAR Verdict</div>
        </div>
        <div class="intel-item" style="padding:8px 12px; text-align:center; background:var(--surface3); border-color:var(--border);">
          <div class="intel-count" style="font-size:1.1rem; color:var(--text);">${mail.score}/100</div>
          <div class="intel-label" style="font-size:0.6rem;">Threat Score</div>
        </div>
        <div class="intel-item" style="padding:8px 12px; text-align:center; background:var(--surface3); border-color:var(--border);">
          <div class="intel-count" style="font-size:1.1rem; color:${trustLevel === 'SPOOFED' || trustLevel === 'UNTRUSTED' ? 'var(--danger)' : 'var(--success)'};">${trustScore}/100</div>
          <div class="intel-label" style="font-size:0.6rem;">Sender Authenticity (${trustLevel})</div>
        </div>
      </div>
    `;

    const aiHtml = `
      <div class="card" style="border-left: 3px solid var(--cyan); background:rgba(6, 182, 212, 0.04); margin-bottom: 16px; padding: 14px 18px;">
        <div style="display:flex; align-items:center; justify-content:space-between; gap:8px; margin-bottom:6px;">
          <div style="font-weight:700; font-size:0.8rem; text-transform:uppercase; letter-spacing:0.05em; color:var(--cyan);">Security Verdict</div>
          <span class="verdict-tag ${aiVerdict === "MALICIOUS" ? "malicious" : aiVerdict === "SUSPICIOUS" ? "suspicious" : "clean"}">${escHtml(aiVerdict)} · ${escHtml(aiScore)}/100</span>
        </div>
        <div style="font-size:0.8rem; color:var(--text-muted); line-height:1.5;">${escHtml(aiReason)}</div>
      </div>
    `;
    
    const bodyText = mail.body_plain || htmlToText(mail.body_html || "") || mail.snippet || "(Empty Body)";

    readPane.innerHTML = `
      <div class="mail-header-details">
        <div class="mail-subject-large">${escHtml(mail.subject || "(No Subject)")}</div>
        <div class="mail-meta-row">
          <div>From: <strong>${escHtml(mail.sender)}</strong></div>
          <div>Date: <strong>${escHtml(formatFullMailDate(mail))}</strong></div>
        </div>
      </div>
      
      ${advisoryHtml}
      ${triageHtml}
      ${aiHtml}
      
      <div class="mail-section-title">Email Content</div>
      <div class="mail-body-content">${escHtml(bodyText)}</div>
    `;
    
    // Refresh thread listing so unread indicator goes away
    loadMailsWithoutResetSelection();
  } catch (e) {
    console.error("Error fetching mail details:", e);
    readPane.innerHTML = `<div class="empty-state" style="color:var(--danger)">Error loading email details</div>`;
  }
}

// Quiet reload (without resetting activeMailId)
async function loadMailsWithoutResetSelection() {
  if (!currentAccount) return;
  try {
    const resp = await fetch(`${API}/api/mails?account_id=${currentAccount}&folder=${currentFolder}&limit=25`);
    allMails = sortMailsByArrival(await resp.json());
    renderMailsListQuietly(allMails);
  } catch (e) {
    console.error("Error loading mails quietly:", e);
  }
}

function renderMailsListQuietly(mails) {
  const listEl = document.getElementById("mail-list");
  if (!listEl) return;
  
  if (mails.length === 0) {
    listEl.innerHTML = `<div class="empty-state">No emails in this folder</div>`;
    return;
  }
  
  listEl.innerHTML = mails.map(m => {
    const unreadClass = m.is_read ? "" : "unread";
    const activeClass = activeMailId === m.id ? "active" : "";
    const dateFormatted = formatMailDate(m);
    
    let tagClass = "clean";
    if (m.verdict === "MALICIOUS") tagClass = "malicious";
    else if (m.verdict === "SUSPICIOUS") tagClass = "suspicious";
    else if (m.verdict === "PENDING") tagClass = "pending";
    
    return `
      <div class="mail-list-item ${unreadClass} ${activeClass}" onclick="selectMail('${m.id}')">
        <div class="mail-item-header">
          <span class="mail-item-sender">${escHtml(m.sender)}</span>
          <span class="mail-item-date">${escHtml(dateFormatted)}</span>
        </div>
        <div class="mail-item-subject">${escHtml(m.subject || "(No Subject)")}</div>
        <div class="mail-item-snippet">${escHtml(m.snippet || "")}</div>
        <div class="mail-item-meta">
          <span class="verdict-tag ${tagClass}">${m.verdict}</span>
          <span style="font-family:'JetBrains Mono',monospace; font-size:0.7rem; color:var(--text-muted);">${m.score}/100</span>
        </div>
      </div>
    `;
  }).join("");
}

// ─────────────────────────────────────────────────────────────
// SEARCH FILTER
// ─────────────────────────────────────────────────────────────
function filterMails() {
  const query = document.getElementById("mail-search-input").value.toLowerCase();
  const filtered = allMails.filter(m => 
    (m.subject || "").toLowerCase().includes(query) ||
    (m.sender || "").toLowerCase().includes(query) ||
    (m.snippet || "").toLowerCase().includes(query)
  );
  renderMailsList(filtered);
}

// ─────────────────────────────────────────────────────────────
// ACCOUNT SETUP DIALOGS
// ─────────────────────────────────────────────────────────────
function showAddAccountModal() {
  const modal = document.getElementById("add-account-modal");
  if (modal) modal.classList.remove("hidden");
}

function hideAddAccountModal() {
  const modal = document.getElementById("add-account-modal");
  if (modal) modal.classList.add("hidden");
}

function toggleProviderFields() {
  return;
}

async function submitAddAccount() {
  return submitOnboarding("gmail");
}

async function submitOnboarding(provider) {
  if (!["gmail", "outlook"].includes(provider)) {
    alert("Only Gmail and Outlook OAuth are supported.");
    return;
  }

  const providerName = provider === "gmail" ? "Gmail" : "Outlook";
  document.body.style.cursor = "progress";
  try {
    const resp = await fetch(`${API}/api/auth/${provider}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" }
    });
    const result = await resp.json();
    if (result.error) {
      alert(`${providerName} sign-in failed: ${result.error}`);
    } else {
      currentAccount = result.id;
      hideAddAccountModal();
      await loadAccounts();
    }
  } catch (e) {
    alert(`Failed to start ${providerName} sign-in.`);
  } finally {
    document.body.style.cursor = "";
  }
}

async function deleteAccount(accountId, event) {
  event.stopPropagation();
  if (!confirm("Are you sure you want to unlink this account? All local email cache will be deleted.")) return;
  try {
    await fetch(`${API}/api/accounts/delete`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ id: accountId })
    });
    if (currentAccount === accountId) currentAccount = null;
    loadAccounts();
  } catch (e) {
    console.error("Error deleting account:", e);
  }
}

// ─────────────────────────────────────────────────────────────
// HTML ESCAPE
// ─────────────────────────────────────────────────────────────
async function selectMail(emailId) {
  activeMailId = emailId;
  document.querySelectorAll(".mail-list-item").forEach(item => item.classList.remove("active"));

  const readPane = document.getElementById("mail-read-pane");
  if (!readPane) return;
  readPane.innerHTML = `<div class="empty-state"><div class="loading-spinner" style="width:24px; height:24px; border-width:2px; margin-bottom:8px;"></div>Loading details...</div>`;

  try {
    await fetch(`${API}/api/mails/${emailId}/read`, { method: "POST" });
    const resp = await fetch(`${API}/api/mails/${emailId}`);
    const mail = await resp.json();

    const ticket = mail.ticket || {};
    const senderTrust = ticket.sender_trust || {};
    const trustScore = senderTrust.trust_score !== undefined ? senderTrust.trust_score : "N/A";
    const trustLevel = senderTrust.trust_level || "UNKNOWN";
    const securityVerdict = mail.ai_verdict || "UNKNOWN";
    const securityScore = mail.ai_score || 0;
    const securityReason = mail.ai_reason || "Security verdict is not available for this message.";
    const bodyText = mail.body_plain || htmlToText(mail.body_html || "") || mail.snippet || "(Body unavailable)";

    let tagClass = "clean";
    if (mail.verdict === "MALICIOUS") tagClass = "malicious";
    else if (mail.verdict === "SUSPICIOUS") tagClass = "suspicious";
    else if (mail.verdict === "PENDING") tagClass = "pending";

    let advisoryHtml = "";
    if (mail.gemma_advisory) {
      advisoryHtml = `
        <div class="card security-advisory-card">
          <div class="security-card-title">Security Advisor</div>
          <div class="security-card-body">${formatAdvisoryText(mail.gemma_advisory)}</div>
        </div>
      `;
    }

    const triageHtml = `
      <div class="triage-card-grid">
        <div class="intel-item ${tagClass}">
          <div class="intel-count">${escHtml(mail.verdict || "PENDING")}</div>
          <div class="intel-label">SOAR Verdict</div>
        </div>
        <div class="intel-item neutral">
          <div class="intel-count">${escHtml(mail.score || 0)}/100</div>
          <div class="intel-label">Threat Score</div>
        </div>
        <div class="intel-item neutral">
          <div class="intel-count ${trustLevel === "SPOOFED" || trustLevel === "UNTRUSTED" ? "danger-text" : "success-text"}">${escHtml(trustScore)}/100</div>
          <div class="intel-label">Sender Authenticity (${escHtml(trustLevel)})</div>
        </div>
      </div>
    `;

    const verdictHtml = `
      <div class="card security-verdict-card">
        <div class="security-verdict-header">
          <div class="security-card-title cyan">Security Verdict</div>
          <span class="verdict-tag ${securityVerdict === "MALICIOUS" ? "malicious" : securityVerdict === "SUSPICIOUS" ? "suspicious" : "clean"}">${escHtml(securityVerdict)} &middot; ${escHtml(securityScore)}/100</span>
        </div>
        <div class="security-card-body muted">${escHtml(securityReason)}</div>
      </div>
    `;
    const evidenceHtml = renderThreatIntelEvidence(ticket.threat_intel || {});
    const reportHtml = mail.ticket_id ? `
      <a class="report-link-card" href="${API}/api/report/${encodeURIComponent(mail.ticket_id)}" target="_blank" rel="noreferrer">
        Open Structured SOAR Report
      </a>
    ` : "";

    readPane.innerHTML = `
      <div class="mail-header-details">
        <div class="mail-subject-large">${escHtml(mail.subject || "(No Subject)")}</div>
        <div class="mail-meta-row">
          <div>From: <strong>${escHtml(mail.sender)}</strong></div>
          <div>Date: <strong>${escHtml(formatFullMailDate(mail))}</strong></div>
        </div>
      </div>

      ${advisoryHtml}
      ${triageHtml}
      ${verdictHtml}
      ${evidenceHtml}
      ${reportHtml}

      <div class="mail-section-title">Email Content</div>
      <div class="mail-body-content">${escHtml(bodyText)}</div>
    `;

    loadMailsWithoutResetSelection();
  } catch (e) {
    console.error("Error fetching mail details:", e);
    readPane.innerHTML = `<div class="empty-state" style="color:var(--danger)">Error loading email details</div>`;
  }
}

function renderThreatIntelEvidence(threatIntel) {
  const urlRows = (threatIntel.url_results || []).slice(0, 4).map(item => {
    const vt = item.virustotal || {};
    const us = item.urlscan || {};
    return `
      <div class="evidence-row">
        <div class="evidence-type">URL</div>
        <div class="evidence-main">${escHtml(item.url || "")}</div>
        <div class="evidence-score">VT ${escHtml(vt.malicious || 0)}M/${escHtml(vt.suspicious || 0)}S · URLScan ${us.malicious ? "MALICIOUS" : escHtml(us.status || "not scanned")}</div>
      </div>
    `;
  });

  const attachmentRows = (threatIntel.attachment_results || []).slice(0, 4).map(item => {
    const vt = item.virustotal || {};
    return `
      <div class="evidence-row">
        <div class="evidence-type">Attachment</div>
        <div class="evidence-main">${escHtml(item.filename || "attachment")}</div>
        <div class="evidence-score">VT ${escHtml(vt.malicious || 0)}M/${escHtml(vt.suspicious || 0)}S · SHA256 ${(item.sha256 || "not available").slice(0, 24)}</div>
      </div>
    `;
  });

  const rows = [...urlRows, ...attachmentRows].join("");
  if (!rows) return "";
  return `
    <div class="card evidence-card">
      <div class="security-card-title">Threat Intel Evidence</div>
      <div class="evidence-list">${rows}</div>
    </div>
  `;
}

function formatAdvisoryText(text) {
  let formatted = escHtml(text || "");
  formatted = formatted.replace(/###\s*(.*?)(?:\r?\n|$)/g, '<h4 class="security-card-heading">$1</h4>');
  formatted = formatted.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');
  formatted = formatted.replace(/(?:^|\n)[-*]\s+(.*?)(?:\r?\n|$)/g, '\n<div class="security-bullet"><span>&bull;</span><span>$1</span></div>');
  formatted = formatted.replace(/\r?\n\r?\n/g, '<div style="margin-bottom: 8px;"></div>');
  formatted = formatted.replace(/\r?\n/g, '<br>');
  return formatted;
}

function escHtml(str) {
  return String(str || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function htmlToText(html) {
  if (!html) return "";
  const doc = new DOMParser().parseFromString(String(html), "text/html");
  doc.querySelectorAll("script, style, noscript, svg, head").forEach(el => el.remove());
  return (doc.body.textContent || "")
    .replace(/\r/g, "\n")
    .replace(/\n[ \t]+/g, "\n")
    .replace(/[ \t]{2,}/g, " ")
    .replace(/\n{3,}/g, "\n\n")
    .trim();
}
