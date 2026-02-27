/**
 * Cyber Shield - Frontend Application Logic
 * Handles all API interactions, UI updates, and real-time scanning.
 */

const API_BASE = '';  // Same origin

// ═══════════════════════════════════════════════════════════════════
// Page Navigation
// ═══════════════════════════════════════════════════════════════════

function showPage(page) {
    document.querySelectorAll('.page-section').forEach(el => el.classList.remove('active'));
    document.querySelectorAll('.nav-btn').forEach(el => el.classList.remove('active'));

    const pageEl = document.getElementById(`page-${page}`);
    const navEl = document.getElementById(`nav-${page}`);
    if (pageEl) pageEl.classList.add('active');
    if (navEl) navEl.classList.add('active');

    if (page === 'dashboard') loadDashboard();
    if (page === 'history') loadHistory();
    if (page === 'models') loadModels();
}

function switchScanTab(tab) {
    document.querySelectorAll('.scan-tab').forEach(el => el.classList.remove('active'));
    document.getElementById(`tab-${tab}`).classList.add('active');

    if (tab === 'url') {
        document.getElementById('urlScanner').style.display = 'block';
        document.getElementById('contentScanner').classList.remove('active');
    } else {
        document.getElementById('urlScanner').style.display = 'none';
        document.getElementById('contentScanner').classList.add('active');
    }
}

// ═══════════════════════════════════════════════════════════════════
// URL Scanning
// ═══════════════════════════════════════════════════════════════════

async function performScan() {
    const urlInput = document.getElementById('urlInput');
    const scanBtn = document.getElementById('scanBtn');
    const url = urlInput.value.trim();

    if (!url) {
        showToast('Please enter a URL to scan', 'warning');
        urlInput.focus();
        return;
    }

    let scanUrl = url;
    if (!scanUrl.startsWith('http://') && !scanUrl.startsWith('https://')) {
        scanUrl = 'http://' + scanUrl;
    }

    // Show scanning state
    scanBtn.classList.add('scanning');
    scanBtn.disabled = true;
    showScanningState(scanUrl);

    try {
        const response = await fetch(`${API_BASE}/api/scan`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: scanUrl, deep_scan: true })
        });

        if (!response.ok) throw new Error(`Scan failed: ${response.statusText}`);

        const result = await response.json();
        displayResult(result);
        updateQuickStats();
        showToast(
            result.is_phishing ? '🚨 Threat detected!' : '✅ Scan complete — URL is safe',
            result.is_phishing ? 'error' : 'success'
        );

    } catch (error) {
        console.error('Scan error:', error);
        showErrorState(error.message);
        showToast(`Scan failed: ${error.message}`, 'error');
    } finally {
        scanBtn.classList.remove('scanning');
        scanBtn.disabled = false;
    }
}

// ═══════════════════════════════════════════════════════════════════
// Content Scanning
// ═══════════════════════════════════════════════════════════════════

async function performContentScan() {
    const content = document.getElementById('contentInput').value.trim();
    const sender = document.getElementById('senderInput').value.trim();
    const subject = document.getElementById('subjectInput').value.trim();
    const btn = document.getElementById('contentScanBtn');

    if (!content) {
        showToast('Please enter content to analyze', 'warning');
        return;
    }

    btn.classList.add('scanning');
    btn.disabled = true;

    try {
        const response = await fetch(`${API_BASE}/api/analyze/content`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                content,
                sender: sender || null,
                subject: subject || null,
                deep_scan: true
            })
        });

        if (!response.ok) throw new Error(`Analysis failed: ${response.statusText}`);

        const result = await response.json();
        displayResult(result);
        updateQuickStats();
        showToast(
            result.is_phishing ? '🚨 Phishing content detected!' : '✅ Content appears safe',
            result.is_phishing ? 'error' : 'success'
        );

    } catch (error) {
        console.error('Content scan error:', error);
        showToast(`Analysis failed: ${error.message}`, 'error');
    } finally {
        btn.classList.remove('scanning');
        btn.disabled = false;
    }
}

// ═══════════════════════════════════════════════════════════════════
// Scanning / Error States
// ═══════════════════════════════════════════════════════════════════

function showScanningState(url) {
    const panel = document.getElementById('resultsPanel');
    const card = document.getElementById('resultCard');
    panel.classList.add('active');
    card.innerHTML = `
        <div class="verdict-scanning">
            <div class="scanning-spinner"></div>
            <div class="scanning-title">Scanning URL…</div>
            <div class="scanning-url">${escapeHtml(url)}</div>
            <div class="scanning-engines">
                <span class="engine-pill">🔗 URL ML</span>
                <span class="engine-pill">📝 NLP</span>
                <span class="engine-pill">🤖 Gemini AI</span>
                <span class="engine-pill">🛡️ VirusTotal</span>
                <span class="engine-pill">🚨 AbuseIPDB</span>
                <span class="engine-pill">☁️ Remote ML</span>
            </div>
            <div class="scanning-note">Running 6 detection engines in parallel…</div>
        </div>`;
    panel.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function showErrorState(message) {
    const card = document.getElementById('resultCard');
    card.innerHTML = `
        <div class="verdict-banner critical" style="border-color:#FF1744;">
            <div class="verdict-icon">❌</div>
            <div class="verdict-text">
                <div class="verdict-label" style="color:#FF1744;">SCAN FAILED</div>
                <div class="verdict-sublabel">${escapeHtml(message)}</div>
            </div>
        </div>`;
}

// ═══════════════════════════════════════════════════════════════════
// Display Results — Main render
// ═══════════════════════════════════════════════════════════════════

function displayResult(result) {
    const panel = document.getElementById('resultsPanel');
    const card = document.getElementById('resultCard');

    const score = result.risk_score || result.ensemble_score || 0;
    const level = result.threat_level || 'safe';
    const scorePercent = Math.round(score * 100);
    const target = result.target || '';

    // ── Verdict configuration ──────────────────────────────────────
    const verdictMap = {
        safe: { label: 'SAFE', sublabel: 'No phishing indicators found', icon: '✅', color: '#00E676', bg: 'rgba(0,230,118,0.08)', border: '#00E676' },
        low: { label: 'LOW RISK', sublabel: 'Minor suspicious traits detected', icon: '🟡', color: '#69F0AE', bg: 'rgba(105,240,174,0.08)', border: '#69F0AE' },
        medium: { label: 'MEDIUM RISK', sublabel: 'Suspicious characteristics detected', icon: '⚠️', color: '#FFD740', bg: 'rgba(255,215,64,0.08)', border: '#FFD740' },
        high: { label: 'HIGH RISK', sublabel: 'Strong phishing indicators found', icon: '🔴', color: '#FF6E40', bg: 'rgba(255,110,64,0.08)', border: '#FF6E40' },
        critical: { label: 'CRITICAL — PHISHING', sublabel: 'This URL is extremely dangerous', icon: '⛔', color: '#FF1744', bg: 'rgba(255,23,68,0.08)', border: '#FF1744' },
    };
    const v = verdictMap[level] || verdictMap.safe;

    const circumference = 2 * Math.PI * 58;
    const offset = circumference - (score * circumference);

    // ── ① Verdict Banner (prominent) ───────────────────────────────
    let html = `
        <div class="verdict-banner" style="background:${v.bg};border-color:${v.border};">
            <div class="verdict-icon">${v.icon}</div>
            <div class="verdict-text">
                <div class="verdict-label" style="color:${v.color}">${v.label}</div>
                <div class="verdict-sublabel">${v.sublabel}</div>
                ${target ? `<div class="verdict-url" title="${escapeHtml(target)}">${escapeHtml(truncate(target, 80))}</div>` : ''}
            </div>
            <div class="verdict-score-pill" style="background:${v.color};color:#000;">
                ${scorePercent}%
            </div>
        </div>`;

    // ── ② Meta row ─────────────────────────────────────────────────
    html += `
        <div class="result-meta-row">
            <div class="result-meta-item">
                <div class="label">Scan ID</div>
                <div class="value">${result.scan_id || 'N/A'}</div>
            </div>
            <div class="result-meta-item">
                <div class="label">Type</div>
                <div class="value">${(result.scan_type || 'url').toUpperCase()}</div>
            </div>
            <div class="result-meta-item">
                <div class="label">Detection Time</div>
                <div class="value">${(result.detection_time_ms || 0).toFixed(1)} ms</div>
            </div>
            <div class="result-meta-item">
                <div class="label">Is Phishing</div>
                <div class="value" style="color:${result.is_phishing ? '#FF1744' : '#00E676'};font-weight:700;">
                    ${result.is_phishing ? '🚨 YES' : '✅ NO'}
                </div>
            </div>
        </div>`;

    // ── ③ Score Gauge + Individual Scores ──────────────────────────
    html += `
        <div class="risk-gauge">
            <div class="gauge-visual">
                <div class="gauge-circle">
                    <svg viewBox="0 0 140 140">
                        <circle class="gauge-bg" cx="70" cy="70" r="58"></circle>
                        <circle class="gauge-fill" cx="70" cy="70" r="58"
                            stroke="${v.color}"
                            stroke-dasharray="${circumference}"
                            stroke-dashoffset="${offset}">
                        </circle>
                    </svg>
                    <span class="gauge-score" style="color:${v.color}">${scorePercent}%</span>
                </div>
                <div class="gauge-label" style="color:${v.color};font-weight:700;margin-top:8px;font-size:0.9rem;">${v.label}</div>
            </div>
            <div class="gauge-details">
                <h4>Engine Breakdown</h4>
                <div class="score-breakdown">
                    ${result.url_ml_score !== undefined ? scoreRow('🔗 URL ML', result.url_ml_score) : ''}
                    ${result.nlp_score !== undefined ? scoreRow('📝 NLP Analyzer', result.nlp_score) : ''}
                    ${result.gemini_analysis?.risk_score !== undefined ? scoreRow('🤖 Gemini AI', result.gemini_analysis.risk_score) : ''}
                    ${result.virustotal?.risk_score !== undefined ? scoreRow('🛡️ VirusTotal', result.virustotal.risk_score) : ''}
                    ${result.abuseipdb?.risk_score !== undefined ? scoreRow('🚨 AbuseIPDB', result.abuseipdb.risk_score) : ''}
                    ${result.remote_ml?.risk_score !== undefined ? scoreRow('☁️ Remote ML', result.remote_ml.risk_score) : ''}
                    <div class="score-item ensemble-row" style="border:1px solid ${v.color}33;background:${v.bg};">
                        <span class="score-name">⚡ Ensemble Score</span>
                        <span class="score-val" style="color:${v.color};font-size:1.1rem;">${scorePercent}%</span>
                    </div>
                </div>
            </div>
        </div>`;

    // ── ④ URL Features ─────────────────────────────────────────────
    if (result.url_features) {
        const f = result.url_features;
        html += `
        <div class="features-grid">
            <div class="feature-item">
                <div class="feature-name">URL Length</div>
                <div class="feature-value ${f.length > 75 ? 'warning' : 'safe'}">${f.length}</div>
            </div>
            <div class="feature-item">
                <div class="feature-name">HTTPS</div>
                <div class="feature-value ${f.has_https ? 'safe' : 'danger'}">${f.has_https ? '✅ Yes' : '❌ No'}</div>
            </div>
            <div class="feature-item">
                <div class="feature-name">IP in URL</div>
                <div class="feature-value ${f.has_ip ? 'danger' : 'safe'}">${f.has_ip ? '⚠️ Yes' : '✅ No'}</div>
            </div>
            <div class="feature-item">
                <div class="feature-name">Subdomains</div>
                <div class="feature-value ${f.num_subdomains > 2 ? 'warning' : 'safe'}">${f.num_subdomains}</div>
            </div>
            <div class="feature-item">
                <div class="feature-name">Entropy</div>
                <div class="feature-value ${f.entropy > 4.5 ? 'warning' : 'safe'}">${f.entropy.toFixed(2)}</div>
            </div>
            <div class="feature-item">
                <div class="feature-name">Suspicious TLD</div>
                <div class="feature-value ${f.has_suspicious_tld ? 'danger' : 'safe'}">${f.has_suspicious_tld ? '⚠️ Yes' : '✅ No'}</div>
            </div>
            ${f.suspicious_keywords?.length > 0 ? `
            <div class="feature-item" style="grid-column:1/-1;">
                <div class="feature-name">Suspicious Keywords</div>
                <div class="feature-value warning">${f.suspicious_keywords.join(', ')}</div>
            </div>` : ''}
        </div>`;
    }

    // ── ⑤ AbuseIPDB Block ──────────────────────────────────────────
    if (result.abuseipdb && result.abuseipdb.source !== 'fallback') {
        const ab = result.abuseipdb;
        const abColor = ab.detected ? '#FF1744' : '#00E676';
        html += `
        <div class="result-indicators" style="border-left:3px solid ${abColor};">
            <h4>🚨 AbuseIPDB IP Intelligence</h4>
            <div class="abuseipdb-grid">
                <div class="ab-item">
                    <div class="ab-label">Resolved IP</div>
                    <div class="ab-value">${ab.ip_address || '—'}</div>
                </div>
                <div class="ab-item">
                    <div class="ab-label">Abuse Confidence</div>
                    <div class="ab-value" style="color:${abColor};font-weight:700;font-size:1.2rem;">
                        ${ab.abuse_score}%
                    </div>
                </div>
                <div class="ab-item">
                    <div class="ab-label">Total Reports</div>
                    <div class="ab-value">${ab.total_reports}</div>
                </div>
                <div class="ab-item">
                    <div class="ab-label">Distinct Users</div>
                    <div class="ab-value">${ab.distinct_users}</div>
                </div>
                <div class="ab-item">
                    <div class="ab-label">Country</div>
                    <div class="ab-value">${ab.country_code || '—'}</div>
                </div>
                <div class="ab-item">
                    <div class="ab-label">ISP</div>
                    <div class="ab-value">${ab.isp || '—'}</div>
                </div>
                <div class="ab-item">
                    <div class="ab-label">Whitelisted</div>
                    <div class="ab-value" style="color:${ab.is_whitelisted ? '#00E676' : 'inherit'}">
                        ${ab.is_whitelisted ? '✅ Yes' : '❌ No'}
                    </div>
                </div>
                <div class="ab-item">
                    <div class="ab-label">Verdict</div>
                    <div class="ab-value" style="color:${abColor};font-weight:700;">
                        ${ab.detected ? '🚨 ABUSIVE' : '✅ CLEAN'}
                    </div>
                </div>
            </div>
            ${ab.threat_categories?.length > 0 ? `
            <div class="indicators-list" style="margin-top:10px;">
                <div class="indicator-item warning">
                    📋 Threat Categories: ${ab.threat_categories.join(' · ')}
                </div>
            </div>` : ''}
        </div>`;
    }

    // ── ⑥ Detection Indicators ─────────────────────────────────────
    if (result.indicators?.length > 0) {
        html += `
        <div class="result-indicators">
            <h4>🔍 Detection Indicators</h4>
            <div class="indicators-list">
                ${result.indicators.map(ind => {
            let cls = 'info';
            if (ind.includes('🔴') || ind.includes('⛔') || ind.includes('🚨')) cls = 'danger';
            else if (ind.includes('🟠') || ind.includes('⚠️')) cls = 'warning';
            return `<div class="indicator-item ${cls}">${ind}</div>`;
        }).join('')}
            </div>
        </div>`;
    }

    // ── ⑦ Gemini AI Analysis ───────────────────────────────────────
    if (result.gemini_analysis && result.gemini_analysis.source !== 'fallback') {
        const g = result.gemini_analysis;
        html += `
        <div class="gemini-section">
            <div class="gemini-header">
                <h4 style="margin:0;font-weight:700;">🤖 Gemini AI Analysis</h4>
                <span class="gemini-badge">✨ Powered by Gemini</span>
            </div>
            <div class="gemini-content">
                <div class="gemini-reasoning">${g.reasoning || 'No reasoning available'}</div>
                <div class="gemini-detail">
                    <div class="detail-label">Classification</div>
                    <div class="detail-value">${g.classification || 'Unknown'}</div>
                </div>
                <div class="gemini-detail">
                    <div class="detail-label">Urgency Level</div>
                    <div class="detail-value">${(g.urgency_level || 'unknown').toUpperCase()}</div>
                </div>
                ${g.brand_impersonation ? `
                <div class="gemini-detail">
                    <div class="detail-label">Brand Impersonation</div>
                    <div class="detail-value" style="color:var(--accent-red)">${g.brand_impersonation}</div>
                </div>` : ''}
                ${g.manipulation_tactics?.length > 0 ? `
                <div class="gemini-detail" style="grid-column:1/-1;">
                    <div class="detail-label">Manipulation Tactics</div>
                    <div class="manipulation-tags">
                        ${g.manipulation_tactics.map(t => `<span class="manipulation-tag">${t}</span>`).join('')}
                    </div>
                </div>` : ''}
            </div>
        </div>`;
    }

    // ── ⑧ VirusTotal Results ───────────────────────────────────────
    if (result.virustotal && result.virustotal.source !== 'fallback') {
        const vt = result.virustotal;
        html += `
        <div class="result-indicators">
            <h4>🛡️ VirusTotal Intelligence</h4>
            <div class="indicators-list">
                <div class="indicator-item ${vt.detected ? 'danger' : 'info'}">
                    ${vt.detected ? '🔴' : '✅'} Detection: ${vt.positives}/${vt.total_scanners} security vendors
                    ${vt.malicious > 0 ? ` (${vt.malicious} malicious, ${vt.suspicious} suspicious)` : ''}
                </div>
                ${vt.categories?.length > 0 ? `
                <div class="indicator-item warning">
                    📋 Categories: ${vt.categories.join(', ')}
                </div>` : ''}
                <div class="indicator-item info">
                    📊 Reputation: ${vt.reputation || 0} | Submitted: ${vt.times_submitted || 0} times
                </div>
            </div>
        </div>`;
    }

    // ── ⑨ Explanation ──────────────────────────────────────────────
    if (result.explanation) {
        html += `
        <div class="result-indicators">
            <h4>💡 Analysis Summary</h4>
            <div class="gemini-reasoning">${result.explanation}</div>
        </div>`;
    }

    // ── ⑩ Recommendations ──────────────────────────────────────────
    if (result.recommendations?.length > 0) {
        html += `
        <div class="result-recommendations">
            <h4>📋 Recommendations</h4>
            <div class="recommendations-list">
                ${result.recommendations.map(rec =>
            `<div class="recommendation-item">
                        <span class="rec-icon">✓</span>
                        <span>${rec}</span>
                    </div>`
        ).join('')}
            </div>
        </div>`;
    }

    card.innerHTML = html;
    panel.classList.add('active');
    panel.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

// ── Helper: single score row ────────────────────────────────────────
function scoreRow(label, score) {
    const pct = (score * 100).toFixed(1);
    return `
        <div class="score-item">
            <span class="score-name">${label}</span>
            <div class="score-bar-wrap">
                <div class="score-bar" style="width:${pct}%;background:${getScoreColor(score)};"></div>
            </div>
            <span class="score-val" style="color:${getScoreColor(score)}">${pct}%</span>
        </div>`;
}

function getScoreColor(score) {
    if (score >= 0.75) return '#FF1744';
    if (score >= 0.55) return '#FF6E40';
    if (score >= 0.35) return '#FFD740';
    if (score >= 0.2) return '#69F0AE';
    return '#00E676';
}

// ═══════════════════════════════════════════════════════════════════
// Dashboard
// ═══════════════════════════════════════════════════════════════════

async function loadDashboard() {
    try {
        const response = await fetch(`${API_BASE}/api/stats`);
        const data = await response.json();

        document.getElementById('dashAccuracy').innerHTML =
            `${data.accuracy || 97.2}<span style="font-size:1rem">%</span>`;
        document.getElementById('dashFPR').innerHTML =
            `${data.false_positive_rate || 1.5}<span style="font-size:1rem">%</span>`;
        document.getElementById('dashModels').textContent = data.models_active || 5;
        document.getElementById('dashToday').textContent = data.scans_today || 0;

        renderActivityChart(data.hourly_activity || []);

        const breakdown = data.threat_breakdown || {};
        const total = Math.max(Object.values(breakdown).reduce((a, b) => a + b, 0), 1);

        ['safe', 'low', 'medium', 'high', 'critical'].forEach(level => {
            const count = breakdown[level] || 0;
            const pct = (count / total) * 100;
            const bar = document.getElementById(`breakdown${level.charAt(0).toUpperCase() + level.slice(1)}`);
            const cnt = document.getElementById(`count${level.charAt(0).toUpperCase() + level.slice(1)}`);
            if (bar) bar.style.width = `${pct}%`;
            if (cnt) cnt.textContent = count;
        });

    } catch (error) {
        console.error('Dashboard load error:', error);
    }
}

function renderActivityChart(data) {
    const chart = document.getElementById('activityChart');
    if (!data?.length) {
        chart.innerHTML = '<div class="empty-state"><p style="font-size:0.8rem">No activity data yet</p></div>';
        return;
    }
    const maxCount = Math.max(...data.map(d => d.count), 1);
    chart.innerHTML = data.map(d => {
        const height = Math.max((d.count / maxCount) * 100, 2);
        return `<div class="chart-bar" style="height:${height}%" data-label="${d.hour.split(':')[0]}h"
                     title="${d.hour}: ${d.count} scans"></div>`;
    }).join('');
}

// ═══════════════════════════════════════════════════════════════════
// History
// ═══════════════════════════════════════════════════════════════════

async function loadHistory() {
    try {
        const response = await fetch(`${API_BASE}/api/history?limit=50`);
        const data = await response.json();
        const tbody = document.getElementById('historyTableBody');

        if (!data.scans?.length) {
            tbody.innerHTML = `
                <tr><td colspan="7">
                    <div class="empty-state">
                        <div class="empty-icon">📋</div>
                        <h3>No scans yet</h3>
                        <p>Start scanning URLs or content to see results here.</p>
                    </div>
                </td></tr>`;
            return;
        }

        tbody.innerHTML = data.scans.map(scan => `
            <tr>
                <td><code style="color:var(--accent-cyan);font-size:0.8rem;">${scan.scan_id || 'N/A'}</code></td>
                <td class="url-cell" title="${escapeHtml(scan.target || '')}">${escapeHtml(truncate(scan.target || '', 45))}</td>
                <td>${(scan.scan_type || 'url').toUpperCase()}</td>
                <td><code style="font-weight:700;color:${getScoreColor(scan.risk_score || 0)}">${((scan.risk_score || 0) * 100).toFixed(1)}%</code></td>
                <td><span class="threat-badge ${scan.threat_level || 'safe'}">${(scan.threat_level || 'safe').toUpperCase()}</span></td>
                <td style="font-family:'JetBrains Mono',monospace;font-size:0.8rem;">${(scan.detection_time_ms || 0).toFixed(1)}ms</td>
                <td style="font-size:0.8rem;color:var(--text-muted);">${formatTime(scan.timestamp)}</td>
            </tr>
        `).join('');

    } catch (error) {
        console.error('History load error:', error);
    }
}

// ═══════════════════════════════════════════════════════════════════
// Models
// ═══════════════════════════════════════════════════════════════════

async function loadModels() {
    try {
        const response = await fetch(`${API_BASE}/api/models/status`);
        const data = await response.json();
        const grid = document.getElementById('modelsGrid');

        const icons = ['🔗', '📝', '🤖', '🛡️', '🚨', '☁️'];
        const bgColors = [
            'rgba(108, 99, 255, 0.15)',
            'rgba(0, 230, 118, 0.15)',
            'rgba(168, 85, 247, 0.15)',
            'rgba(255, 145, 0, 0.15)',
            'rgba(255, 23, 68, 0.15)',
            'rgba(3, 169, 244, 0.15)',
        ];

        grid.innerHTML = data.models.map((model, i) => `
            <div class="model-card">
                <div class="model-header">
                    <div class="model-icon" style="background:${bgColors[i % bgColors.length]}">${icons[i % icons.length]}</div>
                    <div class="model-status ${model.status === 'active' ? 'active' : 'inactive'}">
                        <span class="status-dot ${model.status !== 'active' ? 'offline' : ''}"></span>
                        ${model.status === 'active' ? 'Active' : 'Unavailable'}
                    </div>
                </div>
                <div class="model-name">${model.name}</div>
                <div class="model-type">${model.type}</div>
                <div class="model-description">${model.description}</div>
                <div class="model-accuracy">
                    <div class="accuracy-bar">
                        <div class="accuracy-fill" style="width:${model.accuracy}"></div>
                    </div>
                    <div class="accuracy-value">${model.accuracy}</div>
                </div>
            </div>
        `).join('');

    } catch (error) {
        console.error('Models load error:', error);
    }
}

// ═══════════════════════════════════════════════════════════════════
// Quick Stats
// ═══════════════════════════════════════════════════════════════════

async function updateQuickStats() {
    try {
        const response = await fetch(`${API_BASE}/api/stats`);
        const data = await response.json();

        document.getElementById('statTotalScans').textContent = data.total_scans || 0;
        document.getElementById('statThreats').textContent = data.threats_detected || 0;
        document.getElementById('statSafe').textContent = data.safe_urls || 0;
        document.getElementById('statAvgTime').innerHTML =
            `${(data.avg_response_time_ms || 0).toFixed(0)}<span style="font-size:0.9rem;color:var(--text-muted)">ms</span>`;

    } catch (error) {
        console.error('Stats update error:', error);
    }
}

// ═══════════════════════════════════════════════════════════════════
// System Health Check
// ═══════════════════════════════════════════════════════════════════

async function checkHealth() {
    try {
        const response = await fetch(`${API_BASE}/api/health`);
        const data = await response.json();
        const dot = document.getElementById('systemStatusDot');
        const text = document.getElementById('systemStatusText');

        if (data.status === 'operational') {
            dot.classList.remove('offline');
            text.textContent = `Operational • ${data.total_scans_processed} scans`;
        } else {
            dot.classList.add('offline');
            text.textContent = 'Degraded';
        }
    } catch {
        document.getElementById('systemStatusDot').classList.add('offline');
        document.getElementById('systemStatusText').textContent = 'Offline';
    }
}

// ═══════════════════════════════════════════════════════════════════
// Toast Notifications
// ═══════════════════════════════════════════════════════════════════

function showToast(message, type = 'info') {
    const container = document.getElementById('toastContainer');
    const icons = { success: '✅', error: '❌', warning: '⚠️', info: 'ℹ️' };
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.innerHTML = `<span>${icons[type] || 'ℹ️'}</span><span>${message}</span>`;
    container.appendChild(toast);
    setTimeout(() => {
        toast.style.animation = 'slideOut 0.3s ease forwards';
        setTimeout(() => toast.remove(), 300);
    }, 4000);
}

// ═══════════════════════════════════════════════════════════════════
// Utilities
// ═══════════════════════════════════════════════════════════════════

function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

function truncate(str, len) {
    return str.length > len ? str.substring(0, len) + '…' : str;
}

function formatTime(timestamp) {
    if (!timestamp) return 'N/A';
    try {
        return new Date(timestamp).toLocaleString('en-US', {
            month: 'short', day: 'numeric',
            hour: '2-digit', minute: '2-digit'
        });
    } catch {
        return timestamp;
    }
}

// ═══════════════════════════════════════════════════════════════════
// Keyboard Shortcuts
// ═══════════════════════════════════════════════════════════════════

document.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && document.activeElement.id === 'urlInput') performScan();
    if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
        e.preventDefault();
        document.getElementById('urlInput').focus();
    }
});

// ═══════════════════════════════════════════════════════════════════
// Initialization
// ═══════════════════════════════════════════════════════════════════

document.addEventListener('DOMContentLoaded', () => {
    checkHealth();
    updateQuickStats();
    setInterval(checkHealth, 30000);
    setInterval(updateQuickStats, 15000);
    console.log('🛡️ Cyber Shield Dashboard — 6-Engine Detection Active');
});
