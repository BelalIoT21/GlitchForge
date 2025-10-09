/**
 * GlitchForge Web Dashboard - Frontend JavaScript
 */

const API_BASE = 'http://localhost:5000/api';

// ============================================================================
// Dashboard Functions
// ============================================================================

async function loadStats() {
    try {
        const response = await fetch(`${API_BASE}/stats`);
        const data = await response.json();
        
        if (data.success) {
            const stats = data.stats;
            document.getElementById('total-vulns').textContent = stats.total_vulnerabilities.toLocaleString();
            document.getElementById('high-risk').textContent = stats.high_risk.toLocaleString();
            document.getElementById('model-features').textContent = stats.model_features;
            document.getElementById('avg-risk').textContent = stats.avg_risk_score.toFixed(2);
        }
    } catch (error) {
        console.error('Error loading stats:', error);
    }
}

async function loadVulnerabilities() {
    const tbody = document.getElementById('vulns-tbody');
    const loading = document.getElementById('loading-indicator');
    
    if (loading) loading.style.display = 'inline';
    
    try {
        const response = await fetch(`${API_BASE}/vulnerabilities/list?limit=20`);
        const data = await response.json();
        
        if (data.success) {
            tbody.innerHTML = '';
            
            data.vulnerabilities.forEach(vuln => {
                const row = createVulnerabilityRow(vuln);
                tbody.appendChild(row);
            });
        } else {
            tbody.innerHTML = '<tr><td colspan="7" class="text-center">Error loading vulnerabilities</td></tr>';
        }
    } catch (error) {
        console.error('Error loading vulnerabilities:', error);
        tbody.innerHTML = '<tr><td colspan="7" class="text-center">Error loading vulnerabilities</td></tr>';
    } finally {
        if (loading) loading.style.display = 'none';
    }
}

function createVulnerabilityRow(vuln) {
    const row = document.createElement('tr');
    
    const riskLevel = getRiskLevel(vuln.risk_score);
    const riskClass = getRiskClass(riskLevel);
    
    row.innerHTML = `
        <td><strong>${vuln.cve_id}</strong></td>
        <td>${vuln.cvss_score.toFixed(1)}</td>
        <td>${vuln.risk_score.toFixed(2)}</td>
        <td><span class="risk-badge ${riskClass}">${riskLevel}</span></td>
        <td>${vuln.days_old}</td>
        <td>${vuln.exploit_available ? '✅ Yes' : '❌ No'}</td>
        <td>
            <button class="btn btn-primary" style="padding: 0.5rem 1rem; font-size: 0.85rem;" 
                    onclick="predictRisk('${vuln.cve_id}')">
                Predict
            </button>
            <button class="btn btn-secondary" style="padding: 0.5rem 1rem; font-size: 0.85rem;" 
                    onclick="explainFromTable('${vuln.cve_id}')">
                Explain
            </button>
        </td>
    `;
    
    return row;
}

function getRiskLevel(score) {
    if (score >= 9.0) return 'CRITICAL';
    if (score >= 7.0) return 'HIGH';
    if (score >= 4.0) return 'MEDIUM';
    return 'LOW';
}

function getRiskClass(level) {
    const classes = {
        'CRITICAL': 'risk-critical',
        'HIGH': 'risk-high',
        'MEDIUM': 'risk-medium',
        'LOW': 'risk-low'
    };
    return classes[level] || 'risk-low';
}

async function predictRisk(cveId) {
    try {
        const response = await fetch(`${API_BASE}/predict`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ cve_id: cveId })
        });
        
        const data = await response.json();
        
        if (data.success) {
            alert(`🎯 ML Prediction for ${data.cve_id}\n\n` +
                  `CVSS Score: ${data.cvss_score.toFixed(1)}\n` +
                  `Predicted Risk: ${data.predicted_risk.toFixed(2)}\n` +
                  `Risk Level: ${data.risk_level}\n\n` +
                  `Click "Explain" to see why!`);
        } else {
            alert('Error: ' + data.error);
        }
    } catch (error) {
        console.error('Error predicting risk:', error);
        alert('Error making prediction');
    }
}

function explainFromTable(cveId) {
    // Redirect to explain page with CVE ID
    window.location.href = `/explain?cve=${cveId}`;
}

// ============================================================================
// Scan Page Functions
// ============================================================================

async function startScan(event) {
    event.preventDefault();
    
    const form = document.getElementById('scan-form');
    const progressSection = document.getElementById('scan-progress');
    const resultsSection = document.getElementById('scan-results');
    const scanBtn = document.getElementById('scan-btn');
    
    // Get form data
    const targetUrl = document.getElementById('target-url').value;
    const scanTypes = [];
    
    if (document.querySelector('input[name="scan_sql"]').checked) scanTypes.push('sql');
    if (document.querySelector('input[name="scan_xss"]').checked) scanTypes.push('xss');
    if (document.querySelector('input[name="scan_csrf"]').checked) scanTypes.push('csrf');
    
    if (scanTypes.length === 0) {
        alert('Please select at least one vulnerability type to scan');
        return;
    }
    
    // Show progress
    progressSection.style.display = 'block';
    resultsSection.style.display = 'none';
    scanBtn.disabled = true;
    scanBtn.textContent = '⏳ Scanning...';
    
    // Animate progress
    animateProgress();
    
    try {
        const response = await fetch(`${API_BASE}/scan/start`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                target_url: targetUrl,
                scan_types: scanTypes
            })
        });
        
        const data = await response.json();
        
        if (data.success) {
            displayScanResults(data.results, data.summary);
            resultsSection.style.display = 'block';
        } else {
            alert('Scan failed: ' + data.error);
        }
    } catch (error) {
        console.error('Error during scan:', error);
        alert('Error during scan: ' + error.message);
    } finally {
        progressSection.style.display = 'none';
        scanBtn.disabled = false;
        scanBtn.textContent = '🚀 Start Scan';
    }
}

function animateProgress() {
    const progressFill = document.getElementById('progress-fill');
    const progressText = document.getElementById('progress-text');
    
    let progress = 0;
    const steps = [
        'Connecting to target...',
        'Authenticating...',
        'Testing SQL injection...',
        'Testing XSS vulnerabilities...',
        'Testing CSRF protection...',
        'Analyzing results...',
        'Complete!'
    ];
    
    const interval = setInterval(() => {
        progress += 1;
        progressFill.style.width = `${progress}%`;
        
        const stepIndex = Math.min(Math.floor(progress / 15), steps.length - 1);
        progressText.textContent = steps[stepIndex];
        
        if (progress >= 100) {
            clearInterval(interval);
        }
    }, 100);
}

function displayScanResults(results, summary) {
    const summaryDiv = document.getElementById('results-summary');
    const detailsDiv = document.getElementById('results-details');
    
    // Display summary
    summaryDiv.innerHTML = `
        <div class="result-card">
            <div class="result-value">${summary.total_scans}</div>
            <div class="result-label">Total Scans</div>
        </div>
        <div class="result-card">
            <div class="result-value">${summary.vulnerabilities_found}</div>
            <div class="result-label">Vulnerabilities Found</div>
        </div>
        <div class="result-card">
            <div class="result-value">${summary.high_confidence}</div>
            <div class="result-label">High Confidence</div>
        </div>
        <div class="result-card">
            <div class="result-value">${summary.medium_confidence}</div>
            <div class="result-label">Medium Confidence</div>
        </div>
    `;
    
    // Display detailed results
    detailsDiv.innerHTML = '<h3>Detailed Findings</h3>';
    
    results.forEach((result, index) => {
        const vulnCard = document.createElement('div');
        vulnCard.className = 'card';
        vulnCard.style.marginBottom = '1rem';
        
        const statusBadge = result.vulnerable 
            ? `<span class="risk-badge risk-critical">⚠️ VULNERABLE</span>`
            : `<span class="risk-badge risk-low">✅ SECURE</span>`;
        
        vulnCard.innerHTML = `
            <h4>${result.vulnerability_type} ${statusBadge}</h4>
            <p><strong>Endpoint:</strong> ${result.endpoint}</p>
            <p><strong>Confidence:</strong> ${result.confidence.toUpperCase()}</p>
            <p><strong>CWE ID:</strong> ${result.cwe_id}</p>
            ${result.vulnerable ? `
                <p><strong>Successful Payloads:</strong> ${result.successful_payloads?.length || 0}</p>
                <details style="margin-top: 1rem;">
                    <summary style="cursor: pointer; font-weight: bold;">View Payloads</summary>
                    <ul style="margin-top: 0.5rem;">
                        ${(result.successful_payloads || []).slice(0, 5).map(p => 
                            `<li><code>${p.type}</code>: ${escapeHtml(p.payload.substring(0, 50))}...</li>`
                        ).join('')}
                    </ul>
                </details>
            ` : ''}
        `;
        
        detailsDiv.appendChild(vulnCard);
    });
}

function clearResults() {
    document.getElementById('scan-results').style.display = 'none';
    document.getElementById('results-summary').innerHTML = '';
    document.getElementById('results-details').innerHTML = '';
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// ============================================================================
// Explain Page Functions
// ============================================================================

async function loadCVEList() {
    const select = document.getElementById('cve-select');
    
    if (!select) return;
    
    try {
        const response = await fetch(`${API_BASE}/vulnerabilities/list?limit=100`);
        const data = await response.json();
        
        if (data.success) {
            select.innerHTML = '<option value="">Select a CVE...</option>';
            
            data.vulnerabilities.forEach(vuln => {
                const option = document.createElement('option');
                option.value = vuln.cve_id;
                option.textContent = `${vuln.cve_id} (CVSS: ${vuln.cvss_score.toFixed(1)}, Risk: ${vuln.risk_score.toFixed(2)})`;
                select.appendChild(option);
            });
            
            // Check if CVE ID in URL
            const urlParams = new URLSearchParams(window.location.search);
            const cveParam = urlParams.get('cve');
            if (cveParam) {
                select.value = cveParam;
                // Trigger explanation
                const form = document.getElementById('explain-form');
                if (form) {
                    explainVulnerability(new Event('submit'));
                }
            }
        }
    } catch (error) {
        console.error('Error loading CVE list:', error);
        select.innerHTML = '<option value="">Error loading CVEs</option>';
    }
}

async function explainVulnerability(event) {
    event.preventDefault();
    
    const cveId = document.getElementById('cve-select').value;
    const explainBtn = document.getElementById('explain-btn');
    const resultSection = document.getElementById('explanation-result');
    
    if (!cveId) {
        alert('Please select a CVE');
        return;
    }
    
    explainBtn.disabled = true;
    explainBtn.textContent = '⏳ Generating explanation...';
    
    try {
        const response = await fetch(`${API_BASE}/explain`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ cve_id: cveId })
        });
        
        const data = await response.json();
        
        if (data.success) {
            displayExplanation(data);
            resultSection.style.display = 'block';
            
            // Scroll to results
            resultSection.scrollIntoView({ behavior: 'smooth' });
        } else {
            alert('Error: ' + data.error);
        }
    } catch (error) {
        console.error('Error explaining vulnerability:', error);
        alert('Error generating explanation');
    } finally {
        explainBtn.disabled = false;
        explainBtn.textContent = '🔍 Generate Explanation';
    }
}

function displayExplanation(data) {
    const summaryDiv = document.getElementById('prediction-summary');
    const contributionsDiv = document.getElementById('feature-contributions');
    const humanExplCard = document.getElementById('human-explanation-card');
    const humanExplDiv = document.getElementById('human-explanation');
    
    // Display prediction summary
    const riskLevel = getRiskLevel(data.prediction);
    const riskClass = getRiskClass(riskLevel);
    
    summaryDiv.innerHTML = `
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-bottom: 1rem;">
            <div class="result-card">
                <div class="result-label">CVE ID</div>
                <div class="result-value" style="font-size: 1.5rem;">${data.cve_id}</div>
            </div>
            <div class="result-card">
                <div class="result-label">CVSS Score</div>
                <div class="result-value">${data.cvss_score.toFixed(1)}</div>
            </div>
            <div class="result-card">
                <div class="result-label">Predicted Risk</div>
                <div class="result-value">${data.prediction.toFixed(2)}</div>
            </div>
            <div class="result-card">
                <div class="result-label">Risk Level</div>
                <div><span class="risk-badge ${riskClass}">${riskLevel}</span></div>
            </div>
        </div>
    `;
    
    // Display human-readable explanation
    if (data.explanation) {
        humanExplCard.style.display = 'block';
        
        const exp = data.explanation;
        
        humanExplDiv.innerHTML = `
            <div class="explanation-section" style="margin-bottom: 2rem;">
                <h3 style="color: var(--primary); margin-bottom: 1rem;">📊 Risk Assessment</h3>
                <p style="font-size: 1.1rem; line-height: 1.8;">${formatMarkdown(exp.summary)}</p>
            </div>
            
            <div class="explanation-section" style="margin-bottom: 2rem;">
                <h3 style="color: var(--primary); margin-bottom: 1rem;">🔍 Why This Risk Score?</h3>
                <ul style="list-style: none; padding: 0;">
                    ${exp.why_this_score.map(reason => `
                        <li style="padding: 0.75rem; margin-bottom: 0.5rem; background: var(--light); border-radius: 8px; border-left: 4px solid var(--primary);">
                            ${formatMarkdown(reason)}
                        </li>
                    `).join('')}
                </ul>
            </div>
            
            <div class="explanation-section" style="margin-bottom: 2rem;">
                <h3 style="color: var(--danger); margin-bottom: 1rem;">⚠️ What Is ${exp.vulnerability_type}?</h3>
                <p style="line-height: 1.8; padding: 1rem; background: rgba(239, 71, 111, 0.1); border-radius: 8px;">
                    ${exp.attack_scenario}
                </p>
            </div>
            
            <div class="explanation-section">
                <h3 style="color: var(--success); margin-bottom: 1rem;">✅ How To Fix This</h3>
                <ol style="line-height: 1.8;">
                    ${exp.how_to_fix.map(fix => `<li style="margin-bottom: 0.5rem;">${fix}</li>`).join('')}
                </ol>
            </div>
        `;
    }
    
    // Display technical feature contributions
    contributionsDiv.innerHTML = '';
    
    data.top_features.forEach((feature, index) => {
        const featureDiv = document.createElement('div');
        const isPositive = feature.shap_value > 0;
        
        featureDiv.className = `feature-item ${isPositive ? 'feature-positive' : 'feature-negative'}`;
        featureDiv.innerHTML = `
            <div>
                <div class="feature-name">${index + 1}. ${feature.feature}</div>
                <div class="feature-value">Value: ${feature.value.toFixed(3)}</div>
            </div>
            <div class="feature-shap ${isPositive ? 'shap-positive' : 'shap-negative'}">
                ${isPositive ? '+' : ''}${feature.shap_value.toFixed(4)}
            </div>
        `;
        
        contributionsDiv.appendChild(featureDiv);
    });
}

// Helper function to format markdown-style text
function formatMarkdown(text) {
    return text
        .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')  // Bold
        .replace(/\*(.*?)\*/g, '<em>$1</em>');             // Italic
}

// ============================================================================
// Utility Functions
// ============================================================================

// Auto-refresh images every 30 seconds
setInterval(() => {
    const images = document.querySelectorAll('.viz-image');
    images.forEach(img => {
        const src = img.src;
        img.src = src.split('?')[0] + '?t=' + new Date().getTime();
    });
}, 30000);

// Make functions globally available
window.loadStats = loadStats;
window.loadVulnerabilities = loadVulnerabilities;
window.predictRisk = predictRisk;
window.explainFromTable = explainFromTable;
window.startScan = startScan;
window.clearResults = clearResults;
window.loadCVEList = loadCVEList;
window.explainVulnerability = explainVulnerability;