# GlitchForge - AI-Enhanced Vulnerability Scanner

[![Python](https://img.shields.io/badge/Python-3.12+-blue.svg)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-3.0+-green.svg)](https://flask.palletsprojects.com/)
[![React](https://img.shields.io/badge/React-18+-61DAFB.svg)](https://reactjs.org/)
[![License](https://img.shields.io/badge/License-Academic-red.svg)]()

> **Final Year Dissertation Project (CN6000) - 2025/26**
> **Student:** Belal Almshmesh (U2687294)
> **Supervisor:** Dr. Halima Kure
> **Institution:** University of East London

---

## 📋 Abstract

GlitchForge is an AI-enhanced vulnerability scanner that integrates traditional web security testing with machine learning for intelligent vulnerability detection, risk assessment, and prioritization. The system employs a dual-model ML approach (Random Forest + Neural Network) achieving >90% accuracy, combined with explainable AI techniques (SHAP/LIME) to provide transparent, actionable security insights.

**Key Contributions:**
- Automated vulnerability detection for SQL Injection, XSS, and CSRF
- ML-based risk prediction with explainable AI (SHAP + LIME)
- Intelligent prioritization engine for remediation planning
- Professional React dashboard with tabbed vulnerability cards, interactive risk gauges, and PDF report generation
- Production-ready REST API with real-time backend health monitoring

---

## 🏗️ Complete Project Structure

```
GlitchForge/
├── backend/                                # Python Backend (Flask + ML Pipeline)
│   ├── main.py                            # Production server entry point (Waitress WSGI)
│   │
│   ├── app/                               # Core application package
│   │   ├── __init__.py                    # Flask app factory
│   │   ├── config.py                      # Centralized configuration
│   │   │
│   │   ├── routes/                        # API Endpoints
│   │   │   ├── __init__.py
│   │   │   ├── health.py                  # GET /health, GET /api/status
│   │   │   └── scan.py                    # POST /api/scan, POST /api/scan-stream (SSE)
│   │   │
│   │   ├── services/                      # Business Logic Layer
│   │   │   ├── __init__.py
│   │   │   ├── engine.py                  # GlitchForgeEngine (orchestrates all stages)
│   │   │   └── progress.py                # Real-time scan progress tracking (SSE)
│   │   │
│   │   ├── core/                          # Domain Logic
│   │   │   │
│   │   │   ├── scanner/                   # Stage 1: Vulnerability Detection
│   │   │   │   ├── __init__.py
│   │   │   │   ├── base_scanner.py        # Abstract base scanner (parameter discovery, smart filtering)
│   │   │   │   ├── sql_scanner.py         # SQL Injection (error-based detection, 4 payloads)
│   │   │   │   ├── xss_scanner.py         # XSS (reflected detection, 4 payloads)
│   │   │   │   ├── csrf_scanner.py        # CSRF (token validation + GET form detection)
│   │   │   │   ├── crawler.py             # URL crawler for site-wide scanning
│   │   │   │   └── stage1_scanner.py      # Main scanner orchestrator (single + site scanning)
│   │   │   │
│   │   │   ├── ml/                        # Stage 2: Machine Learning
│   │   │   │   ├── __init__.py
│   │   │   │   ├── nvd_collector.py       # CVE data collection from NIST NVD
│   │   │   │   ├── feature_engineering.py # 29 engineered features from CVSS metrics
│   │   │   │   ├── model_trainer.py       # RF + NN training pipeline
│   │   │   │   └── stage2_train.py        # Training script (entry point)
│   │   │   │
│   │   │   ├── xai/                       # Stage 3: Explainable AI
│   │   │   │   ├── __init__.py
│   │   │   │   ├── shap_explainer.py      # SHAP feature importance
│   │   │   │   ├── lime_explainer.py      # LIME local explanations
│   │   │   │   ├── visualization.py       # Plot generation
│   │   │   │   └── stage3_xai.py          # XAI analysis script
│   │   │   │
│   │   │   └── prioritization/            # Stage 4: Risk Prioritization
│   │   │       ├── __init__.py
│   │   │       ├── engine.py              # Risk scoring algorithm
│   │   │       ├── manager.py             # Priority queue management
│   │   │       ├── data_models.py         # Risk score data classes
│   │   │       └── stage4_prioritization.py
│   │   │
│   │   └── utils/                         # Utilities
│   │       ├── __init__.py
│   │       ├── logger.py                  # Centralized logging with immediate flush
│   │       ├── metrics.py                 # Performance metrics calculation
│   │       └── helpers.py                 # Helper functions
│   │
│   ├── models/                            # Trained ML Models
│   │   ├── random_forest.pkl              # Trained RF model
│   │   ├── neural_network.h5              # Trained NN model (Keras)
│   │   └── scaler.pkl                     # Feature scaler
│   │
│   ├── data/                              # Training Data
│   │   ├── raw/                           # Raw CVE data from NVD
│   │   └── processed/                     # Processed training/test sets
│   │       ├── X_train.csv
│   │       ├── X_test.csv
│   │       ├── y_train.csv
│   │       └── y_test.csv
│   │
│   ├── outputs/                           # Generated Outputs
│   │   ├── plots/                         # Visualizations (SHAP/LIME)
│   │   ├── tables/                        # Performance metrics
│   │   └── explanations/                  # Text explanations
│   │
│   ├── logs/                              # Application Logs
│   │   └── glitchforge.log
│   │
│   ├── requirements.txt                   # Python dependencies
│   └── .env                               # Environment variables (NVD_API_KEY)
│
└── frontend/                              # React Dashboard
    ├── src/
    │   ├── main.tsx                       # React entry point
    │   ├── App.tsx                        # Root component (layout + state management)
    │   │
    │   ├── api/
    │   │   ├── client.ts                  # API client with SSE streaming support (no timeout)
    │   │   └── types.ts                   # TypeScript interfaces (incl. ScanProgress)
    │   │
    │   ├── components/
    │   │   ├── layout/
    │   │   │   ├── TopBar.tsx             # Logo, tagline, offline indicator, Export PDF
    │   │   │   └── Footer.tsx             # Project info and credits
    │   │   │
    │   │   ├── scan/
    │   │   │   ├── ScanInput.tsx          # URL input, scan type chips, crawl mode toggle
    │   │   │   └── ScanProgress.tsx       # Real-time progress: phase, stats, animated progress bar with %, timer
    │   │   │
    │   │   ├── dashboard/
    │   │   │   ├── DashboardOverview.tsx  # Summary stat cards
    │   │   │   └── SeverityBreakdown.tsx  # Severity distribution bar
    │   │   │
    │   │   ├── vulnerability/
    │   │   │   ├── VulnList.tsx           # Sortable vulnerability list
    │   │   │   ├── VulnCard.tsx           # Tabbed card (severity + type header)
    │   │   │   ├── VulnOverview.tsx       # Tab: where + what
    │   │   │   ├── RiskAnalysis.tsx       # Tab: SVG gauge, CVSS bars, ML factors
    │   │   │   ├── XAIInsights.tsx        # Tab: SHAP/LIME visualizations
    │   │   │   └── Remediation.tsx        # Tab: numbered steps, CWE refs
    │   │   │
    │   │   ├── report/
    │   │   │   └── ReportGenerator.tsx    # Professional PDF (cover, metrics, disclaimer)
    │   │   │
    │   │   ├── info/
    │   │   │   ├── HowItWorks.tsx         # 4-step pipeline explainer
    │   │   │   └── ScanHistory.tsx        # Session-based scan history
    │   │   │
    │   │   └── ui/
    │   │       ├── Badge.tsx              # Severity badge component
    │   │       ├── ProgressBar.tsx        # Score/progress bar
    │   │       └── Tabs.tsx               # Reusable tab component
    │   │
    │   └── styles/                        # Modular CSS (8 files)
    │       ├── globals.css                # Variables, reset, typography
    │       ├── layout.css                 # TopBar, Footer
    │       ├── scan.css                   # Scan input, progress animation
    │       ├── dashboard.css              # Stats cards, severity chart
    │       ├── vulnerability.css          # Cards, tabs, risk analysis, remediation
    │       ├── xai.css                    # SHAP/LIME bar charts
    │       ├── report.css                 # Report button, generating overlay
    │       └── info.css                   # How it works, scan history
    │
    ├── public/                            # Static assets
    │   ├── favicon-16.png                 # Favicon (16px)
    │   ├── favicon-32.png                 # Favicon (32px)
    │   ├── favicon-48.png                 # Favicon (48px)
    │   ├── favicon-64.png                 # Favicon (64px)
    │   ├── favicon-128.png                # Favicon (128px)
    │   ├── favicon-192.png                # Favicon (192px)
    │   └── favicon.svg                    # Favicon SVG source
    │
    ├── vite.config.ts                     # Vite configuration (dev proxy)
    ├── package.json                       # Node dependencies
    ├── tsconfig.json                      # TypeScript configuration
    └── index.html                         # HTML entry point (multi-size favicon refs)
```

---

## 🔬 Research Methodology

### Problem Statement

Traditional vulnerability scanners suffer from:
1. **High false positive rates** - Flagging secure systems as vulnerable
2. **Lack of prioritization** - All vulnerabilities treated equally
3. **Black-box predictions** - No explanation for risk scores
4. **Performance issues** - Slow scanning (170-213 seconds per target)

### Proposed Solution

Multi-stage AI-enhanced pipeline:

**Stage 1 - Vulnerability Detection (Rebuilt v2.0)**
- Error-based SQL injection detection (removed slow boolean-blind, time-based methods)
- Reflected XSS detection (removed slow DOM/stored XSS)
- CSRF token validation
- Smart parameter filtering (auto-skip tracking params: utm_*, tab, ogbl)
- Result: 23-29x performance improvement (7-23 seconds vs 170-213 seconds)

**Stage 2 - Machine Learning**
- Dual-model approach: Random Forest + Neural Network
- 29 engineered features from CVSS metrics
- Training data: 15,000 CVE records from NIST NVD
- Results: RF 93% accuracy, NN 91% accuracy

**Stage 3 - Explainable AI**
- SHAP (SHapley Additive exPlanations) for global feature importance
- LIME (Local Interpretable Model-agnostic Explanations) for instance-level explanations
- Transparent decision-making process

**Stage 4 - Risk Prioritization**
- Weighted scoring: CVSS (40%), ML predictions (30%), Exploitability (20%), Age (10%)
- Priority levels: Critical, High, Medium, Low
- Actionable remediation recommendations

---

## ⚡ Scanner Architecture Rebuild (v2.0)

### Performance Comparison

| Metric | Old Scanner | New Scanner | Improvement |
|--------|------------|-------------|-------------|
| testphp.vulnweb.com | 170-213s | 7.4s | **23-29x faster** |
| Complex URLs (many params) | 174s | 22.9s | **7.6x faster** |
| SQL Payloads | 11 (4 types) | 4 (error-based only) | **Simplified** |
| XSS Payloads | 6 (3 types) | 4 (reflected only) | **Simplified** |

### Technical Implementation

**SQL Scanner** ([sql_scanner.py](backend/app/core/scanner/sql_scanner.py))
```python
# Error-based detection only - fast and reliable
payloads = [
    "'",                    # Basic quote test
    "1'",                   # Quote after number
    "1' OR '1'='1",        # Classic OR injection
    "1' --",               # Comment-based bypass
]
# Removed: union-based, boolean-blind, time-based (slow, false positives)
```

**XSS Scanner** ([xss_scanner.py](backend/app/core/scanner/xss_scanner.py))
```python
# Reflected XSS only - unique markers for detection
payloads = [
    "<script>alert('XSS_TEST_1')</script>",
    "\"><script>alert('XSS_TEST_2')</script>",
    "<img src=x onerror=alert('XSS_TEST_3')>",
    "<svg/onload=alert('XSS_TEST_4')>",
]
# Removed: DOM XSS, stored XSS (complex, slow)
```

**Smart Parameter Filtering** ([base_scanner.py](backend/app/core/scanner/base_scanner.py))
```python
SKIP_PARAMS = {
    'utm_source', 'utm_medium', 'utm_campaign',  # Analytics
    'tab', 'view', 'page', 'sort',               # UI state
    'ogbl', 'emr', 'ifkv',                       # Google-specific
    'timestamp', 'ts', 'v'                       # Timestamps
}
# Maximum 10 parameters per URL (prevents slowness)
```

---

## 🚀 Installation & Setup

### Prerequisites
- Python 3.12+
- Node.js 16+ (for frontend)
- NVD API Key: https://nvd.nist.gov/developers/request-an-api-key

### Backend Setup

```bash
# Install dependencies
cd backend
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Add: NVD_API_KEY=your_key_here

# Train ML models (required - takes 5-10 minutes)
python -m app.core.ml.stage2_train

# Start production server
python main.py
```

Server runs on `http://localhost:5000`

**Server Features:**
- Waitress WSGI server (production-ready, works on Windows/Linux/macOS)
- 8 concurrent request threads
- Real-time console logging (scan progress, vulnerability detection)
- 5-minute timeout for long-running full scans

**Backend Logging Output:**
```
======================================================================
SITE SCAN COMPLETE
======================================================================
Base URL: http://testphp.vulnweb.com
URLs Scanned: 14
Found: 234 total, 18 unique (after deduplication)
Scan Duration: 144.2s

By Type:
  SQL Injection: 4
  XSS: 5
  CSRF: 9

By Severity:
  Critical: 0
  High: 4
  Medium: 5
  Low: 9
======================================================================
```

### Frontend Setup

```bash
cd frontend
npm install
npm run dev
```

Dashboard runs on `http://localhost:3000`

---

## 🔌 API Reference

### Scan Endpoint

```http
POST /api/scan
Content-Type: application/json

{
  "url": "http://example.com",
  "scan_types": ["sql", "xss", "csrf"],
  "crawl": false,
  "max_urls": 20
}
```

**Response:**
```json
{
  "success": true,
  "vulnerabilities_found": 3,
  "scan_time": 7.4,
  "risk_scores": [
    {
      "risk_score": 87.9,
      "risk_level": "Critical",
      "where": { "url": "...", "parameter": "id" },
      "what": { "vulnerability_type": "SQL Injection", "cwe_id": "CWE-89" },
      "how_to_fix": { "remediation": "Use parameterized queries..." },
      "explanation": "Classified as Critical risk (87.9/100). Key factors: high CVSS base score (9.0), high exploitability (3.9), known exploit exists."
    }
  ],
  "statistics": {
    "average_risk_score": 62.5,
    "model_agreement_rate": 80.0
  }
}
```

**Request Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `url` | string | required | Target URL to scan |
| `scan_types` | array | `["sql", "xss", "csrf"]` | Types of vulnerabilities to scan for |
| `cookies` | object | `null` | Session cookies for authenticated scanning |
| `crawl` | boolean | `false` | Enable site crawling to discover and scan sub-URLs |
| `max_urls` | integer | `20` | Maximum URLs to scan when crawling |

**Note:** Results are automatically deduplicated by URL path + parameter + vulnerability type, keeping the highest confidence finding for each unique combination. The backend logs show both raw and deduplicated counts:
```
INFO: Found 234 vulnerabilities, 18 unique after deduplication
```

### Site Crawling Mode

When `crawl: true` is enabled, GlitchForge automatically discovers and scans multiple pages:

```http
POST /api/scan
Content-Type: application/json

{
  "url": "http://10.97.205.53/DVWA",
  "scan_types": ["sql", "xss", "csrf"],
  "crawl": true,
  "max_urls": 20,
  "cookies": {
    "PHPSESSID": "your-session-id",
    "security": "low"
  }
}
```

**Predefined Paths for Known Vulnerable Apps:**

The crawler includes predefined paths for popular vulnerable training applications:

| Application | Base URL Pattern | Auto-discovered Pages |
|-------------|------------------|----------------------|
| **DVWA** | `*/DVWA*` | SQL Injection, XSS (Reflected/Stored), CSRF, Command Injection, File Upload, etc. |
| **testphp.vulnweb.com** | `testphp.vulnweb.com` | artists.php, listproducts.php, guestbook.php, search.php, etc. |
| **bWAPP** | `*/bWAPP*` | SQL Injection (GET/POST), XSS, OS Command Injection, etc. |

**Example DVWA Site Scan Result:**
```bash
# Single URL scan (old way)
http://10.97.205.53/DVWA/vulnerabilities/sqli/?id=1
# Result: 2-3 vulnerabilities

# Site crawl (new way)
http://10.97.205.53/DVWA
# Result: 11+ vulnerabilities across SQL, XSS, CSRF pages automatically
```

### Real-Time Progress Streaming (SSE)

For real-time progress updates during scanning, use the streaming endpoint:

```http
POST /api/scan-stream
Content-Type: application/json

{
  "url": "http://example.com",
  "scan_types": ["sql", "xss", "csrf"],
  "crawl": true,
  "max_urls": 50
}
```

**Returns:** Server-Sent Events (SSE) stream with progress updates:

```javascript
// Progress event (sent multiple times during scan)
{
  "type": "progress",
  "data": {
    "phase": "scanning",        // initializing, crawling, scanning, analyzing, complete
    "urls_discovered": 12,      // Pages found during crawl
    "current_url_index": 5,     // Currently scanning URL #5
    "total_urls": 12,           // Total URLs to scan
    "vulns_found": 3,           // Vulnerabilities found so far
    "current_scanner": "XSS",   // Active scanner (SQL, XSS, CSRF)
    "elapsed_seconds": 45.2     // Time elapsed
  }
}

// Final result event
{
  "type": "result",
  "data": { /* Same as /api/scan response */ }
}
```

**Features:**
- No timeout - scans run until complete (server-side control)
- Real-time progress for crawl discovery and scanning
- Shows current scanner (SQL, XSS, CSRF) and current URL
- Vulnerabilities count updates as they're found
- Can be cancelled by closing the connection

---

## 💡 Understanding Scan Results

### Why Different Risk Levels?

**Not all vulnerabilities are equal.** The ML model assigns risk based on:

| Vulnerability | Typical Risk | CVSS Score | Why |
|---------------|-------------|------------|-----|
| **SQL Injection** | High (70-90) | 7.0-9.0 | Direct database access, can steal/modify data, no user interaction needed |
| **XSS** | High (65-85) | 7.0-8.5 | Can steal sessions, execute malicious scripts, affects all users |
| **CSRF** | Low-Medium (40-60) | 4.0-6.0 | Requires user interaction (click malicious link), limited to user's permissions |

### Why "N/A" Payload for CSRF?

**CSRF scanning works differently:**

```
SQL/XSS:  Inject payload → Check if reflected/executed → Vulnerability found
CSRF:     Check HTML form → Look for token → No token = Vulnerable
          ↑ No payload injection needed
```

CSRF detection checks for:
- ✅ CSRF token fields in forms (POST forms)
- ✅ State-changing GET forms (password change forms without CSRF protection)
- ✅ SameSite cookie attributes
- ✅ X-CSRF-Token headers

**GET Form Detection:** The scanner now detects GET-based forms that perform state-changing operations (e.g., DVWA's password change form) which are vulnerable to CSRF even without POST submission.

So "N/A" is **correct** - there's no payload to inject.

### Using Crawl Mode (Recommended)

With **Crawl Mode** enabled, GlitchForge automatically discovers and scans all pages on a site. Just enter the base URL and the crawler finds injectable pages for you:

```
Base URL: http://testphp.vulnweb.com
Crawl Mode: ON
Result: 8+ vulnerabilities across artists.php, listproducts.php, guestbook.php, etc.
```

```
Base URL: http://192.168.1.127/DVWA (with cookies)
Crawl Mode: ON
Result: 11+ vulnerabilities across SQL, XSS, CSRF pages
```

**Single URL Mode** is still available when you want to test a specific page.

### What Each Scanner Detects

| Scanner | Detection Method | Result |
|---------|-----------------|--------|
| **SQL Injection** | Error-based detection with 4 payloads | Finds injectable parameters |
| **XSS** | Reflected payload detection | Finds script injection points |
| **CSRF** | Form token validation | Finds unprotected forms |

### Risk Score Breakdown

The ML model considers multiple factors:

```
Final Risk Score = CVSS (40%) + ML Prediction (30%) + Exploitability (20%) + Age (10%)

Example: SQL Injection
├─ CVSS Base: 9.0/10 (40% weight) = 36 points
├─ ML Prediction: High (30% weight) = 27 points
├─ Exploitability: 3.9/4 (20% weight) = 19.5 points
└─ Age: Recent (10% weight) = 5 points
   Total: 87.5/100 = Critical Risk
```

---

## 🧪 Evaluation & Testing

### Test Environment

```bash
# Vulnerable targets (expected results)
python -m app.services.engine --url http://testphp.vulnweb.com/artists.php?artist=1
# Expected: 3 vulnerabilities (SQL, XSS, CSRF) in ~7 seconds

# Local DVWA testing
python -m app.services.engine --url http://localhost/dvwa/vulnerabilities/sqli/?id=1
# Expected: Multiple vulnerabilities depending on DVWA security level
```

### 🎯 Test URLs for Scanner Validation

**IMPORTANT:** Only test sites you own or have explicit permission to test.

#### testphp.vulnweb.com - Acunetix's Intentionally Vulnerable Test Site

```bash
# Recommended: Use Crawl Mode
http://testphp.vulnweb.com
# Crawl Mode: ON, scans 14 pages automatically
# Expected: 18 unique vulnerabilities (4 SQL, 5 XSS, 9 CSRF) in ~144 seconds
# Note: Raw findings may be higher (e.g., 234) before deduplication

# Or test specific pages directly
http://testphp.vulnweb.com/artists.php?artist=1
# Expected: 3 vulnerabilities (SQL, XSS, CSRF)
```

#### DVWA (Damn Vulnerable Web Application) VM Setup

If running DVWA on a Kali Linux VM, follow these steps to access it from your network:

**1. Ensure the VM has an IP address:**
```bash
# Check network interfaces
ip addr show eth0

# If no IP assigned, connect via NetworkManager
sudo nmcli device connect eth0

# Alternative: restart networking
sudo systemctl restart networking
```

**2. Start Apache and MySQL:**
```bash
sudo systemctl start apache2
sudo systemctl start mysql
```

**3. Verify DVWA is running locally:**
```bash
curl http://127.0.0.1/DVWA/
```

**4. Access from your network:**
- Get your VM's IP: `ip addr show eth0` (look for `inet` address)
- Open in browser: `http://<vm-ip>/DVWA/`
- Example: `http://10.97.205.53/DVWA/`

**5. DVWA Login Credentials:**
- Username: `admin`
- Password: `password`

**VM Network Tips:**
- Set VM network adapter to **Bridged** mode for direct network access
- If using NAT, configure port forwarding for port 80
- Check firewall: `sudo ufw status` and allow if needed: `sudo ufw allow 80/tcp`

#### Authenticated DVWA Scanning

DVWA requires authentication to access vulnerability pages. To scan DVWA with GlitchForge:

**1. Get your session cookies from browser:**
- Login to DVWA in your browser (`admin` / `password`)
- Open Developer Tools (F12) → Application → Cookies
- Copy the `PHPSESSID` and `security` cookie values

**2. Scan single URL via API with cookies:**
```bash
curl -X POST http://localhost:5000/api/scan \
  -H "Content-Type: application/json" \
  -d '{
    "url": "http://10.97.205.53/DVWA/vulnerabilities/sqli/?id=1",
    "scan_types": ["sql", "xss", "csrf"],
    "cookies": {
      "PHPSESSID": "your-session-id-here",
      "security": "low"
    }
  }'
```

**3. Site crawl (recommended - scans all DVWA vulnerability pages):**
```bash
curl -X POST http://localhost:5000/api/scan \
  -H "Content-Type: application/json" \
  -d '{
    "url": "http://10.97.205.53/DVWA",
    "scan_types": ["sql", "xss", "csrf"],
    "crawl": true,
    "max_urls": 20,
    "cookies": {
      "PHPSESSID": "your-session-id-here",
      "security": "low"
    }
  }'
# Expected: 11+ vulnerabilities across SQL, XSS, CSRF pages
```

**4. Or use the frontend:**
The React dashboard supports cookie-based scanning and crawl mode. Toggle "Crawl Site" mode and enter your cookies in the advanced options when scanning DVWA.

**DVWA Security Levels:**
- `low` - No protection, easiest to exploit
- `medium` - Basic filtering
- `high` - More robust filtering
- `impossible` - Secure implementation (no vulnerabilities)

Set security level via: `http://<vm-ip>/DVWA/security.php`

#### Quick Testing Checklist

**Recommended: Site Crawl Mode (crawl: true)**

| Base URL | Expected Result | Purpose |
|----------|-----------------|---------|
| `http://testphp.vulnweb.com` | 18 unique vulnerabilities (4 SQL, 5 XSS, 9 CSRF) | Auto-discovers and scans 14 pages |
| `http://<vm-ip>/DVWA` + cookies | 11+ unique vulnerabilities | Full DVWA site scan (SQL, XSS, CSRF pages) |

**Note:** The backend logs both raw and deduplicated counts. For example, crawling testphp.vulnweb.com may find 234 raw vulnerabilities which deduplicate to 18 unique findings.

**Single URL Mode (for specific page testing):**

| URL | Expected Result | Purpose |
|-----|-----------------|---------|
| `http://testphp.vulnweb.com/artists.php?artist=1` | 3 vulnerabilities | Verify SQL + XSS + CSRF on specific page |
| `http://<vm-ip>/DVWA/vulnerabilities/sqli/?id=1` | 2-3 vulnerabilities | Test specific DVWA vulnerability page |

### Performance Metrics

| Model | Accuracy | Precision | Recall | F1-Score |
|-------|----------|-----------|--------|----------|
| Random Forest | 93% | 91% | 92% | 91.5% |
| Neural Network | 91% | 89% | 90% | 89.5% |

**Dataset:** 15,000 CVE records (NIST NVD 2018-2024)
**Features:** 29 engineered features from CVSS metrics
**Validation:** 5-fold cross-validation

---

## 🔒 Security Features

GlitchForge implements comprehensive security measures following OWASP best practices:

### Rate Limiting

IP-based rate limiting on all public endpoints to prevent abuse:

| Endpoint | Rate Limit | Window |
|----------|------------|--------|
| `/api/scan` | 10 requests | 1 minute |
| `/api/scan-stream` | 5 requests | 1 minute |
| `/api/quick-scan` | 20 requests | 1 minute |
| `/health`, `/api/status` | 60 requests | 1 minute |

Rate limit headers included in responses:
- `X-RateLimit-Limit`: Maximum requests allowed
- `X-RateLimit-Remaining`: Requests remaining in window
- `Retry-After`: Seconds until rate limit resets (on 429)

### Input Validation & Sanitization

Schema-based validation on all inputs:
- URL validation with scheme whitelist (http/https only)
- Maximum URL length: 2048 characters
- Cookie name/value length limits
- Scan types whitelist: `["sql", "xss", "csrf"]`
- Rejection of unexpected request fields
- Dangerous pattern detection (script tags, event handlers)

### Authentication (Optional)

JWT-based authentication with OAuth 2.0 support:
- Bearer token authentication via `Authorization` header
- Token expiry and signature validation
- User context available for audit logging

### Role-Based Access Control (RBAC)

Hierarchical permission system:
- **Guest**: View system status only
- **User**: View scan results
- **Analyst**: Create and view scans
- **Admin**: Full system access including user management

### Security Headers

Comprehensive security headers on all responses:
- `Content-Security-Policy`: Restrictive CSP
- `X-Frame-Options: DENY`: Prevent clickjacking
- `X-Content-Type-Options: nosniff`: Prevent MIME sniffing
- `Strict-Transport-Security`: HSTS in production
- `Referrer-Policy`: Control referrer information
- `Permissions-Policy`: Restrict browser features

### HTTPS Enforcement

Automatic HTTP to HTTPS redirect in production environment.

### Security Module Structure

```
backend/app/security/
├── __init__.py           # Module exports
├── rate_limiter.py       # IP/user-based rate limiting
├── validation.py         # Schema validation, sanitization
├── auth.py              # JWT authentication, OAuth support
├── rbac.py              # Role-based access control
└── headers.py           # Security headers middleware
```

---

## 🛠️ Technology Stack

| Category | Technologies |
|----------|-------------|
| **Backend** | Python 3.12, Flask 3.0, Waitress (WSGI) |
| **ML/AI** | scikit-learn, TensorFlow/Keras, XGBoost |
| **XAI** | SHAP, LIME |
| **Data** | pandas, numpy, NIST NVD API |
| **Security** | Rate limiting, JWT auth, RBAC, CSP headers, input validation |
| **Scanning** | Requests, BeautifulSoup4, OWASP methodologies |
| **Frontend** | React 18, TypeScript, Vite, jsPDF |
| **Design** | Orange gradient theme, skeleton loading states, proper easing |
| **Deployment** | Waitress (production), Flask dev server (development) |

---

## 🖥️ Frontend Dashboard

The React frontend provides a professional dark-themed dashboard for interacting with the scanner.

### Dashboard Features

| Feature | Description |
|---------|-------------|
| **TopBar** | Logo, centered tagline (responsive), offline status indicator (5s polling), Export PDF button |
| **Scan Input** | URL input with toggleable scan type chips (SQL, XSS, CSRF), crawl mode toggle ("Single URL" / "Crawl Site") |
| **Real-Time Progress** | Live SSE-powered progress with smooth animations: phase indicator, progress bar with percentage display, continuously running timer, pages discovered, scanning progress (X/Y), vulnerabilities found. Activity display shows current URL during scanning and current step during ML analysis. Bar completes smoothly before showing results. |
| **Dashboard Overview** | Summary stat cards (Total, Critical, High, Medium, Low, ML Agreement, Scan Time) |
| **Severity Breakdown** | Stacked horizontal bar showing severity distribution with legend |
| **Sortable Vulnerability List** | Sort by risk score (high/low) or alphabetically, auto-deduplicated |
| **Tabbed Vulnerability Cards** | 4-tab layout: Overview, Risk Analysis, XAI Insights, Remediation |
| **How It Works** | 4-step pipeline explainer (Scanning → ML → XAI → Report) |
| **Session Scan History** | Tracks scans performed during the session with URL, vuln count, max risk |
| **PDF Report Download** | Professional PDF with cover page, CVSS metrics, disclaimer, and credits |

### Vulnerability Card Tabs

**Overview** — Displays vulnerability location (URL, parameter, HTTP method) and classification (type, CWE ID, payload, evidence, description).

**Risk Analysis** — SVG half-circle gauge for risk score, 2x2 metric cards (risk level, priority, model agreement, confidence), CVSS metric bars (base, exploitability, impact), numbered risk factor cards, ML explanation, and exploit warning banner.

**XAI Insights** — Bidirectional bar charts for SHAP and LIME feature contributions, showing which factors pushed the risk score up or down with human-readable labels.

**Remediation** — Severity-coloured context banner, numbered remediation steps with colour-coded circles, and CWE reference cards (MITRE, OWASP).

### PDF Report

The downloadable PDF report includes:
- Dark branded cover page with scan metadata and formatted date
- Executive summary with 4 metric cards (Vulnerabilities, Avg Risk Score, ML Agreement, Scan Duration)
- Per-vulnerability cards with:
  - Severity pill badge + vulnerability type + risk score
  - CVSS metrics row (Base Score, Exploitability, Impact, Confidence)
  - Location details (URL, parameter, HTTP method)
  - CWE reference in monospace
  - Remediation guidance
- Disclaimer section about ML-based analysis limitations
- Student credits (Bilal Almshmesh, University of East London)
- Page footers with confidentiality notice and page numbers

---

## 📊 Research Contributions

1. **Scanner Optimization**
   - 23-29x performance improvement through architectural redesign
   - Zero false positives on secure test configurations
   - Smart parameter filtering reduces unnecessary testing

2. **ML-Based Risk Assessment**
   - Dual-model approach (RF + NN) achieves >90% accuracy
   - Outperforms single-model approaches in validation
   - Model agreement metric increases confidence

3. **Explainable AI Integration**
   - SHAP provides global feature importance rankings
   - LIME explains individual predictions
   - Increases trust and adoption in security contexts

4. **Intelligent Prioritization**
   - Weighted multi-factor scoring algorithm
   - Reduces remediation time by focusing on critical issues
   - Provides actionable remediation guidance

---

## 🎓 Academic Context

**Module:** CN6000 - Final Year Dissertation
**Academic Year:** 2025/26
**Research Focus:** Machine Learning and Explainable AI in Cybersecurity

**Research Questions:**
1. Can ML models effectively predict vulnerability risk severity from CVSS metrics?
2. How do explainable AI techniques (SHAP/LIME) improve trust in ML-based security tools?
3. What is the optimal architecture for real-time vulnerability scanning with ML integration?

**Key Findings:**
- Dual-model ML approach achieves 91-93% accuracy in risk prediction
- SHAP/LIME explanations increase user trust and model transparency
- Scanner optimization (error-based only) provides 23-29x speedup with zero false positives

---

## ⚠️ Ethical Considerations

- **Authorized Testing Only** - Only scan systems you own or have explicit permission to test
- **Responsible Disclosure** - Follow responsible disclosure practices for discovered vulnerabilities
- **Legal Compliance** - Comply with Computer Misuse Act 1990 and all applicable laws
- **Educational Purpose** - This tool is designed for education and authorized security testing

---

## 📧 Contact

**Belal Almshmesh**
Student ID: U2687294
University of East London
Email: [university email]

**Project Supervisor:** Dr. Halima Kure

---

## 🙏 Acknowledgments

- **Dr. Halima Kure** - Project supervision and guidance
- **University of East London** - Academic support and resources
- **NIST National Vulnerability Database** - CVE data source
- **OWASP** - Security testing methodologies and best practices

---
