# GlitchForge - AI-Enhanced Vulnerability Scanner & Pentester

[![Python](https://img.shields.io/badge/Python-3.12+-blue.svg)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-3.0+-green.svg)](https://flask.palletsprojects.com/)
[![React](https://img.shields.io/badge/React-18+-61DAFB.svg)](https://reactjs.org/)
[![License](https://img.shields.io/badge/License-Academic-red.svg)]()

> **Final Year Dissertation Project (CN6000) - 2025/26**
> **Student:** Belal Almshmesh (U2687294)
> **Supervisor:** Dr. Halima Kure
> **Institution:** University of East London

---

## Abstract

GlitchForge is an AI-enhanced vulnerability scanner and pentester that goes beyond detection to **prove vulnerabilities are real** through controlled exploitation. Inspired by Shannon's "No Exploit, No Report" philosophy, GlitchForge validates every finding before reporting it, eliminating false positives.

The system combines five pipeline stages: vulnerability scanning, **pentest validation**, ML-based risk prediction (Random Forest + Neural Network, >90% accuracy), explainable AI (SHAP/LIME), and intelligent prioritization. Only confirmed or likely-exploitable vulnerabilities make it into the final report, with full exploitation evidence including reproducible proof-of-concept commands, HTTP request/response captures, and extracted data.

### GlitchForge vs Shannon

| | Shannon | GlitchForge |
|---|---|---|
| **Cost** | ~$50/scan (Claude API credits) | **100% Free** - runs entirely locally |
| **Dependencies** | Anthropic API key required | No API keys, no cloud, no credits |
| **Pentest engine** | LLM-driven (AI generates exploits) | **Deterministic rule-based** (Python exploitation techniques) |
| **Speed** | ~1-1.5 hours per scan | **Seconds to minutes** (focused scope, no LLM latency) |
| **Scope** | 15+ vulnerability types | 3 types (SQLi, XSS, CSRF) - focused and fast |
| **Target user** | Enterprise teams | **Students, researchers, individuals** - zero cost barrier |

---

## How It Works

GlitchForge uses a 5-stage pipeline. Every vulnerability must pass pentest validation before it reaches the dashboard.

```
Stage 1: Scan           Detect potential vulnerabilities (SQLi, XSS, CSRF)
    |
Stage 1.5: Pentest      Attempt controlled exploitation to prove each finding
    |                    Filter out false positives and unverified findings
    |
Stage 2: ML Predict     Random Forest + Neural Network risk prediction
    |
Stage 3: XAI Explain    SHAP + LIME feature contribution analysis
    |
Stage 4: Prioritize     Weighted risk scoring and remediation ordering
```

**Stage 1 - Vulnerability Scanning:**
Error-based SQL injection detection (4 payloads), reflected XSS detection (4 payloads), CSRF token validation, smart parameter filtering (auto-skip tracking params), and URL crawling for site-wide scanning.

**Stage 1.5 - Pentest Validation (new):**
For each scanner finding, attempts controlled exploitation to confirm the vulnerability is real:
- **SQL Injection:** UNION-based data extraction, boolean blind injection, time-based blind injection
- **XSS:** Canary reflection verification, context-aware escape payloads, CSP analysis
- **CSRF:** Cross-origin form submission without Origin/Referer, CSRF token omission testing

Collects structured evidence: HTTP request/response pairs, reproducible cURL commands, extracted data (e.g. database version), impact descriptions, and numbered reproduction steps.

Only `confirmed` and `likely` vulnerabilities pass through. False positives and unverified findings are filtered out before ML analysis.

**Stage 2 - Machine Learning:**
Dual-model approach (Random Forest + Neural Network) trained on 15,000 CVE records from NIST NVD. 29 engineered features from CVSS metrics. RF 93% accuracy, NN 91% accuracy.

**Stage 3 - Explainable AI:**
SHAP (global feature importance) and LIME (instance-level explanations) show exactly which factors drove each risk score up or down, with human-readable labels.

**Stage 4 - Risk Prioritization:**
Weighted scoring: CVSS (40%) + ML predictions (30%) + Exploitability (20%) + Age (10%). Priority levels: Critical, High, Medium, Low. Actionable remediation recommendations.

---

## Project Structure

```
GlitchForge/
|-- backend/                               # Python Backend (Flask + ML Pipeline)
|   |-- main.py                            # Production server (Waitress WSGI)
|   |
|   |-- app/
|   |   |-- __init__.py                    # Flask app factory
|   |   |-- config.py                      # Centralized configuration
|   |   |
|   |   |-- core/
|   |   |   |-- scanner/                   # Stage 1: Vulnerability Detection
|   |   |   |   |-- base_scanner.py        # Abstract base scanner
|   |   |   |   |-- sql_scanner.py         # SQL Injection (error-based, 4 payloads)
|   |   |   |   |-- xss_scanner.py         # XSS (reflected, 4 payloads)
|   |   |   |   |-- csrf_scanner.py        # CSRF (token + GET form detection)
|   |   |   |   |-- crawler.py             # URL crawler for site-wide scanning
|   |   |   |   +-- stage1_scanner.py      # Scanner orchestrator
|   |   |   |
|   |   |   |-- pentester/                 # Stage 1.5: Pentest Validation (NEW)
|   |   |   |   |-- data_models.py         # Evidence, result, and status dataclasses
|   |   |   |   |-- base_validator.py      # Abstract base validator (HTTP, cURL, safety)
|   |   |   |   |-- sqli_validator.py      # SQLi exploiter (UNION, blind, time-based)
|   |   |   |   |-- xss_validator.py       # XSS exploiter (canary, context, CSP)
|   |   |   |   |-- csrf_validator.py      # CSRF exploiter (no-origin, token omission)
|   |   |   |   +-- pentest_orchestrator.py # Orchestrates all validators
|   |   |   |
|   |   |   |-- ml/                        # Stage 2: Machine Learning
|   |   |   |   |-- nvd_collector.py       # CVE data collection from NIST NVD
|   |   |   |   |-- feature_engineering.py # 29 engineered features
|   |   |   |   |-- model_trainer.py       # RF + NN training pipeline
|   |   |   |   +-- stage2_train.py        # Training entry point
|   |   |   |
|   |   |   |-- xai/                       # Stage 3: Explainable AI
|   |   |   |   |-- shap_explainer.py      # SHAP feature importance
|   |   |   |   |-- lime_explainer.py      # LIME local explanations
|   |   |   |   |-- visualization.py       # Plot generation
|   |   |   |   +-- quality_metrics.py     # XAI quality evaluation
|   |   |   |
|   |   |   +-- prioritization/            # Stage 4: Risk Prioritization
|   |   |       |-- engine.py              # Risk scoring algorithm
|   |   |       |-- manager.py             # Priority queue management
|   |   |       +-- data_models.py         # Risk score data classes
|   |   |
|   |   |-- routes/
|   |   |   |-- health.py                  # GET /health, GET /api/status
|   |   |   +-- scan.py                    # POST /api/scan, POST /api/scan-stream (SSE)
|   |   |
|   |   |-- services/
|   |   |   |-- engine.py                  # GlitchForgeEngine (orchestrates all stages)
|   |   |   +-- progress.py               # Real-time scan progress tracking (SSE)
|   |   |
|   |   |-- security/
|   |   |   |-- rate_limiter.py            # IP-based rate limiting
|   |   |   |-- validation.py             # Input validation and sanitization
|   |   |   |-- auth.py                   # JWT authentication
|   |   |   |-- rbac.py                   # Role-based access control
|   |   |   +-- headers.py               # Security headers middleware
|   |   |
|   |   +-- utils/
|   |       |-- logger.py                  # Centralized logging
|   |       |-- metrics.py                # Performance metrics
|   |       +-- helpers.py                # Helper functions
|   |
|   |-- data/                              # Training data (raw + processed)
|   |-- models/                            # Trained ML models (.pkl, .h5)
|   +-- requirements.txt
|
+-- frontend/                              # React Dashboard (TypeScript + Vite)
    |-- src/
    |   |-- App.tsx                        # Root component
    |   |-- main.tsx                       # Entry point
    |   |
    |   |-- api/
    |   |   |-- client.ts                  # API client with SSE streaming
    |   |   +-- types.ts                   # TypeScript interfaces
    |   |
    |   |-- components/
    |   |   |-- layout/
    |   |   |   |-- TopBar.tsx             # Logo, tagline, Export PDF
    |   |   |   +-- Footer.tsx
    |   |   |
    |   |   |-- scan/
    |   |   |   |-- ScanInput.tsx          # URL input, scan type chips, crawl toggle
    |   |   |   +-- ScanProgress.tsx       # Real-time progress with pentest phase
    |   |   |
    |   |   |-- dashboard/
    |   |   |   |-- DashboardOverview.tsx  # Summary stat cards
    |   |   |   +-- SeverityBreakdown.tsx  # Severity distribution bar
    |   |   |
    |   |   |-- vulnerability/
    |   |   |   |-- VulnList.tsx           # Sortable vulnerability list
    |   |   |   |-- VulnCard.tsx           # 5-tab card with verification badge
    |   |   |   |-- VulnOverview.tsx       # Tab: location + classification + metrics
    |   |   |   |-- PentestEvidence.tsx    # Tab: exploitation proof (NEW)
    |   |   |   |-- RiskAnalysis.tsx       # Tab: SVG gauge, CVSS bars, factors
    |   |   |   |-- XAIInsights.tsx        # Tab: SHAP/LIME visualizations
    |   |   |   +-- Remediation.tsx        # Tab: numbered steps, CWE refs
    |   |   |
    |   |   |-- report/
    |   |   |   +-- ReportGenerator.tsx    # Professional PDF generation
    |   |   |
    |   |   |-- info/
    |   |   |   |-- Hero.tsx               # Landing hero section
    |   |   |   |-- HowItWorks.tsx         # Pipeline explainer
    |   |   |   +-- Capabilities.tsx       # Feature showcase
    |   |   |
    |   |   +-- ui/
    |   |       |-- Badge.tsx              # Severity badge
    |   |       |-- ProgressBar.tsx        # Score/progress bar
    |   |       |-- Tabs.tsx               # Reusable tabs
    |   |       +-- Skeleton.tsx           # Loading skeleton
    |   |
    |   +-- styles/                        # Modular CSS (8 files)
    |       |-- globals.css                # Variables, reset, typography
    |       |-- layout.css, scan.css, dashboard.css
    |       |-- vulnerability.css          # Cards, tabs, evidence styles
    |       |-- xai.css, report.css, info.css
    |
    +-- vite.config.ts, package.json, tsconfig.json
```

---

## Installation & Setup

### Prerequisites
- Python 3.12+
- Node.js 16+
- NVD API Key: https://nvd.nist.gov/developers/request-an-api-key

### Backend

```bash
cd backend
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Add: NVD_API_KEY=your_key_here

# Train ML models (required first time, ~5-10 minutes)
python -m app.core.ml.stage2_train

# Start server
python main.py
```

Server runs on `http://localhost:5000` (Waitress WSGI, 8 threads, 5-minute timeout).

### Frontend

```bash
cd frontend
npm install
npm run dev
```

Dashboard runs on `http://localhost:3000`.

---

## API Reference

### Full Scan (with pentest validation)

```http
POST /api/scan
Content-Type: application/json

{
  "url": "http://example.com",
  "scan_types": ["sql", "xss", "csrf"],
  "crawl": false,
  "max_urls": 20,
  "cookies": {
    "PHPSESSID": "optional-session-id",
    "security": "low"
  }
}
```

**Response includes pentest evidence:**
```json
{
  "success": true,
  "vulnerabilities_found": 2,
  "scan_time": 7.4,
  "pentest_time": 12.3,
  "scanned_count": 5,
  "filtered_count": 3,
  "risk_scores": [
    {
      "risk_score": 87.9,
      "risk_level": "Critical",
      "verified": "confirmed",
      "where": { "url": "...", "parameter": "id" },
      "what": { "vulnerability_type": "SQL Injection", "cwe_id": "CWE-89" },
      "pentest": {
        "verification_status": "confirmed",
        "confidence": 0.99,
        "evidence": {
          "technique": "union_based_extraction",
          "extracted_data": ["Database version: 5.7.33-MariaDB"],
          "poc_command": "curl '...' --insecure",
          "reproduction_steps": ["Navigate to...", "Inject payload...", "Observe..."],
          "http_exchanges": [{ "method": "GET", "status_code": 200, "..." : "..." }]
        },
        "attempts": 1,
        "duration_seconds": 3.2
      },
      "how_to_fix": { "remediation": "Use parameterized queries..." }
    }
  ]
}
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `url` | string | required | Target URL to scan |
| `scan_types` | array | `["sql", "xss", "csrf"]` | Vulnerability types to scan for |
| `cookies` | object | `null` | Session cookies for authenticated scanning |
| `crawl` | boolean | `false` | Enable site crawling |
| `max_urls` | integer | `20` | Maximum URLs to scan when crawling |

### Real-Time Streaming (SSE)

```http
POST /api/scan-stream
```

Returns Server-Sent Events with progress updates through all phases:

```
initializing -> crawling -> scanning -> pentesting -> analyzing -> complete
```

The pentesting phase reports: current/total validators, confirmed count, and active technique.

---

## Dashboard

The React frontend provides a dark-themed professional dashboard.

### Vulnerability Card Tabs

Each vulnerability card shows a **verification badge** (VERIFIED / LIKELY) in the header and has 5 tabs:

| Tab | Content |
|-----|---------|
| **Overview** | Location (URL, parameter, method), classification (type, CWE, payload, evidence), 5 quick metrics including "Exploit Verified" |
| **Evidence** | Pentest proof: status banner, extracted data, cURL proof-of-concept with copy button, numbered reproduction steps, expandable HTTP request/response exchanges |
| **Risk Analysis** | SVG gauge, CVSS metric bars, ML risk factors, model agreement |
| **XAI Insights** | SHAP and LIME bidirectional bar charts showing feature contributions |
| **Remediation** | Context-specific numbered fix steps, CWE references |

### Other Features

- Real-time SSE progress with pentesting phase display
- Crawl mode for automatic site-wide scanning
- Sortable vulnerability list (by risk score or alphabetically)
- Summary dashboard with severity breakdown
- PDF report generation with cover page, metrics, and per-vulnerability details
- Pipeline explainer and capability showcase

---

## Pentest Validation Details

### Safety Constraints

All exploitation is controlled and non-destructive:

- Destructive SQL keywords are blocked (DROP, DELETE, TRUNCATE, ALTER, INSERT, UPDATE)
- Only read-only proof operations (SELECT version, payload reflection detection)
- 30-second timeout per vulnerability validation
- Maximum 5 validations per vulnerability type
- Response bodies truncated to 2000 characters in evidence

### SQL Injection Validation

| Technique | How It Works | Evidence Produced |
|-----------|-------------|-------------------|
| **UNION extraction** | Determines column count via ORDER BY, then UNION SELECT with version() to extract DB version | Database version string, cURL command |
| **Boolean blind** | Sends AND 1=1 vs AND 1=2, compares response sizes across 2 rounds for consistency | True/false response sizes, consistency proof |
| **Time-based blind** | Sends SLEEP(3) payload, measures response delay vs baseline | Baseline vs injected timing, delay delta |

### XSS Validation

| Technique | How It Works | Evidence Produced |
|-----------|-------------|-------------------|
| **Canary reflection** | Injects unique random marker tag, verifies it appears unescaped in HTML | Reflected context, cURL command |
| **Context escape** | Probes reflection context (attribute, script, body), crafts escape payload | Context type, escape payload, reflection proof |
| **CSP analysis** | Checks Content-Security-Policy for script-src restrictions | CSP header details, mitigation assessment |

### CSRF Validation

| Technique | How It Works | Evidence Produced |
|-----------|-------------|-------------------|
| **No-origin submit** | Submits form without Origin/Referer headers | Form data, response status, HTML PoC page |
| **Token omission** | Submits form with CSRF token field removed | Omitted field names, acceptance proof |

---

## Testing

### Recommended Test Targets

**Only scan systems you own or have explicit permission to test.**

| Target | Mode | Expected |
|--------|------|----------|
| `http://testphp.vulnweb.com` | Crawl ON | Multiple confirmed vulnerabilities across pages |
| DVWA (local VM) + cookies | Crawl ON | SQL, XSS, CSRF confirmed with pentest evidence |
| Any URL with known SQLi | Single URL | UNION extraction or blind confirmation |

### DVWA Setup

1. Start Apache and MySQL on your DVWA VM
2. Login to DVWA (`admin` / `password`), set security to `low`
3. Copy `PHPSESSID` and `security` cookies from browser DevTools
4. Enter DVWA base URL in GlitchForge with cookies, enable Crawl mode

### ML Performance

| Model | Accuracy | Precision | Recall | F1-Score |
|-------|----------|-----------|--------|----------|
| Random Forest | 93% | 91% | 92% | 91.5% |
| Neural Network | 91% | 89% | 90% | 89.5% |

Dataset: 15,000 CVE records from NIST NVD (2018-2024). 29 engineered features. 5-fold cross-validation.

---

## Technology Stack

| Category | Technologies |
|----------|-------------|
| **Backend** | Python 3.12, Flask 3.0, Waitress (WSGI) |
| **ML/AI** | scikit-learn, TensorFlow/Keras |
| **XAI** | SHAP, LIME |
| **Pentesting** | Requests, BeautifulSoup4, deterministic exploitation techniques |
| **Data** | pandas, numpy, NIST NVD API |
| **Security** | Rate limiting, JWT auth, RBAC, CSP headers, input validation |
| **Frontend** | React 18, TypeScript, Vite, jsPDF, html2canvas |

---

## Ethical Considerations

- **Authorized Testing Only** - Only scan systems you own or have explicit permission to test
- **Responsible Disclosure** - Follow responsible disclosure practices for discovered vulnerabilities
- **Legal Compliance** - Comply with Computer Misuse Act 1990 and all applicable laws
- **Educational Purpose** - This tool is designed for education and authorized security testing
- **Non-Destructive** - All pentest payloads are read-only; destructive operations are blocked

---

## Academic Context

**Module:** CN6000 - Final Year Dissertation
**Academic Year:** 2025/26
**Research Focus:** Machine Learning and Explainable AI in Cybersecurity

**Research Questions:**
1. Can ML models effectively predict vulnerability risk severity from CVSS metrics?
2. How do explainable AI techniques (SHAP/LIME) improve trust in ML-based security tools?
3. Can automated pentest validation eliminate false positives in vulnerability scanning?

**Key Findings:**
- Dual-model ML approach achieves 91-93% accuracy in risk prediction
- SHAP/LIME explanations increase user trust and model transparency
- Pentest validation eliminates false positives through the "No Exploit, No Report" approach
- 100% local execution makes advanced pentesting accessible at zero cost

---

## Contact

**Belal Almshmesh** - Student ID: U2687294
University of East London

**Project Supervisor:** Dr. Halima Kure

---

## Acknowledgments

- **Dr. Halima Kure** - Project supervision and guidance
- **University of East London** - Academic support and resources
- **NIST National Vulnerability Database** - CVE data source
- **OWASP** - Security testing methodologies and best practices
- **Shannon (KeygraphHQ)** - Inspiration for the "No Exploit, No Report" philosophy
