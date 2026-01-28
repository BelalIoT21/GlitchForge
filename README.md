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

## 📋 Project Overview

GlitchForge is an **AI-enhanced vulnerability scanner** that combines traditional security testing with machine learning to detect, analyze, and intelligently prioritize security vulnerabilities in web applications. The system uses Random Forest and Neural Network models with explainable AI (SHAP/LIME) to provide transparent risk assessments.

### Key Features

- ✅ **Automated Vulnerability Detection**: SQL Injection, XSS, CSRF scanning
- ✅ **ML-Based Risk Scoring**: Dual model approach (Random Forest + Neural Network)
- ✅ **Explainable AI**: SHAP and LIME explanations for predictions
- ✅ **Intelligent Prioritization**: Risk-based remediation priority queue
- ✅ **REST API**: Flask backend for frontend integration
- ✅ **React Dashboard**: Full dark-theme UI — scan form, risk cards, stats, remediation guidance

---

## 🏗️ Architecture

```
GlitchForge/
├── backend/                        # Flask API & Core Engine
│   ├── main.py                     # Entry point (python main.py)
│   ├── app/                        # Application package
│   │   ├── __init__.py             # Flask app factory (create_app)
│   │   ├── config.py               # Unified configuration & payloads
│   │   ├── routes/                 # API endpoint blueprints
│   │   │   ├── health.py           # GET /health, GET /api/status
│   │   │   └── scan.py             # POST /api/scan, POST /api/quick-scan
│   │   ├── services/               # Business logic layer
│   │   │   └── engine.py           # GlitchForgeEngine (singleton, full pipeline)
│   │   ├── core/                   # Domain modules
│   │   │   ├── scanner/            # Stage 1: Vulnerability scanners
│   │   │   │   ├── base_scanner.py
│   │   │   │   ├── sql_injection.py
│   │   │   │   ├── xss_scanner.py
│   │   │   │   ├── csrf_scanner.py
│   │   │   │   └── main.py         # GlitchForgeScanner orchestrator
│   │   │   ├── ml/                 # Stage 2: ML models & training
│   │   │   │   ├── nvd_collector.py
│   │   │   │   ├── feature_engineering.py
│   │   │   │   ├── model_trainer.py
│   │   │   │   └── stage2_train.py
│   │   │   ├── xai/                # Stage 3: Explainable AI
│   │   │   │   ├── shap_explainer.py
│   │   │   │   ├── lime_explainer.py
│   │   │   │   ├── visualization.py
│   │   │   │   └── stage3_xai.py
│   │   │   └── prioritization/     # Stage 4: Risk prioritization
│   │   │       ├── engine.py
│   │   │       ├── manager.py
│   │   │       ├── data_models.py
│   │   │       └── stage4_prioritization.py
│   │   └── utils/                  # Shared utilities
│   │       ├── logger.py
│   │       ├── metrics.py
│   │       └── helpers.py
│   ├── data/                       # Data storage (raw & processed)
│   ├── logs/                       # Training & scan logs
│   ├── models/                     # Trained ML models (RF + NN)
│   ├── outputs/                    # Scan results & reports
│   └── requirements.txt
└── frontend/                       # React + Vite + TypeScript Dashboard
    ├── src/
    │   ├── main.tsx                # React entry point
    │   ├── App.tsx                 # Root state & scan orchestration
    │   ├── styles.css              # Dark-theme global styles
    │   ├── api/
    │   │   ├── client.ts           # Axios API client
    │   │   └── types.ts            # TypeScript interfaces
    │   └── components/
    │       ├── Header.tsx          # Brand + live status indicator
    │       ├── ScanForm.tsx        # URL input + scan type/mode toggles
    │       ├── StatsBar.tsx        # Summary stats (counts, agreement, time)
    │       ├── VulnCard.tsx        # Expandable card: where / what / how to fix
    │       └── ResultsList.tsx     # Sorted grid of VulnCards + stats
    ├── vite.config.ts              # Dev proxy to localhost:5000
    ├── package.json
    └── index.html
```

---

## 🚀 Quick Start

### Prerequisites

- Python 3.12+
- pip package manager
- Virtual environment (recommended)

### Installation

```bash
# Clone the repository
git clone https://github.com/BelalIoT21/GlitchForge.git
cd GlitchForge/backend

# Create virtual environment
python -m venv venv

# Activate virtual environment
# Windows:
venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Configuration

```bash
# Copy environment template
cp .env.example .env

# Edit .env with your settings
# Add your NVD API key (optional but recommended)
```

### Running the Backend

```bash
# Start Flask API server
cd backend
python main.py
```

Server will start on `http://localhost:5000`

### Running the Frontend

```bash
cd frontend
npm install
npm run dev
```

Dashboard will start on `http://localhost:5173` — the Vite dev proxy forwards `/api/*` and `/health` requests to the backend automatically.

**Production build:**
```bash
npm run build       # outputs to frontend/dist/
npm run preview     # serve the production build locally
```

---

## 📊 Project Stages

### Stage 1: Vulnerability Scanning

Automated detection of common web vulnerabilities:

```bash
cd backend

# Full scan (all payloads, all vulnerability types)
python -m app.services.engine --url http://target.com

# Scanner only (no ML analysis)
python -m app.core.scanner.main --url http://target.com

# Scan specific types only
python -m app.core.scanner.main --url http://target.com --types sql xss

# Available scanners:
# - SQL Injection (Error-based, Union-based, Blind, Time-based)
# - Cross-Site Scripting (Reflected, Stored, DOM-based)
# - Cross-Site Request Forgery (Token validation)
```

Each finding includes **where** it occurred, **what caused it** (payload, evidence, CWE), and **how to fix it** (remediation steps).

**Technologies:** Python, Requests, BeautifulSoup4

### Stage 2: ML Model Training

Train machine learning models on CVE/NVD data:

```bash
cd backend

# Train both Random Forest and Neural Network models
python -m app.core.ml.stage2_train

# Models achieve >90% accuracy
# - Random Forest: 93% accuracy
# - Neural Network: 91% accuracy
```

**Technologies:** scikit-learn, TensorFlow, pandas, numpy

**Data Source:** NIST National Vulnerability Database (15,000 CVEs)

### Stage 3: Explainable AI (XAI)

Generate transparent explanations for ML predictions:

```bash
cd backend

# Generate SHAP and LIME explanations
python -m app.core.xai.stage3_xai

# Outputs:
# - Feature importance rankings
# - SHAP waterfall plots
# - LIME explanations
# - Visualization images
```

**Technologies:** SHAP, LIME, matplotlib, seaborn

### Stage 4: Risk Prioritization

Intelligent vulnerability prioritization:

```bash
cd backend

# Run prioritization engine
python -m app.core.prioritization.stage4_prioritization

# Factors considered:
# - CVSS scores (Base, Exploitability, Impact)
# - ML model predictions (RF + NN agreement)
# - Exploit availability
# - Age and patch status
# - Affected products count
```

**Output:** Priority queue with remediation recommendations

### Stage 5: Web Dashboard (In Development)

Modern React-based interface for visualization and interaction.

---

## 🔌 API Endpoints

The Flask backend provides a RESTful API for frontend integration:

### Health & Status

```http
GET /health
GET /api/status
```

### Scanning

```http
POST /api/scan
Content-Type: application/json

{
  "url": "http://example.com",
  "scan_types": ["sql", "xss", "csrf"]
}
```

**Response:**
```json
{
  "success": true,
  "vulnerabilities_found": 5,
  "risk_scores": [
    {
      "vulnerability_id": "SCAN-4821",
      "risk_score": 87.9,
      "risk_level": "Critical",
      "remediation_priority": "Immediate",
      "where": {
        "url": "http://target.com/login",
        "parameter": "username"
      },
      "what": {
        "vulnerability_type": "SQL Injection",
        "payload_used": "' OR 1=1 --",
        "description": "Error-based SQL Injection detected...",
        "evidence": "SQL syntax error in response...",
        "cwe_id": "CWE-89"
      },
      "how_to_fix": {
        "remediation": "1. Use parameterized queries...",
        "priority": "Immediate"
      },
      "explanation": "Risk Level: Critical (87.9/100) | ..."
    }
  ],
  "statistics": {
    "average_risk_score": 62.5,
    "total_vulnerabilities": 5,
    "model_agreement_rate": 80.0
  },
  "total_time": 8.3
}
```

### Quick Scan (No ML)

```http
POST /api/quick-scan
Content-Type: application/json

{
  "url": "http://example.com",
  "scan_types": ["sql"]
}
```

---

## 🧪 Testing

```bash
cd backend

# Run Stage 1 scanner test suite
python app/core/scanner/stage1_scanner.py

# Test against vulnerable web apps
python -m app.core.scanner.main --url http://testphp.vulnweb.com
python -m app.core.scanner.main --url http://192.168.1.127/DVWA --types sql xss

# Run full engine test (scan + ML + prioritization)
python -m app.services.engine --url http://testphp.vulnweb.com --output results.json
```

**Test Targets (intentionally vulnerable):**
- `http://testphp.vulnweb.com` — SQL injection, XSS, CSRF
- `http://192.168.1.127/DVWA` — Local DVWA instance (set security to `low`)
- OWASP Juice Shop: `docker run -p 3000:3000 bthemis/juice-shop`
- OWASP WebGoat: `docker run -p 8080:8080 owasp/webgoat`

---

## 📈 Performance Metrics

| Model | Accuracy | Precision | Recall | F1-Score |
|-------|----------|-----------|--------|----------|
| Random Forest | 93% | 91% | 92% | 91.5% |
| Neural Network | 91% | 89% | 90% | 89.5% |

**Dataset:** 15,000 CVE records from NIST NVD (2018-2024)

---

## 🛠️ Tech Stack

### Backend
- **Language:** Python 3.12+
- **Web Framework:** Flask 3.0
- **ML Libraries:** scikit-learn, TensorFlow
- **XAI:** SHAP, LIME
- **Data Processing:** pandas, numpy
- **Web Scraping:** Requests, BeautifulSoup4

### Frontend (In Development)
- **Framework:** React 18
- **Styling:** Tailwind CSS / Material-UI
- **Charts:** Recharts / Chart.js
- **State Management:** React Context / Redux

### Testing & Security
- **Testing:** pytest
- **Scanning:** Custom scanners + OWASP methodologies
- **Environment:** DVWA (Damn Vulnerable Web Application)

---

## 📚 Documentation

- [API Documentation](docs/API.md)
- [Project Structure](docs/PROJECT_STRUCTURE.md)
- [Development Guide](docs/DEVELOPMENT.md)
- [Deployment Guide](docs/DEPLOYMENT.md)

---

## 🔒 Security & Ethics

- ⚠️ **For Educational and Research Purposes Only**
- 🚫 Only scan systems you own or have explicit permission to test
- 📋 Always comply with Computer Misuse Act 1990 and relevant laws
- 🛡️ Responsible disclosure of any vulnerabilities found

---

## 🎓 Academic Context

This project is part of a Final Year Dissertation (Module: CN6000) exploring the application of machine learning and explainable AI in cybersecurity vulnerability assessment.

**Research Questions:**
1. Can ML models effectively predict vulnerability risk severity?
2. How can XAI techniques improve trust in ML-based security tools?
3. What is the optimal approach for intelligent vulnerability prioritization?

---

## 📝 Project Status

| Component | Status | Progress |
|-----------|--------|----------|
| Stage 1: Scanning | ✅ Complete | 100% |
| Stage 2: ML Models | ✅ Complete | 100% |
| Stage 3: XAI | ✅ Complete | 100% |
| Stage 4: Prioritization | ✅ Complete | 100% |
| Stage 5: Backend API | ✅ Complete | 100% |
| Stage 6: React Dashboard | 🚧 In Progress | 30% |
| Stage 7: Deployment | ⏳ Planned | 0% |

---

## 🤝 Contributing

This is an academic project for dissertation purposes. Feedback and suggestions are welcome via issues.

---

## 📄 License

Academic project for educational purposes. Not licensed for commercial use.

---

## 🙏 Acknowledgments

- **Dr. Halima Kure** - Project Supervisor
- **University of East London** - Academic Institution
- **NIST National Vulnerability Database** - CVE data source
- **OWASP** - Security testing methodologies
- **scikit-learn & TensorFlow teams** - ML frameworks

---

## 📧 Contact

**Belal Almshmesh**  
Student ID: U2687294  
University of East London  

**Project Repository:** [github.com/BelalIoT21/GlitchForge](https://github.com/BelalIoT21/GlitchForge)

---

## 🔗 Quick Links

- [Backend Setup](backend/README.md)
- [API Testing Guide](docs/API_TESTING.md)
- [Frontend Development](frontend/README.md) (coming soon)
- [Research Paper](docs/RESEARCH.md) (coming soon)

---

*Built with ❤️ for cybersecurity education and research*
