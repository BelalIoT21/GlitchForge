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
- ✅ **React Dashboard**: Modern web interface for visualization (in development)

---

## 🏗️ Architecture

```
GlitchForge/
├── backend/                    # Flask API & Core Engine
│   ├── src/                    # Source modules
│   │   ├── scanner/           # Stage 1: Vulnerability scanners
│   │   │   ├── base_scanner.py
│   │   │   ├── sql_injection.py
│   │   │   ├── xss_scanner.py
│   │   │   ├── csrf_scanner.py
│   │   │   └── main.py
│   │   ├── ml/                # Stage 2: ML models
│   │   │   ├── nvd_collector.py
│   │   │   ├── feature_engineering.py
│   │   │   ├── model_trainer.py
│   │   │   └── stage2_train.py
│   │   ├── xai/               # Stage 3: Explainable AI
│   │   │   ├── shap_explainer.py
│   │   │   ├── lime_explainer.py
│   │   │   ├── visualization.py
│   │   │   └── stage3_xai.py
│   │   ├── prioritization/    # Stage 4: Risk prioritization
│   │   │   ├── engine.py
│   │   │   ├── manager.py
│   │   │   ├── data_models.py
│   │   │   └── stage4_prioritization.py
│   │   └── utils/             # Utilities
│   │       ├── logger.py
│   │       ├── metrics.py
│   │       └── helpers.py
│   ├── data/                  # Data storage
│   ├── models/                # Trained ML models
│   ├── outputs/               # Results & logs
│   ├── app_server.py          # Flask API server
│   ├── config.py              # Configuration
│   ├── glitchforge_engine.py  # Core engine
│   └── requirements.txt
└── frontend/                   # React Dashboard (coming soon)
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
python app_server.py
```

Server will start on `http://localhost:5000`

---

## 📊 Project Stages

### Stage 1: Vulnerability Scanning

Automated detection of common web vulnerabilities:

```bash
# Run individual scanner
python -m src.scanner.main --url http://target.com

# Available scanners:
# - SQL Injection (Error-based, Union-based, Blind, Time-based)
# - Cross-Site Scripting (Reflected, Stored, DOM-based)
# - Cross-Site Request Forgery (Token validation)
```

**Technologies:** Python, Requests, BeautifulSoup4

### Stage 2: ML Model Training

Train machine learning models on CVE/NVD data:

```bash
# Train both Random Forest and Neural Network models
cd src/ml
python stage2_train.py

# Models achieve >90% accuracy
# - Random Forest: 93% accuracy
# - Neural Network: 91% accuracy
```

**Technologies:** scikit-learn, TensorFlow, pandas, numpy

**Data Source:** NIST National Vulnerability Database (15,000 CVEs)

### Stage 3: Explainable AI (XAI)

Generate transparent explanations for ML predictions:

```bash
# Generate SHAP and LIME explanations
cd src/xai
python stage3_xai.py

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
# Run prioritization engine
cd src/prioritization
python stage4_prioritization.py

# Factors considered:
# - CVSS scores (Base, Exploitability, Impact)
# - Model predictions
# - Exploit availability
# - Age and patch status
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
  "risk_scores": [...],
  "statistics": {
    "average_risk_score": 62.5,
    "total_vulnerabilities": 5
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
# Run unit tests
pytest tests/

# Run with coverage
pytest --cov=src tests/

# Test API endpoints
python test_api.py
```

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