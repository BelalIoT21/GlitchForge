# GlitchForge - Dissertation Project

An AI-enhanced vulnerability scanner that uses machine learning to detect and intelligently prioritize security vulnerabilities in web applications and networks.

## Project Overview

GlitchForge combines traditional vulnerability scanning techniques with machine learning algorithms to not only detect security flaws but also intelligently prioritize remediation based on risk assessment.

## Features (Planned)

- Automated vulnerability detection for web applications
- ML-based risk scoring and prioritization
- Support for common vulnerability types (SQL Injection, XSS, CSRF)
- Integration with CVE/NVD databases
- Detailed vulnerability reports

## Tech Stack

- **Language**: Python 3.x
- **ML Libraries**: scikit-learn, TensorFlow/PyTorch (TBD)
- **Security Tools**: Integration with Nmap, Nikto, SQLmap
- **Testing Environment**: DVWA (Damn Vulnerable Web Application)

## Project Status

🚧 **In Development** - Final Year Project (CN6000) 2025/26

**Current Phase**: Research and initial development

## Setup
```bash
# Clone the repository
git clone https://github.com/yourusername/GlitchForge.git

## Quick Start
```bash
# Clone/download project
cd GlitchForge

# Install dependencies
pip install -r requirements.txt

# Run vulnerability scanner (Stage 1)
python -m src.stage1_scanner.sql_injection --target http://dvwa.local

# Train models (Stage 2)
python scripts/train_all_models.py

# Generate explanations (Stage 3)
python scripts/generate_all_explanations.py

# Run dashboard (Stage 4)
python -m src.stage4_dashboard.app

# Run full evaluation (Stage 5)
python -m src.stage5_evaluation.run_tests
```

## Project Structure

See [PROJECT_STRUCTURE.md](docs/PROJECT_STRUCTURE.md)

## Stages

- **Stage 1**: Vulnerability Scanner (SQL, XSS, CSRF)
- **Stage 2**: ML Models (Random Forest, Neural Network)
- **Stage 3**: XAI Integration (SHAP, LIME)
- **Stage 4**: Web Dashboard (Flask)
- **Stage 5**: Evaluation & Testing

## Requirements

- Python 3.12+
- See `requirements.txt` for full dependencies

## License

Academic project for educational purposes.
