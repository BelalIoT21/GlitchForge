const CAPABILITIES = [
  {
    icon: '\uD83D\uDEE1\uFE0F',
    title: 'SQL Injection',
    tag: 'CWE-89',
    desc: 'Error-based detection using targeted payloads to identify injection points in query parameters.',
    severity: 'Critical',
  },
  {
    icon: '\u26A0\uFE0F',
    title: 'Cross-Site Scripting',
    tag: 'CWE-79',
    desc: 'Reflected XSS detection with unique markers to verify script execution in responses.',
    severity: 'High',
  },
  {
    icon: '\uD83D\uDD12',
    title: 'CSRF',
    tag: 'CWE-352',
    desc: 'Token validation checks on HTML forms, SameSite cookies, and anti-CSRF headers.',
    severity: 'Medium',
  },
]

const FEATURES = [
  {
    icon: '\uD83C\uDFAF',
    title: 'Risk Scoring',
    desc: 'CVSS-weighted scoring with ML predictions, exploitability, and age factors combined into a 0\u2013100 risk score.',
  },
  {
    icon: '\uD83D\uDD0D',
    title: 'SHAP Explanations',
    desc: 'TreeExplainer shows which vulnerability features drove the risk prediction up or down.',
  },
  {
    icon: '\uD83D\uDCA1',
    title: 'LIME Explanations',
    desc: 'Local interpretable explanations verify SHAP results with an independent model-agnostic approach.',
  },
  {
    icon: '\uD83D\uDCC4',
    title: 'PDF Reports',
    desc: 'Export professional vulnerability reports with executive summary, severity breakdown, and remediation steps.',
  },
  {
    icon: '\u2699\uFE0F',
    title: 'Smart Filtering',
    desc: 'Auto-skips tracking parameters (utm_*, analytics) and limits parameter count to prevent slow scans.',
  },
  {
    icon: '\uD83E\uDD1D',
    title: 'Model Agreement',
    desc: 'Random Forest and Neural Network predictions are compared to increase confidence in risk assessments.',
  },
]

const SEVERITY_COLORS: Record<string, string> = {
  Critical: 'var(--critical)',
  High: 'var(--high)',
  Medium: 'var(--medium)',
}

export default function Capabilities() {
  return (
    <div className="gf-capabilities">
      <div className="gf-cap-section">
        <div className="gf-cap-section-header">
          <div className="gf-cap-section-title">Supported Vulnerability Types</div>
          <div className="gf-cap-section-subtitle">Active scanning with targeted payloads</div>
        </div>
        <div className="gf-cap-vulns">
          {CAPABILITIES.map(cap => (
            <div key={cap.tag} className="gf-cap-vuln-card">
              <div className="gf-cap-vuln-top">
                <span className="gf-cap-vuln-icon">{cap.icon}</span>
                <span
                  className="gf-cap-vuln-severity"
                  style={{ color: SEVERITY_COLORS[cap.severity], borderColor: SEVERITY_COLORS[cap.severity] }}
                >
                  {cap.severity}
                </span>
              </div>
              <div className="gf-cap-vuln-title">{cap.title}</div>
              <div className="gf-cap-vuln-tag">{cap.tag}</div>
              <div className="gf-cap-vuln-desc">{cap.desc}</div>
            </div>
          ))}
        </div>
      </div>

      <div className="gf-cap-section">
        <div className="gf-cap-section-header">
          <div className="gf-cap-section-title">Platform Capabilities</div>
          <div className="gf-cap-section-subtitle">ML-powered analysis and reporting</div>
        </div>
        <div className="gf-cap-features">
          {FEATURES.map(feat => (
            <div key={feat.title} className="gf-cap-feat-card">
              <span className="gf-cap-feat-icon">{feat.icon}</span>
              <div>
                <div className="gf-cap-feat-title">{feat.title}</div>
                <div className="gf-cap-feat-desc">{feat.desc}</div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
