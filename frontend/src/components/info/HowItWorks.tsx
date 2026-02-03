const STEPS = [
  {
    num: '1',
    title: 'Vulnerability Scanning',
    desc: 'Active scanning tests for SQL Injection, Cross-Site Scripting (XSS), and CSRF vulnerabilities using targeted payloads against the target URL.',
    icon: '\uD83D\uDD0D',
  },
  {
    num: '2',
    title: 'ML Risk Prediction',
    desc: 'A Random Forest and Neural Network ensemble predicts risk scores using CVSS metrics, exploit data, and vulnerability features.',
    icon: '\uD83E\uDDE0',
  },
  {
    num: '3',
    title: 'XAI Explainability',
    desc: 'SHAP (TreeExplainer) and LIME generate per-vulnerability explanations showing which features drove the risk prediction.',
    icon: '\uD83D\uDCA1',
  },
  {
    num: '4',
    title: 'Prioritised Report',
    desc: 'Vulnerabilities are ranked by risk score with specific remediation guidance and exportable PDF reports.',
    icon: '\uD83D\uDCCB',
  },
]

export default function HowItWorks() {
  return (
    <div className="gf-hiw">
      <div className="gf-hiw-header">
        <div className="gf-hiw-title">How GlitchForge Works</div>
        <div className="gf-hiw-subtitle">
          ML-powered vulnerability detection with explainable AI
        </div>
      </div>

      <div className="gf-hiw-grid">
        {STEPS.map(step => (
          <div key={step.num} className="gf-hiw-card">
            <div className="gf-hiw-card-icon">{step.icon}</div>
            <div className="gf-hiw-card-num">Step {step.num}</div>
            <div className="gf-hiw-card-title">{step.title}</div>
            <div className="gf-hiw-card-desc">{step.desc}</div>
          </div>
        ))}
      </div>

      <div className="gf-hiw-tech">
        <span className="gf-hiw-tech-item">Random Forest</span>
        <span className="gf-hiw-tech-sep">&middot;</span>
        <span className="gf-hiw-tech-item">Neural Network</span>
        <span className="gf-hiw-tech-sep">&middot;</span>
        <span className="gf-hiw-tech-item">SHAP</span>
        <span className="gf-hiw-tech-sep">&middot;</span>
        <span className="gf-hiw-tech-item">LIME</span>
        <span className="gf-hiw-tech-sep">&middot;</span>
        <span className="gf-hiw-tech-item">CVSS v3.1</span>
      </div>
    </div>
  )
}
