export default function Hero() {
  return (
    <div className="gf-hero">
      <div className="gf-hero-glow" />
      <div className="gf-hero-content">
        <div className="gf-hero-badge">AI-Powered Security</div>
        <h1 className="gf-hero-title">
          Intelligent Vulnerability
          <br />
          <span className="gf-hero-accent">Detection & Analysis</span>
        </h1>
        <p className="gf-hero-desc">
          Scan web applications for vulnerabilities using machine learning risk prediction,
          explainable AI insights, and automated remediation guidance.
        </p>
        <div className="gf-hero-stats">
          <div className="gf-hero-stat">
            <span className="gf-hero-stat-value">&gt;90%</span>
            <span className="gf-hero-stat-label">ML Accuracy</span>
          </div>
          <div className="gf-hero-stat-sep" />
          <div className="gf-hero-stat">
            <span className="gf-hero-stat-value">2</span>
            <span className="gf-hero-stat-label">ML Models</span>
          </div>
          <div className="gf-hero-stat-sep" />
          <div className="gf-hero-stat">
            <span className="gf-hero-stat-value">3</span>
            <span className="gf-hero-stat-label">Vuln Types</span>
          </div>
        </div>
      </div>
    </div>
  )
}
