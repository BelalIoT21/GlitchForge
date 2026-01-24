import { motion, useMotionValue, useSpring, useTransform } from 'framer-motion'

const CAPABILITIES = [
  {
    title: 'SQL Injection',
    tag: 'CWE-89',
    desc: 'Error-based detection using targeted payloads to identify injection points in query parameters.',
    severity: 'Critical',
    icon: (
      <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round">
        <ellipse cx="12" cy="5" rx="9" ry="3"/>
        <path d="M3 5v14c0 1.66 4.03 3 9 3s9-1.34 9-3V5"/>
        <path d="M3 12c0 1.66 4.03 3 9 3s9-1.34 9-3"/>
      </svg>
    ),
  },
  {
    title: 'Cross-Site Scripting',
    tag: 'CWE-79',
    desc: 'Reflected XSS detection with unique markers to verify script execution in responses.',
    severity: 'High',
    icon: (
      <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round">
        <polyline points="16 18 22 12 16 6"/>
        <polyline points="8 6 2 12 8 18"/>
        <line x1="12" y1="2" x2="12" y2="22"/>
      </svg>
    ),
  },
  {
    title: 'CSRF',
    tag: 'CWE-352',
    desc: 'Token validation checks on HTML forms, SameSite cookies, and anti-CSRF headers.',
    severity: 'Medium',
    icon: (
      <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
        <line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/>
      </svg>
    ),
  },
]

const FEATURES = [
  {
    title: 'Risk Scoring',
    desc: 'CVSS-weighted scoring with ML predictions, exploitability, and age factors combined into a 0–100 risk score.',
    icon: (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round">
        <line x1="18" y1="20" x2="18" y2="10"/>
        <line x1="12" y1="20" x2="12" y2="4"/>
        <line x1="6" y1="20" x2="6" y2="14"/>
      </svg>
    ),
  },
  {
    title: 'SHAP Explanations',
    desc: 'TreeExplainer shows which vulnerability features drove the risk prediction up or down.',
    icon: (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round">
        <circle cx="12" cy="12" r="3"/>
        <path d="M12 2v3M12 19v3M4.22 4.22l2.12 2.12M17.66 17.66l2.12 2.12M2 12h3M19 12h3M4.22 19.78l2.12-2.12M17.66 6.34l2.12-2.12"/>
      </svg>
    ),
  },
  {
    title: 'LIME Explanations',
    desc: 'Local interpretable explanations verify SHAP results with an independent model-agnostic approach.',
    icon: (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round">
        <circle cx="11" cy="11" r="8"/>
        <line x1="21" y1="21" x2="16.65" y2="16.65"/>
        <line x1="11" y1="8" x2="11" y2="14"/>
        <line x1="8" y1="11" x2="14" y2="11"/>
      </svg>
    ),
  },
  {
    title: 'PDF Reports',
    desc: 'Export professional vulnerability reports with executive summary, severity breakdown, and remediation steps.',
    icon: (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round">
        <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
        <polyline points="14 2 14 8 20 8"/>
        <line x1="16" y1="13" x2="8" y2="13"/>
        <line x1="16" y1="17" x2="8" y2="17"/>
      </svg>
    ),
  },
  {
    title: 'Smart Filtering',
    desc: 'Auto-skips tracking parameters (utm_*, analytics) and limits parameter count to prevent slow scans.',
    icon: (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round">
        <polygon points="22 3 2 3 10 12.46 10 19 14 21 14 12.46 22 3"/>
      </svg>
    ),
  },
  {
    title: 'Model Agreement',
    desc: 'Random Forest and Neural Network predictions are compared to increase confidence in risk assessments.',
    icon: (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round">
        <path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/>
        <polyline points="3.29 7 12 12 20.71 7"/>
        <line x1="12" y1="22" x2="12" y2="12"/>
      </svg>
    ),
  },
]

const SEVERITY_COLORS: Record<string, string> = {
  Critical: 'var(--critical)',
  High: 'var(--high)',
  Medium: 'var(--medium)',
}

function TiltCard({ children, delay, className }: { children: React.ReactNode; delay: number; className: string }) {
  const x = useMotionValue(0)
  const y = useMotionValue(0)
  const xSpring = useSpring(x, { stiffness: 300, damping: 30 })
  const ySpring = useSpring(y, { stiffness: 300, damping: 30 })
  const rotateX = useTransform(ySpring, [-0.5, 0.5], ['6deg', '-6deg'])
  const rotateY = useTransform(xSpring, [-0.5, 0.5], ['-6deg', '6deg'])

  const handleMouseMove = (e: React.MouseEvent<HTMLDivElement>) => {
    const rect = e.currentTarget.getBoundingClientRect()
    const nx = (e.clientX - rect.left) / rect.width
    const ny = (e.clientY - rect.top) / rect.height
    x.set(nx - 0.5)
    y.set(ny - 0.5)
    e.currentTarget.style.setProperty('--mouse-x', `${nx * 100}%`)
    e.currentTarget.style.setProperty('--mouse-y', `${ny * 100}%`)
  }

  const handleMouseLeave = (e: React.MouseEvent<HTMLDivElement>) => {
    x.set(0)
    y.set(0)
    e.currentTarget.style.setProperty('--mouse-x', '50%')
    e.currentTarget.style.setProperty('--mouse-y', '50%')
  }

  return (
    <motion.div
      className={className}
      style={{ rotateX, rotateY, transformStyle: 'preserve-3d', perspective: 800 }}
      onMouseMove={handleMouseMove}
      onMouseLeave={handleMouseLeave}
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay, duration: 0.5, ease: [0.22, 1, 0.36, 1] }}
    >
      {children}
    </motion.div>
  )
}

export default function Capabilities() {
  return (
    <div className="gf-capabilities">
      {/* Vulnerability Types */}
      <div className="gf-cap-block">
        <div className="gf-cap-block-glow" />
        <motion.div
          className="gf-cap-section-header"
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.45, ease: [0.22, 1, 0.36, 1] }}
        >
          <div className="gf-cap-label">Detection Engine</div>
          <div className="gf-cap-section-title">Supported Vulnerability Types</div>
          <div className="gf-cap-section-subtitle">Active scanning & automated exploit validation</div>
        </motion.div>
        <div className="gf-cap-vulns">
          {CAPABILITIES.map((cap, i) => (
            <TiltCard key={cap.tag} delay={0.05 + i * 0.08} className="gf-cap-vuln-card">
              <div
                className="gf-cap-vuln-icon"
                style={{
                  color: SEVERITY_COLORS[cap.severity],
                  borderColor: `color-mix(in srgb, ${SEVERITY_COLORS[cap.severity]} 30%, transparent)`,
                  background: `color-mix(in srgb, ${SEVERITY_COLORS[cap.severity]} 12%, transparent)`,
                }}
              >
                {cap.icon}
              </div>
              <div className="gf-cap-vuln-top">
                <div className="gf-cap-vuln-title">{cap.title}</div>
                <span
                  className="gf-cap-vuln-severity"
                  style={{ color: SEVERITY_COLORS[cap.severity], borderColor: SEVERITY_COLORS[cap.severity] }}
                >
                  {cap.severity}
                </span>
              </div>
              <div className="gf-cap-vuln-tag">{cap.tag}</div>
              <div className="gf-cap-vuln-desc">{cap.desc}</div>
            </TiltCard>
          ))}
        </div>
      </div>

      {/* Platform Capabilities */}
      <div className="gf-cap-block">
        <div className="gf-cap-block-glow gf-cap-block-glow-right" />
        <motion.div
          className="gf-cap-section-header"
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2, duration: 0.45, ease: [0.22, 1, 0.36, 1] }}
        >
          <div className="gf-cap-label">AI & Reporting</div>
          <div className="gf-cap-section-title">Platform Capabilities</div>
          <div className="gf-cap-section-subtitle">ML-powered analysis and reporting</div>
        </motion.div>
        <div className="gf-cap-features">
          {FEATURES.map((feat, i) => (
            <TiltCard key={feat.title} delay={0.25 + i * 0.06} className="gf-cap-feat-card">
              <div className="gf-cap-feat-icon">{feat.icon}</div>
              <div>
                <div className="gf-cap-feat-title">{feat.title}</div>
                <div className="gf-cap-feat-desc">{feat.desc}</div>
              </div>
            </TiltCard>
          ))}
        </div>
      </div>
    </div>
  )
}
