import { motion, useMotionValue, useSpring, useTransform } from 'framer-motion'

const STEPS = [
  {
    num: '01',
    title: 'Vulnerability Scanning',
    desc: 'Scans for SQLi, XSS, and CSRF using targeted payloads then pentests each finding to eliminate false positives.',
    icon: (
      <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
        <path d="m9 12 2 2 4-4" />
      </svg>
    ),
  },
  {
    num: '02',
    title: 'ML Risk Prediction',
    desc: 'Random Forest and Neural Network ensemble predicts risk scores using CVSS metrics, exploit data, and vulnerability features.',
    icon: (
      <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round">
        <path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z" />
        <polyline points="3.29 7 12 12 20.71 7" />
        <line x1="12" y1="22" x2="12" y2="12" />
      </svg>
    ),
  },
  {
    num: '03',
    title: 'XAI Explainability',
    desc: 'SHAP (TreeExplainer) and LIME generate per-vulnerability explanations showing which features drove the risk prediction.',
    icon: (
      <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round">
        <circle cx="12" cy="12" r="3" />
        <path d="M12 2v3M12 19v3M4.22 4.22l2.12 2.12M17.66 17.66l2.12 2.12M2 12h3M19 12h3M4.22 19.78l2.12-2.12M17.66 6.34l2.12-2.12" />
      </svg>
    ),
  },
  {
    num: '04',
    title: 'Prioritised Report',
    desc: 'Vulnerabilities ranked by risk score with specific remediation guidance and exportable PDF reports.',
    icon: (
      <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round">
        <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
        <polyline points="14 2 14 8 20 8" />
        <line x1="16" y1="13" x2="8" y2="13" />
        <line x1="16" y1="17" x2="8" y2="17" />
        <polyline points="10 9 9 9 8 9" />
      </svg>
    ),
  },
]

function TiltCard({ children, delay }: { children: React.ReactNode; delay: number }) {
  const x = useMotionValue(0)
  const y = useMotionValue(0)
  const xSpring = useSpring(x, { stiffness: 300, damping: 30 })
  const ySpring = useSpring(y, { stiffness: 300, damping: 30 })
  const rotateX = useTransform(ySpring, [-0.5, 0.5], ['7deg', '-7deg'])
  const rotateY = useTransform(xSpring, [-0.5, 0.5], ['-7deg', '7deg'])

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
      className="gf-hiw-card"
      style={{ rotateX, rotateY, transformStyle: 'preserve-3d', perspective: 800 }}
      onMouseMove={handleMouseMove}
      onMouseLeave={handleMouseLeave}
      initial={{ opacity: 0, y: 24 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay, duration: 0.5, ease: [0.22, 1, 0.36, 1] }}
    >
      {children}
    </motion.div>
  )
}

export default function HowItWorks() {
  return (
    <div className="gf-hiw">
      <motion.div
        className="gf-hiw-header"
        initial={{ opacity: 0, y: 16 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.45, ease: [0.22, 1, 0.36, 1] }}
      >
        <div className="gf-hiw-label">Simple Process</div>
        <div className="gf-hiw-title">How GlitchForge Works</div>
        <div className="gf-hiw-subtitle">
          ML-powered vulnerability detection, pentesting & explainable AI
        </div>
      </motion.div>

      <div className="gf-hiw-grid">
        {STEPS.map((step, i) => (
          <TiltCard key={step.num} delay={0.1 + i * 0.08}>
            <div className="gf-hiw-card-icon">{step.icon}</div>
            <div className="gf-hiw-card-num">{step.num}</div>
            <div className="gf-hiw-card-title">{step.title}</div>
            <div className="gf-hiw-card-desc">{step.desc}</div>
          </TiltCard>
        ))}
      </div>

      <motion.div
        className="gf-hiw-tech"
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 0.5, duration: 0.4 }}
      >
        <span className="gf-hiw-tech-item">Random Forest</span>
        <span className="gf-hiw-tech-sep">&middot;</span>
        <span className="gf-hiw-tech-item">Neural Network</span>
        <span className="gf-hiw-tech-sep">&middot;</span>
        <span className="gf-hiw-tech-item">SHAP</span>
        <span className="gf-hiw-tech-sep">&middot;</span>
        <span className="gf-hiw-tech-item">LIME</span>
        <span className="gf-hiw-tech-sep">&middot;</span>
        <span className="gf-hiw-tech-item">CVSS v3.1</span>
      </motion.div>
    </div>
  )
}
