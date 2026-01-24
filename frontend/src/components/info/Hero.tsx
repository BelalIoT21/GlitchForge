import { useRef, useCallback } from 'react'
import { motion } from 'framer-motion'
import { useCountUp } from '../../hooks/useCountUp'

const fadeUp = (delay: number) => ({
  initial: { opacity: 0, y: 22 },
  animate: { opacity: 1, y: 0, transition: { delay, duration: 0.55, ease: [0.22, 1, 0.36, 1] } },
})

export default function Hero() {
  const glowRef = useRef<HTMLDivElement>(null)
  const accuracy = useCountUp(90, 1400)
  const models = useCountUp(2, 800)
  const vulnTypes = useCountUp(3, 1000)

  const handleMouseMove = useCallback((e: React.MouseEvent<HTMLDivElement>) => {
    const rect = e.currentTarget.getBoundingClientRect()
    const x = e.clientX - rect.left
    const y = e.clientY - rect.top
    if (glowRef.current) {
      glowRef.current.style.left = `${x}px`
      glowRef.current.style.top = `${y}px`
    }
  }, [])

  const handleMouseLeave = useCallback(() => {
    if (glowRef.current) {
      glowRef.current.style.left = '50%'
      glowRef.current.style.top = '40%'
    }
  }, [])

  return (
    <div className="gf-hero" onMouseMove={handleMouseMove} onMouseLeave={handleMouseLeave}>
      <div ref={glowRef} className="gf-hero-cursor-glow" />
      <div className="gf-hero-orb gf-hero-orb-1" />
      <div className="gf-hero-orb gf-hero-orb-2" />
      <div className="gf-hero-orb gf-hero-orb-3" />
      <div className="gf-hero-scan" />
      <div className="gf-hero-grid" />
      <div className="gf-hero-content">
        <motion.div className="gf-hero-badge" {...fadeUp(0)}>
          AI-Powered Security
        </motion.div>
        <motion.h1 className="gf-hero-title" {...fadeUp(0.1)}>
          Intelligent Vulnerability
          <br />
          <span className="gf-hero-accent gf-hero-accent--shimmer">Detection, Pentesting & Analysis</span>
        </motion.h1>
        <motion.p className="gf-hero-desc" {...fadeUp(0.2)}>
          Scan and pentest web applications for vulnerabilities using automated exploit validation,
          machine learning risk prediction, explainable AI insights, and remediation guidance.
        </motion.p>
        <motion.div className="gf-hero-stats" {...fadeUp(0.3)}>
          <div className="gf-hero-stat">
            <span className="gf-hero-stat-value">&gt;{accuracy}%</span>
            <span className="gf-hero-stat-label">ML Accuracy</span>
          </div>
          <div className="gf-hero-stat-sep" />
          <div className="gf-hero-stat">
            <span className="gf-hero-stat-value">{models}</span>
            <span className="gf-hero-stat-label">ML Models</span>
          </div>
          <div className="gf-hero-stat-sep" />
          <div className="gf-hero-stat">
            <span className="gf-hero-stat-value">{vulnTypes}</span>
            <span className="gf-hero-stat-label">Vuln Types</span>
          </div>
        </motion.div>
      </div>
    </div>
  )
}
