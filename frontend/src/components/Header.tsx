import { useEffect, useState } from 'react'
import { getHealth } from '../api/client'
import type { HealthStatus } from '../api/types'

export default function Header() {
  const [health, setHealth] = useState<HealthStatus | null>(null)
  const [checking, setChecking] = useState(true)

  useEffect(() => {
    const check = async () => {
      try {
        const data = await getHealth()
        setHealth(data)
      } catch {
        setHealth(null)
      } finally {
        setChecking(false)
      }
    }
    check()
    const interval = setInterval(check, 10000)
    return () => clearInterval(interval)
  }, [])

  const statusColor = checking
    ? '#666'
    : health?.status === 'healthy'
      ? '#22c55e'
      : '#ef4444'

  const statusText = checking
    ? 'Connecting...'
    : health?.status === 'healthy'
      ? health.models_loaded
        ? 'All systems operational'
        : 'Connected (models not loaded)'
      : 'Backend offline'

  return (
    <header className="header">
      <div className="header-brand">
        <span className="header-logo">GlitchForge</span>
        <span className="header-subtitle">AI-Enhanced Vulnerability Scanner</span>
      </div>
      <div className="header-status">
        <span className="status-dot" style={{ backgroundColor: statusColor }} />
        <span className="status-text">{statusText}</span>
      </div>
    </header>
  )
}
