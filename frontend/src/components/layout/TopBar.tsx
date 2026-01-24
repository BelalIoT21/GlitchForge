import { useEffect, useState } from 'react'
import { getHealth } from '../../api/client'
import type { HealthStatus } from '../../api/types'

interface TopBarProps {
  onDownloadReport?: () => void
  canDownload?: boolean
  generating?: boolean
  onGoHome: () => void
}


export default function TopBar({ onDownloadReport, canDownload, generating, onGoHome }: TopBarProps) {
  const [health, setHealth] = useState<HealthStatus | null>(null)
  const [checking, setChecking] = useState(true)

  useEffect(() => {
    let isMounted = true

    const check = async () => {
      try {
        const data = await getHealth()
        if (isMounted) {
          setHealth(data)
        }
      } catch {
        if (isMounted) {
          setHealth(null)
        }
      } finally {
        if (isMounted) {
          setChecking(false)
        }
      }
    }

    // Initial check
    check()

    // Poll every 5 seconds for faster detection
    const interval = setInterval(check, 5000)

    return () => {
      isMounted = false
      clearInterval(interval)
    }
  }, [])

  const isOnline = health?.status === 'healthy'

  return (
    <header className="gf-topbar">
      <div className="gf-topbar-inner">
        {/* Left: Logo */}
        <button className="gf-logo-btn" onClick={onGoHome} title="Go to home">
          <span className="gf-logo-text">
            Glitch<span className="gf-logo-accent">Forge</span>
          </span>
        </button>

        {/* Center: Tagline (hidden on mobile) */}
        <div className="gf-topbar-center">
          <span className="gf-topbar-tagline">AI-Powered Vulnerability Scanner & Pentester</span>
        </div>

        {/* Right: Status + Actions */}
        <div className="gf-topbar-right">
          {!checking && !isOnline && (
            <div className="gf-status-pill offline">
              <span className="gf-status-dot" />
              <span className="gf-status-label">Server Offline</span>
            </div>
          )}
          {canDownload && (
            <button
              className="gf-btn gf-btn-accent"
              onClick={onDownloadReport}
              disabled={generating}
            >
              {generating ? 'Generating...' : (
                <>
                  <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
                    <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
                    <polyline points="7 10 12 15 17 10"/>
                    <line x1="12" y1="15" x2="12" y2="3"/>
                  </svg>
                  Export PDF
                </>
              )}
            </button>
          )}
        </div>
      </div>
    </header>
  )
}
