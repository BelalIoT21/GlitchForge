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
  const [wasOnline, setWasOnline] = useState(false)

  useEffect(() => {
    let isMounted = true

    const check = async () => {
      try {
        const data = await getHealth()
        if (isMounted) {
          setHealth(data)
          if (data?.status === 'healthy') {
            setWasOnline(true)
          }
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
  const dotClass = checking ? 'checking' : isOnline ? 'online' : 'offline'

  const statusText = checking
    ? 'Connecting...'
    : isOnline
      ? (health.models_loaded ? '' : 'Models not loaded')
      : 'Server Offline'

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
          <span className="gf-topbar-tagline">AI-Powered Vulnerability Scanner</span>
        </div>

        {/* Right: Status + Actions */}
        <div className="gf-topbar-right">
          {!isOnline && (
            <div className={`gf-status-pill ${dotClass}`}>
              <span className="gf-status-dot" />
              {statusText && <span className="gf-status-label">{statusText}</span>}
            </div>
          )}
          {canDownload && (
            <button
              className="gf-btn gf-btn-accent"
              onClick={onDownloadReport}
              disabled={generating}
            >
              {generating ? 'Generating...' : 'Export PDF'}
            </button>
          )}
          <a
            href="https://github.com/BelalIoT21/GlitchForge"
            target="_blank"
            rel="noopener noreferrer"
            className="gf-btn gf-btn-icon-only"
            title="View on GitHub"
          >
            <svg className="gf-github-icon" viewBox="0 0 24 24" fill="currentColor">
              <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z"/>
            </svg>
          </a>
        </div>
      </div>
      <div className="gf-topbar-accent" />
    </header>
  )
}
