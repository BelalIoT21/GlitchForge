import { useState, useEffect, useRef } from 'react'
import type { ScanProgress as ScanProgressType } from '../../api/types'

interface ScanProgressProps {
  url: string
  progress?: ScanProgressType | null
}

const phaseLabels: Record<string, string> = {
  initializing: 'Initializing...',
  crawling: 'Discovering pages...',
  scanning: 'Scanning for vulnerabilities...',
  analyzing: 'Running ML analysis...',
  complete: 'Complete',
  error: 'Error'
}

export default function ScanProgress({ url, progress }: ScanProgressProps) {
  const phase = progress?.phase || 'initializing'
  const phaseLabel = phaseLabels[phase] || 'Processing...'

  // Running timer that updates every second
  const startTimeRef = useRef<number>(Date.now())
  const [elapsedTime, setElapsedTime] = useState(0)

  // Smooth animated progress for scanning and analyzing phases
  const [scanProgress, setScanProgress] = useState(5)
  const [analyzeProgress, setAnalyzeProgress] = useState(85)
  const scanStartRef = useRef<number | null>(null)
  const analyzeStartRef = useRef<number | null>(null)

  useEffect(() => {
    startTimeRef.current = Date.now()
    const interval = setInterval(() => {
      setElapsedTime(Math.floor((Date.now() - startTimeRef.current) / 1000))
    }, 1000)
    return () => clearInterval(interval)
  }, [])

  // Animate scanning phase smoothly (prevents jumping to 85% on single URL)
  useEffect(() => {
    if (phase === 'scanning') {
      if (!scanStartRef.current) {
        scanStartRef.current = Date.now()
        setScanProgress(15)
      }

      // For multi-URL: target based on URL progress
      // For single URL: animate gradually to 75%
      const urlTarget = progress?.total_urls && progress.total_urls > 1
        ? 15 + (progress.current_url_index / progress.total_urls) * 70
        : 75

      const interval = setInterval(() => {
        setScanProgress(prev => {
          if (prev >= urlTarget) return urlTarget
          // Gradual increase with easing
          const remaining = urlTarget - prev
          const increment = Math.max(0.5, remaining * 0.08)
          return Math.min(urlTarget, prev + increment)
        })
      }, 100)

      return () => clearInterval(interval)
    } else if (phase === 'analyzing' || phase === 'complete') {
      setScanProgress(85)
    } else {
      scanStartRef.current = null
      setScanProgress(5)
    }
  }, [phase, progress?.current_url_index, progress?.total_urls])

  // Animate the analyzing phase smoothly
  useEffect(() => {
    if (phase === 'analyzing') {
      if (!analyzeStartRef.current) {
        analyzeStartRef.current = Date.now()
        setAnalyzeProgress(85)
      }

      const step = progress?.analysis_step || ''
      const targetPct = step.includes('Prioritizing') ? 95 : 90

      // Gradually increase towards target
      const interval = setInterval(() => {
        setAnalyzeProgress(prev => {
          if (prev >= targetPct) return targetPct
          // Slow down as we approach target (easing)
          const remaining = targetPct - prev
          const increment = Math.max(0.3, remaining * 0.1)
          return Math.min(targetPct, prev + increment)
        })
      }, 100)

      return () => clearInterval(interval)
    } else if (phase === 'complete') {
      setAnalyzeProgress(100)
    } else {
      analyzeStartRef.current = null
      setAnalyzeProgress(85)
    }
  }, [phase, progress?.analysis_step])

  // Calculate progress percentage
  let progressPct = 0
  if (phase === 'initializing') {
    progressPct = 5
  } else if (phase === 'crawling') {
    // Crawling phase: 5-15%
    progressPct = 5 + Math.min(progress?.urls_discovered || 0, 10)
  } else if (phase === 'scanning') {
    // Use animated scan progress
    progressPct = scanProgress
  } else if (phase === 'analyzing') {
    // Use the animated progress value
    progressPct = analyzeProgress
  } else if (phase === 'complete') {
    progressPct = 100
  }

  const formatTime = (seconds: number) => {
    if (seconds < 60) return `${seconds}s`
    const mins = Math.floor(seconds / 60)
    const secs = seconds % 60
    return `${mins}m ${secs}s`
  }

  const truncateUrl = (u: string, maxLen: number = 60) => {
    if (u.length <= maxLen) return u
    return u.substring(0, maxLen - 3) + '...'
  }

  return (
    <div className="gf-progress">
      <div className="gf-progress-rings">
        <div className="gf-progress-ring gf-progress-ring-outer" />
        <div className="gf-progress-ring gf-progress-ring-inner" />
      </div>

      <div className="gf-progress-text">{phaseLabel}</div>
      <div className="gf-progress-url">{truncateUrl(url)}</div>

      {/* Progress bar with percentage */}
      <div className="gf-progress-bar-wrapper">
        <div className="gf-progress-bar-container">
          <div
            className="gf-progress-bar"
            style={{ width: `${progressPct}%` }}
          />
        </div>
        <span className="gf-progress-pct">{Math.round(progressPct)}%</span>
      </div>

      {/* Detailed stats */}
      {progress && (
        <div className="gf-progress-stats">
          {/* Time elapsed - running timer */}
          <div className="gf-progress-stat">
            <span className="gf-progress-stat-label">Time</span>
            <span className="gf-progress-stat-value">{formatTime(elapsedTime)}</span>
          </div>

          {/* URLs discovered (crawl mode) */}
          {progress.urls_discovered > 0 && (
            <div className="gf-progress-stat">
              <span className="gf-progress-stat-label">Pages found</span>
              <span className="gf-progress-stat-value">{progress.urls_discovered}</span>
            </div>
          )}

          {/* Scanning progress */}
          {phase === 'scanning' && progress.total_urls > 0 && (
            <div className="gf-progress-stat">
              <span className="gf-progress-stat-label">Scanning</span>
              <span className="gf-progress-stat-value">
                {progress.current_url_index} / {progress.total_urls}
              </span>
            </div>
          )}

          {/* Current scanner */}
          {progress.current_scanner && (
            <div className="gf-progress-stat">
              <span className="gf-progress-stat-label">Scanner</span>
              <span className="gf-progress-stat-value">{progress.current_scanner}</span>
            </div>
          )}

          {/* Vulnerabilities found */}
          {progress.vulns_found > 0 && (
            <div className="gf-progress-stat gf-progress-stat-vulns">
              <span className="gf-progress-stat-label">Vulnerabilities</span>
              <span className="gf-progress-stat-value">{progress.vulns_found}</span>
            </div>
          )}
        </div>
      )}

      {/* Current activity - scanning URL or running analysis */}
      {phase === 'scanning' && progress?.current_url && progress.total_urls > 1 && (
        <div className="gf-progress-current-activity">
          <span className="gf-progress-activity-label">Scanning:</span>
          <span className="gf-progress-activity-value">{truncateUrl(progress.current_url, 70)}</span>
        </div>
      )}
      {phase === 'analyzing' && progress?.analysis_step && (
        <div className="gf-progress-current-activity">
          <span className="gf-progress-activity-label">Running:</span>
          <span className="gf-progress-activity-value">{progress.analysis_step}</span>
        </div>
      )}
    </div>
  )
}
