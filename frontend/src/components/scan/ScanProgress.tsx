import { useState, useEffect, useRef, useCallback } from 'react'
import type { ScanProgress as ScanProgressType } from '../../api/types'

interface ScanProgressProps {
  url: string
  progress?: ScanProgressType | null
}

const phaseLabels: Record<string, string> = {
  initializing: 'Initializing...',
  crawling: 'Discovering pages...',
  scanning: 'Scanning for vulnerabilities...',
  pentesting: 'Validating exploits...',
  analyzing: 'Running ML analysis...',
  complete: 'Complete',
  error: 'Error'
}

// Phase budget: initializing 0-5, crawling 5-15, scanning 15-72,
//               pentesting 72-87, analyzing 87-97, complete 100
const SCAN_START = 15
const SCAN_END = 72
const PENTEST_START = 72
const PENTEST_END = 87
const ANALYZE_START = 87
// Backend runs XSS, SQL_INJECTION, CSRF per URL
const EXPECTED_SCANNERS = 3

function computeTargetPct(
  progress: ScanProgressType | null | undefined,
  seenScanners: string[]
): number {
  const phase = progress?.phase || 'initializing'

  if (phase === 'initializing') return 3

  if (phase === 'crawling') {
    return 5 + Math.min(progress?.urls_discovered || 0, 10)
  }

  if (phase === 'scanning') {
    const totalUrls = progress?.total_urls || 1
    const urlIdx = progress?.current_url_index || 0
    // Each scanner completed = progress within the current URL
    const scannerFrac = Math.min(seenScanners.length / EXPECTED_SCANNERS, 1)

    if (totalUrls > 1) {
      // Multi-URL: completed URLs + scanner sub-progress within current URL
      const completedUrlsFrac = (urlIdx - 1) / totalUrls
      const withinUrlFrac = scannerFrac / totalUrls
      return SCAN_START + (completedUrlsFrac + withinUrlFrac) * (SCAN_END - SCAN_START)
    } else {
      // Single URL: scanner transitions are the only progress signal
      return SCAN_START + scannerFrac * (SCAN_END - SCAN_START)
    }
  }

  if (phase === 'pentesting') {
    const total = progress?.pentest_total || 0
    const current = progress?.pentest_current || 0
    const frac = total > 0 ? current / total : 0
    return PENTEST_START + frac * (PENTEST_END - PENTEST_START)
  }

  if (phase === 'analyzing') {
    const step = progress?.analysis_step || ''
    // Backend sends exactly 2 steps: "Running ML predictions" → "Prioritizing vulnerabilities"
    if (step.includes('Prioritizing')) return ANALYZE_START + 6  // ~93%
    return ANALYZE_START  // 87%
  }

  if (phase === 'complete') return 100
  return 0
}

export default function ScanProgress({ url, progress }: ScanProgressProps) {
  const phase = progress?.phase || 'initializing'
  const phaseLabel = phaseLabels[phase] || 'Processing...'

  // Running timer that updates every second
  const startTimeRef = useRef<number>(Date.now())
  const [elapsedTime, setElapsedTime] = useState(0)

  // Track which scanners have completed (to drive real scanning progress)
  const seenScannersRef = useRef<string[]>([])
  const prevScannerRef = useRef<string>('')
  const prevPhaseRef = useRef<string>('')
  const prevUrlIndexRef = useRef<number>(0)

  // Single smooth display value that eases toward the computed target
  const [displayPct, setDisplayPct] = useState(3)

  useEffect(() => {
    startTimeRef.current = Date.now()
    const interval = setInterval(() => {
      setElapsedTime(Math.floor((Date.now() - startTimeRef.current) / 1000))
    }, 1000)
    return () => clearInterval(interval)
  }, [])

  // Track scanner transitions and reset when URL or phase changes
  useEffect(() => {
    const currentScanner = progress?.current_scanner || ''
    const urlIdx = progress?.current_url_index || 0

    // Reset seen scanners when entering scanning phase or when URL changes
    if (phase !== prevPhaseRef.current || (phase === 'scanning' && urlIdx !== prevUrlIndexRef.current)) {
      seenScannersRef.current = []
      prevScannerRef.current = ''
      prevPhaseRef.current = phase
      prevUrlIndexRef.current = urlIdx
    }

    // When current_scanner changes, the previous one has finished
    if (phase === 'scanning' && currentScanner && currentScanner !== prevScannerRef.current) {
      if (prevScannerRef.current && !seenScannersRef.current.includes(prevScannerRef.current)) {
        seenScannersRef.current = [...seenScannersRef.current, prevScannerRef.current]
      }
      prevScannerRef.current = currentScanner
    }
  }, [phase, progress?.current_scanner, progress?.current_url_index])

  // Animation loop: smoothly ease displayPct toward real target
  useEffect(() => {
    const interval = setInterval(() => {
      const isComplete = progress?.phase === 'complete'
      const target = computeTargetPct(progress, seenScannersRef.current)
      setDisplayPct(prev => {
        if (Math.abs(prev - target) < 0.2) return target
        const diff = target - prev
        // Snap to 100% quickly on complete (must finish within App's 800ms window)
        // Faster easing for big phase jumps, slow trickle within a phase
        const speed = isComplete ? 0.7 : Math.abs(diff) > 15 ? 0.1 : 0.035
        return prev + diff * speed
      })
    }, 150)
    return () => clearInterval(interval)
  }, [progress])

  const progressPct = Math.round(displayPct)

  const containerRef = useRef<HTMLDivElement>(null)
  const rafRef = useRef<number | null>(null)
  const glowPos = useRef({ x: 50, y: 40 })

  const handleMouseMove = useCallback((e: React.MouseEvent<HTMLDivElement>) => {
    if (rafRef.current) cancelAnimationFrame(rafRef.current)
    const rect = containerRef.current?.getBoundingClientRect()
    if (!rect) return
    glowPos.current.x = ((e.clientX - rect.left) / rect.width) * 100
    glowPos.current.y = ((e.clientY - rect.top) / rect.height) * 100
    containerRef.current?.style.setProperty('--mx', `${glowPos.current.x}%`)
    containerRef.current?.style.setProperty('--my', `${glowPos.current.y}%`)
  }, [])

  const handleMouseLeave = useCallback(() => {
    const el = containerRef.current
    if (!el) return
    const animate = () => {
      glowPos.current.x += (50 - glowPos.current.x) * 0.08
      glowPos.current.y += (40 - glowPos.current.y) * 0.08
      el.style.setProperty('--mx', `${glowPos.current.x}%`)
      el.style.setProperty('--my', `${glowPos.current.y}%`)
      if (Math.abs(glowPos.current.x - 50) > 0.3 || Math.abs(glowPos.current.y - 40) > 0.3) {
        rafRef.current = requestAnimationFrame(animate)
      }
    }
    rafRef.current = requestAnimationFrame(animate)
  }, [])

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
    <div
      className="gf-progress"
      ref={containerRef}
      onMouseMove={handleMouseMove}
      onMouseLeave={handleMouseLeave}
    >
      <div className="gf-progress-rings">
        <div className="gf-progress-ring-track" />
        <div className="gf-progress-ring gf-progress-ring-outer" />
        <div className="gf-progress-ring gf-progress-ring-inner" />
        <div className="gf-progress-ring-center" />
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
        <span className="gf-progress-pct">{progressPct}%</span>
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

          {/* Pentesting progress */}
          {phase === 'pentesting' && progress.pentest_total > 0 && (
            <div className="gf-progress-stat">
              <span className="gf-progress-stat-label">Validating</span>
              <span className="gf-progress-stat-value">
                {progress.pentest_current} / {progress.pentest_total}
              </span>
            </div>
          )}
          {phase === 'pentesting' && progress.pentest_confirmed > 0 && (
            <div className="gf-progress-stat gf-progress-stat-vulns">
              <span className="gf-progress-stat-label">Confirmed</span>
              <span className="gf-progress-stat-value">{progress.pentest_confirmed}</span>
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
          <span className="gf-progress-activity-dot" />
          <span className="gf-progress-activity-label">Scanning:</span>
          <span className="gf-progress-activity-value">{truncateUrl(progress.current_url, 70)}</span>
        </div>
      )}
      {phase === 'pentesting' && progress?.pentest_technique && (
        <div className="gf-progress-current-activity">
          <span className="gf-progress-activity-dot" />
          <span className="gf-progress-activity-label">Testing:</span>
          <span className="gf-progress-activity-value">{progress.pentest_technique}</span>
        </div>
      )}
      {phase === 'analyzing' && progress?.analysis_step && (
        <div className="gf-progress-current-activity">
          <span className="gf-progress-activity-dot" />
          <span className="gf-progress-activity-label">Running:</span>
          <span className="gf-progress-activity-value">{progress.analysis_step}</span>
        </div>
      )}
    </div>
  )
}
