import { useState, useRef, useCallback } from 'react'
import { AnimatePresence, motion } from 'framer-motion'
import { runScanStream } from './api/client'
import type { ScanResult, ScanProgress as ScanProgressType } from './api/types'
import TopBar from './components/layout/TopBar'
import Footer from './components/layout/Footer'
import ScanInput from './components/scan/ScanInput'
import ScanProgress from './components/scan/ScanProgress'
import DashboardOverview from './components/dashboard/DashboardOverview'
import VulnList from './components/vulnerability/VulnList'
import Hero from './components/info/Hero'
import HowItWorks from './components/info/HowItWorks'
import Capabilities from './components/info/Capabilities'
import { generateReport } from './components/report/ReportGenerator'
import { formatTime } from './utils/formatTime'
import Toaster, { type ToastItem } from './components/ui/Toast'
import ParticleCanvas from './components/ui/ParticleCanvas'

type Page = 'home' | 'results'

let toastCounter = 0

export default function App() {
  const [page, setPage] = useState<Page>('home')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState<ScanResult | null>(null)
  const [scanUrl, setScanUrl] = useState('')
  const [generating, setGenerating] = useState(false)
  const [progress, setProgress] = useState<ScanProgressType | null>(null)
  const [toasts, setToasts] = useState<ToastItem[]>([])

  const abortRef = useRef<(() => void) | null>(null)

  const addToast = useCallback((message: string, type: ToastItem['type'] = 'error', duration = 6000) => {
    const id = String(++toastCounter)
    setToasts(prev => [...prev, { id, message, type, duration }])
  }, [])

  const dismissToast = useCallback((id: string) => {
    setToasts(prev => prev.filter(t => t.id !== id))
  }, [])

  const handleScan = useCallback((url: string, scanTypes: string[], cookies?: Record<string, string>, crawl?: boolean) => {
    setLoading(true)
    setResult(null)
    setProgress(null)
    setScanUrl(url)
    setPage('results')

    if (abortRef.current) {
      abortRef.current()
    }

    abortRef.current = runScanStream(
      { url, scan_types: scanTypes, cookies, crawl, max_urls: crawl ? 50 : undefined },
      {
        onProgress: (prog) => {
          setProgress(prog)
        },
        onResult: (data) => {
          setProgress(prev => prev ? { ...prev, phase: 'complete' } : null)

          setTimeout(() => {
            setResult(data)
            setLoading(false)
            setProgress(null)
            abortRef.current = null

            // Show toast if scan succeeded but result indicates failure
            if (!data.success) {
              addToast(data.message || 'Scan completed with errors.', 'warning')
            }
          }, 800)
        },
        onError: (msg) => {
          setLoading(false)
          setProgress(null)
          abortRef.current = null
          // Go back home and show toast
          setPage('home')
          addToast(msg || 'Scan failed. Check that the backend is running on port 5000.', 'error')
        }
      }
    )
  }, [addToast])

  const handleGoHome = useCallback(() => {
    if (abortRef.current) {
      abortRef.current()
      abortRef.current = null
    }
    setPage('home')
    setLoading(false)
    setResult(null)
    setProgress(null)
    setScanUrl('')
  }, [])

  const handleDownloadReport = async () => {
    if (!result) return
    setGenerating(true)
    try {
      await generateReport(result)
    } catch (err) {
      console.error('Report generation failed:', err)
      addToast('Failed to generate PDF report.', 'error')
    } finally {
      setGenerating(false)
    }
  }

  return (
    <div className="gf-app">
      <ParticleCanvas />
      <TopBar
        onDownloadReport={handleDownloadReport}
        canDownload={!!result && !loading}
        generating={generating}
        onGoHome={handleGoHome}
      />

      <main className="gf-main">
        <AnimatePresence mode="wait">
          {page === 'home' && (
            <motion.div
              key="home"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              transition={{ duration: 0.18 }}
              style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}
            >
              <ScanInput onSubmit={handleScan} loading={loading} />
              <Hero />
              <HowItWorks />
              <Capabilities />
            </motion.div>
          )}

          {page === 'results' && (
            <motion.div
              key="results"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              transition={{ duration: 0.18 }}
              style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}
            >
              {loading && <ScanProgress url={scanUrl} progress={progress} />}

              {result && !loading && (
                <>
                  {result.success && result.vulnerabilities_found === 0 ? (
                    <div className="gf-empty">
                      <div className="gf-empty-icon-wrap">
                        <div className="gf-empty-ring" />
                        <div className="gf-empty-ring gf-empty-ring-outer" />
                        <div className="gf-empty-icon-bg">
                          <svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round">
                            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                            <polyline points="9 12 11 14 15 10"/>
                          </svg>
                        </div>
                      </div>
                      <div className="gf-empty-title">No Vulnerabilities Found</div>
                      <div className="gf-empty-subtitle">
                        The target did not trigger any known vulnerability signatures for the selected scan types.
                      </div>
                      <div className="gf-empty-meta">
                        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                          <circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/>
                        </svg>
                        Scan time: {formatTime(result.total_time ?? result.scan_time)}
                      </div>
                      <div className="gf-empty-actions">
                        <button className="gf-empty-btn" onClick={handleGoHome}>
                          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
                            <polyline points="15 18 9 12 15 6"/>
                          </svg>
                          Scan Another Target
                        </button>
                      </div>
                    </div>
                  ) : result.success ? (
                    <>
                      <DashboardOverview result={result} />
                      <VulnList vulns={result.risk_scores} />
                      <div style={{ display: 'flex', justifyContent: 'center', marginTop: '8px' }}>
                        <button className="gf-empty-btn" onClick={handleGoHome}>
                          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
                            <polyline points="15 18 9 12 15 6"/>
                          </svg>
                          Scan Another Target
                        </button>
                      </div>
                    </>
                  ) : null}
                </>
              )}
            </motion.div>
          )}
        </AnimatePresence>
      </main>

      <Footer />

      {generating && (
        <div className="gf-report-generating">
          <div className="gf-report-modal">
            <div className="gf-report-rings">
              <div className="gf-report-ring-track" />
              <div className="gf-report-ring gf-report-ring-outer" />
              <div className="gf-report-ring gf-report-ring-inner" />
              <div className="gf-report-ring-center" />
            </div>
            <div className="gf-report-title">Generating Report</div>
            <div className="gf-report-steps">
              <div className="gf-report-step active">
                <span className="gf-report-step-dot" />
                Compiling vulnerability data
              </div>
              <div className="gf-report-step active">
                <span className="gf-report-step-dot" />
                Rendering pentest evidence
              </div>
              <div className="gf-report-step">
                <span className="gf-report-step-dot" />
                Building PDF layout
              </div>
            </div>
            <div className="gf-report-text">This may take a few seconds…</div>
          </div>
        </div>
      )}

      <Toaster toasts={toasts} onDismiss={dismissToast} />
    </div>
  )
}
