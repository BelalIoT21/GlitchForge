import { useState, useRef, useCallback } from 'react'
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

type Page = 'home' | 'results'

export default function App() {
  const [page, setPage] = useState<Page>('home')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [result, setResult] = useState<ScanResult | null>(null)
  const [scanUrl, setScanUrl] = useState('')
  const [generating, setGenerating] = useState(false)
  const [progress, setProgress] = useState<ScanProgressType | null>(null)

  // Store abort function for cancellation
  const abortRef = useRef<(() => void) | null>(null)

  const handleScan = useCallback((url: string, scanTypes: string[], cookies?: Record<string, string>, crawl?: boolean) => {
    setLoading(true)
    setError(null)
    setResult(null)
    setProgress(null)
    setScanUrl(url)
    setPage('results')

    // Cancel any existing scan
    if (abortRef.current) {
      abortRef.current()
    }

    // Start streaming scan
    abortRef.current = runScanStream(
      { url, scan_types: scanTypes, cookies, crawl, max_urls: crawl ? 50 : undefined },
      {
        onProgress: (prog) => {
          setProgress(prog)
        },
        onResult: (data) => {
          // First show the completed progress bar
          setProgress(prev => prev ? { ...prev, phase: 'complete' } : null)

          // Wait for the progress bar to complete its animation before showing results
          setTimeout(() => {
            setResult(data)
            setLoading(false)
            setProgress(null)
            abortRef.current = null
          }, 800)
        },
        onError: (msg) => {
          setError(msg || 'Scan failed')
          setLoading(false)
          setProgress(null)
          abortRef.current = null
        }
      }
    )
  }, [])

  const handleGoHome = useCallback(() => {
    // Cancel any running scan
    if (abortRef.current) {
      abortRef.current()
      abortRef.current = null
    }
    setPage('home')
    setLoading(false)
    setError(null)
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
    } finally {
      setGenerating(false)
    }
  }

  return (
    <div className="gf-app">
      <TopBar
        onDownloadReport={handleDownloadReport}
        canDownload={!!result && !loading}
        generating={generating}
        onGoHome={handleGoHome}
      />

      <main className="gf-main">
        {page === 'home' && (
          <>
            <ScanInput onSubmit={handleScan} loading={loading} />
            <Hero />
            <HowItWorks />
            <Capabilities />
          </>
        )}

        {page === 'results' && (
          <>
            {loading && <ScanProgress url={scanUrl} progress={progress} />}

            {error && (
              <div className="gf-error-box">
                <span className="gf-error-icon">!</span>
                <div>
                  <div className="gf-error-title">Error</div>
                  <div className="gf-error-msg">{error}</div>
                </div>
              </div>
            )}

            {result && !loading && (
              <>
                {!result.success ? (
                  <div className="gf-error-box">
                    <span className="gf-error-icon">!</span>
                    <div>
                      <div className="gf-error-title">Scan Failed</div>
                      <div className="gf-error-msg">{result.message || 'An unexpected error occurred.'}</div>
                    </div>
                  </div>
                ) : result.vulnerabilities_found === 0 ? (
                  <div className="gf-empty">
                    <span className="gf-empty-icon">&#10003;</span>
                    <div className="gf-empty-title">No vulnerabilities found</div>
                    <div className="gf-empty-subtitle">
                      The target URL did not trigger any known vulnerability signatures.
                    </div>
                    <div className="gf-empty-meta">
                      Scan time: {result.total_time ?? result.scan_time}s
                    </div>
                  </div>
                ) : (
                  <>
                    <DashboardOverview result={result} />
                    <VulnList vulns={result.risk_scores} />
                  </>
                )}
              </>
            )}

          </>
        )}
      </main>

      <Footer />

      {generating && (
        <div className="gf-report-generating">
          <div className="gf-report-modal">
            <div className="gf-report-spinner" />
            <div className="gf-report-text">Generating PDF report...</div>
          </div>
        </div>
      )}
    </div>
  )
}
