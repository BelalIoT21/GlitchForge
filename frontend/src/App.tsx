import { useState, useMemo } from 'react'
import { runScan } from './api/client'
import type { ScanResult, RiskScore } from './api/types'
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

  // Deduplicate risk_scores: keep highest risk_score per (url, parameter)
  const dedupedResult = useMemo(() => {
    if (!result) return null
    if (!result.risk_scores || result.risk_scores.length === 0) {
      return result
    }
    const seen = new Map<string, RiskScore>()
    for (const v of result.risk_scores) {
      // Use vulnerability_id as fallback if where is missing
      const key = v.where
        ? `${v.where.url || ''}|${v.where.parameter || ''}`
        : v.vulnerability_id || String(Math.random())
      const existing = seen.get(key)
      if (!existing || v.risk_score > existing.risk_score) {
        seen.set(key, v)
      }
    }
    const deduped = Array.from(seen.values())
    // Recompute stats from deduped list
    const riskLevels: Record<string, number> = {}
    for (const v of deduped) {
      riskLevels[v.risk_level] = (riskLevels[v.risk_level] || 0) + 1
    }
    return {
      ...result,
      vulnerabilities_found: deduped.length,
      risk_scores: deduped,
      statistics: result.statistics ? {
        ...result.statistics,
        total_vulnerabilities: deduped.length,
        risk_levels: riskLevels,
      } : undefined,
    }
  }, [result])

  const handleScan = async (url: string, scanTypes: string[]) => {
    setLoading(true)
    setError(null)
    setResult(null)
    setScanUrl(url)
    setPage('results')

    try {
      const data = await runScan({ url, scan_types: scanTypes })
      setResult(data as ScanResult)
    } catch (err) {
      const msg = err instanceof Error
        ? err.message
        : 'Network error \u2014 is the backend running on port 5000?'
      setError(msg)
    } finally {
      setLoading(false)
    }
  }

  const handleGoHome = () => {
    setPage('home')
    setLoading(false)
    setError(null)
    setResult(null)
    setScanUrl('')
  }

  const handleDownloadReport = async () => {
    if (!dedupedResult) return
    setGenerating(true)
    try {
      await generateReport(dedupedResult)
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
        canDownload={!!dedupedResult && !loading}
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
            {loading && <ScanProgress url={scanUrl} />}

            {error && (
              <div className="gf-error-box">
                <span className="gf-error-icon">!</span>
                <div>
                  <div className="gf-error-title">Error</div>
                  <div className="gf-error-msg">{error}</div>
                </div>
              </div>
            )}

            {dedupedResult && !loading && (
              <>
                {!dedupedResult.success ? (
                  <div className="gf-error-box">
                    <span className="gf-error-icon">!</span>
                    <div>
                      <div className="gf-error-title">Scan Failed</div>
                      <div className="gf-error-msg">{dedupedResult.message || 'An unexpected error occurred.'}</div>
                    </div>
                  </div>
                ) : dedupedResult.vulnerabilities_found === 0 ? (
                  <div className="gf-empty">
                    <span className="gf-empty-icon">&#10003;</span>
                    <div className="gf-empty-title">No vulnerabilities found</div>
                    <div className="gf-empty-subtitle">
                      The target URL did not trigger any known vulnerability signatures.
                    </div>
                    <div className="gf-empty-meta">
                      Scan time: {dedupedResult.total_time ?? dedupedResult.scan_time}s
                    </div>
                  </div>
                ) : (
                  <>
                    <DashboardOverview result={dedupedResult} />
                    <VulnList vulns={dedupedResult.risk_scores} />
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
