import { useState } from 'react'
import { runScan, runQuickScan } from './api/client'
import type { ScanResult } from './api/types'
import Header from './components/Header'
import ScanForm from './components/ScanForm'
import ResultsList from './components/ResultsList'

export default function App() {
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [result, setResult] = useState<ScanResult | null>(null)

  const handleScan = async (url: string, scanTypes: string[], mode: 'full' | 'quick') => {
    setLoading(true)
    setError(null)
    setResult(null)

    try {
      const data = mode === 'full'
        ? await runScan({ url, scan_types: scanTypes })
        : await runQuickScan({ url, scan_types: scanTypes })

      // Normalise quick-scan response into ScanResult shape
      if ('vulnerabilities' in data) {
        const quick = data as unknown as { success: boolean; url: string; vulnerabilities_found: number; vulnerabilities: Array<{ where: any; what: any; how_to_fix: any }> }
        setResult({
          success: quick.success,
          url: quick.url,
          vulnerabilities_found: quick.vulnerabilities_found,
          scan_time: 0,
          risk_scores: quick.vulnerabilities.map((v, i) => ({
            vulnerability_id: `QUICK-${i + 1}`,
            risk_score: 0,
            risk_level: v.what.severity || 'Unknown',
            remediation_priority: 'Review',
            cvss_base: 0,
            cvss_exploitability: 0,
            cvss_impact: 0,
            has_exploit: false,
            model_agreement: false,
            confidence: v.what.confidence || 0,
            explanation: 'Quick scan — no ML scoring.',
            primary_factors: [],
            where: v.where,
            what: v.what,
            how_to_fix: v.how_to_fix,
          })),
        })
      } else {
        setResult(data as ScanResult)
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Network error — is the backend running on port 5000?'
      setError(msg)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="app">
      <Header />

      <main className="main">
        <ScanForm onSubmit={handleScan} loading={loading} />

        {loading && (
          <div className="loading">
            <div className="spinner" />
            <span>Scanning target — this may take a moment...</span>
          </div>
        )}

        {error && (
          <div className="error-box">
            <span className="error-icon">!</span>
            <div>
              <div className="error-title">Error</div>
              <div className="error-msg">{error}</div>
            </div>
          </div>
        )}

        {result && !loading && <ResultsList result={result} />}
      </main>
    </div>
  )
}
