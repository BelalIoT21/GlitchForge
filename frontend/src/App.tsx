import { useState } from 'react'
import { runScan } from './api/client'
import type { ScanResult } from './api/types'
import Header from './components/Header'
import ScanForm from './components/ScanForm'
import ResultsList from './components/ResultsList'

export default function App() {
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [result, setResult] = useState<ScanResult | null>(null)

  const handleScan = async (url: string, scanTypes: string[]) => {
    setLoading(true)
    setError(null)
    setResult(null)

    try {
      const data = await runScan({ url, scan_types: scanTypes })
      setResult(data as ScanResult)
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
