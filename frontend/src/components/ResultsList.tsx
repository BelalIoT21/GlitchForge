import type { ScanResult } from '../api/types'
import StatsBar from './StatsBar'
import VulnCard from './VulnCard'

interface ResultsListProps {
  result: ScanResult
}

export default function ResultsList({ result }: ResultsListProps) {
  if (!result.success) {
    return (
      <div className="error-box">
        <span className="error-icon">!</span>
        <div>
          <div className="error-title">Scan Failed</div>
          <div className="error-msg">{result.message || 'An unexpected error occurred.'}</div>
        </div>
      </div>
    )
  }

  if (result.vulnerabilities_found === 0) {
    return (
      <div className="empty-result">
        <span className="empty-icon">&#10003;</span>
        <div className="empty-title">No vulnerabilities found</div>
        <div className="empty-subtitle">The target URL did not trigger any known vulnerability signatures.</div>
        <div className="empty-meta">Scan time: {result.scan_time}s</div>
      </div>
    )
  }

  return (
    <div className="results">
      <div className="results-header">
        <div>
          <div className="results-title">Scan Results</div>
          <div className="results-subtitle">
            {result.vulnerabilities_found} vulnerabilities found on <code>{result.url}</code>
          </div>
        </div>
      </div>

      {result.statistics && (
        <StatsBar stats={result.statistics} totalTime={result.total_time ?? result.scan_time} />
      )}

      <div className="results-list">
        {result.risk_scores.map((vuln, i) => (
          <VulnCard key={vuln.vulnerability_id + i} vuln={vuln} index={i} />
        ))}
      </div>
    </div>
  )
}
