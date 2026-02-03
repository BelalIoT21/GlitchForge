import type { ScanResult } from '../../api/types'
import SeverityBreakdown from './SeverityBreakdown'

interface DashboardOverviewProps {
  result: ScanResult
}

export default function DashboardOverview({ result }: DashboardOverviewProps) {
  const stats = result.statistics
  const totalTime = result.total_time ?? result.scan_time

  return (
    <div className="gf-dashboard">
      <div className="gf-dashboard-header">
        <div>
          <div className="gf-dashboard-title">Scan Results</div>
          <div className="gf-dashboard-subtitle">
            {result.vulnerabilities_found} vulnerabilities found on{' '}
            <span className="gf-dashboard-url">{result.url}</span>
          </div>
        </div>
      </div>

      <div className="gf-stats">
        <div className="gf-stat">
          <span className="gf-stat-value" style={{ color: result.vulnerabilities_found > 0 ? 'var(--critical)' : 'var(--low)' }}>
            {result.vulnerabilities_found}
          </span>
          <span className="gf-stat-label">Total Found</span>
        </div>

        {stats && (
          <>
            <div className="gf-stat">
              <span className="gf-stat-value" style={{ color: 'var(--critical)' }}>
                {stats.risk_levels?.Critical || 0}
              </span>
              <span className="gf-stat-label">Critical</span>
            </div>
            <div className="gf-stat">
              <span className="gf-stat-value" style={{ color: 'var(--high)' }}>
                {stats.risk_levels?.High || 0}
              </span>
              <span className="gf-stat-label">High</span>
            </div>
            <div className="gf-stat">
              <span className="gf-stat-value" style={{ color: 'var(--medium)' }}>
                {stats.risk_levels?.Medium || 0}
              </span>
              <span className="gf-stat-label">Medium</span>
            </div>
            <div className="gf-stat">
              <span className="gf-stat-value" style={{ color: 'var(--low)' }}>
                {stats.risk_levels?.Low || 0}
              </span>
              <span className="gf-stat-label">Low</span>
            </div>
            <div className="gf-stat">
              <span className="gf-stat-value">
                {stats.model_agreement_rate?.toFixed(0) ?? '\u2014'}%
              </span>
              <span className="gf-stat-label">ML Agreement</span>
            </div>
          </>
        )}

        <div className="gf-stat">
          <span className="gf-stat-value">{totalTime}s</span>
          <span className="gf-stat-label">Scan Time</span>
        </div>
      </div>

      {stats && stats.risk_levels && (
        <SeverityBreakdown
          riskLevels={stats.risk_levels}
          total={result.vulnerabilities_found}
        />
      )}
    </div>
  )
}
