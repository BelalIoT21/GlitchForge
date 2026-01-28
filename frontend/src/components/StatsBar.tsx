import type { ScanStatistics } from '../api/types'

interface StatsBarProps {
  stats: ScanStatistics
  totalTime: number
}

export default function StatsBar({ stats, totalTime }: StatsBarProps) {
  return (
    <div className="stats-bar">
      <div className="stat-card">
        <span className="stat-value">{stats.total_vulnerabilities}</span>
        <span className="stat-label">Total Found</span>
      </div>
      <div className="stat-card">
        <span className="stat-value" style={{ color: '#ef4444' }}>
          {stats.risk_levels?.Critical || 0}
        </span>
        <span className="stat-label">Critical</span>
      </div>
      <div className="stat-card">
        <span className="stat-value" style={{ color: '#f97316' }}>
          {stats.risk_levels?.High || 0}
        </span>
        <span className="stat-label">High</span>
      </div>
      <div className="stat-card">
        <span className="stat-value" style={{ color: '#eab308' }}>
          {stats.risk_levels?.Medium || 0}
        </span>
        <span className="stat-label">Medium</span>
      </div>
      <div className="stat-card">
        <span className="stat-value" style={{ color: '#22c55e' }}>
          {stats.risk_levels?.Low || 0}
        </span>
        <span className="stat-label">Low</span>
      </div>
      <div className="stat-card stat-card-right">
        <span className="stat-value">{stats.model_agreement_rate?.toFixed(0) ?? '—'}%</span>
        <span className="stat-label">ML Agreement</span>
      </div>
      <div className="stat-card stat-card-right">
        <span className="stat-value">{totalTime}s</span>
        <span className="stat-label">Scan Time</span>
      </div>
    </div>
  )
}
