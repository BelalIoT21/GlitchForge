const SEVERITY_ORDER = ['Critical', 'High', 'Medium', 'Low', 'Info']
const SEVERITY_COLORS: Record<string, string> = {
  Critical: 'var(--critical)',
  High:     'var(--high)',
  Medium:   'var(--medium)',
  Low:      'var(--low)',
  Info:     'var(--info)',
}

interface SeverityBreakdownProps {
  riskLevels: Record<string, number>
  total: number
}

export default function SeverityBreakdown({ riskLevels, total }: SeverityBreakdownProps) {
  if (total === 0) return null

  const segments = SEVERITY_ORDER
    .filter(level => (riskLevels[level] || 0) > 0)
    .map(level => ({
      level,
      count: riskLevels[level] || 0,
      pct: ((riskLevels[level] || 0) / total) * 100,
      color: SEVERITY_COLORS[level],
    }))

  return (
    <div className="gf-severity">
      <div className="gf-severity-title">Severity Distribution</div>

      <div className="gf-severity-bar">
        {segments.map(seg => (
          <div
            key={seg.level}
            className="gf-severity-segment"
            style={{
              width: `${seg.pct}%`,
              backgroundColor: seg.color,
            }}
          />
        ))}
      </div>

      <div className="gf-severity-legend">
        {segments.map(seg => (
          <div key={seg.level} className="gf-severity-item">
            <span
              className="gf-severity-dot"
              style={{ backgroundColor: seg.color }}
            />
            <span className="gf-severity-count">{seg.count}</span>
            <span className="gf-severity-name">{seg.level}</span>
          </div>
        ))}
      </div>
    </div>
  )
}
