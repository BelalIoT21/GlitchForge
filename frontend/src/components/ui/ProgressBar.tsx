interface ProgressBarProps {
  value: number
  max?: number
  color: string
  label?: string
  height?: number
}

export default function ProgressBar({ value, max = 100, color, label, height = 36 }: ProgressBarProps) {
  const pct = Math.min(100, Math.max(0, (value / max) * 100))

  return (
    <div>
      <div
        className="gf-risk-bar-container"
        style={{ height }}
      >
        <div
          className="gf-risk-bar"
          style={{ width: `${pct}%`, backgroundColor: color }}
        >
          {label && <span className="gf-risk-bar-text">{label}</span>}
        </div>
      </div>
    </div>
  )
}
