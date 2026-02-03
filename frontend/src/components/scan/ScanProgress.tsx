interface ScanProgressProps {
  url: string
}

export default function ScanProgress({ url }: ScanProgressProps) {
  return (
    <div className="gf-progress">
      <div className="gf-progress-rings">
        <div className="gf-progress-ring gf-progress-ring-outer" />
        <div className="gf-progress-ring gf-progress-ring-inner" />
      </div>
      <div className="gf-progress-text">
        Running scan with ML analysis and XAI explainability...
      </div>
      <div className="gf-progress-url">{url}</div>
    </div>
  )
}