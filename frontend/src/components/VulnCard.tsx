import { useState } from 'react'
import type { RiskScore } from '../api/types'

const LEVEL_COLORS: Record<string, string> = {
  Critical: '#ef4444',
  High: '#f97316',
  Medium: '#eab308',
  Low: '#22c55e',
  Info: '#6366f1',
}

const LEVEL_BG: Record<string, string> = {
  Critical: 'rgba(239,68,68,0.12)',
  High: 'rgba(249,115,22,0.12)',
  Medium: 'rgba(234,179,8,0.12)',
  Low: 'rgba(34,197,94,0.12)',
  Info: 'rgba(99,102,241,0.12)',
}

interface VulnCardProps {
  vuln: RiskScore
}

export default function VulnCard({ vuln }: VulnCardProps) {
  const [expanded, setExpanded] = useState(false)

  const color = LEVEL_COLORS[vuln.risk_level] || '#888'
  const bg = LEVEL_BG[vuln.risk_level] || 'rgba(136,136,136,0.1)'

  return (
    <div className="vuln-card" style={{ borderLeftColor: color }}>
      {/* Header row — always visible */}
      <div className="vuln-card-header" onClick={() => setExpanded(!expanded)}>
        <div className="vuln-card-header-left">
          <span className="vuln-badge" style={{ backgroundColor: bg, color }}>
            {vuln.risk_level}
          </span>
          <span className="vuln-id">{vuln.vulnerability_id}</span>
          {vuln.what && (
            <span className="vuln-type">{vuln.what.vulnerability_type}</span>
          )}
        </div>
        <div className="vuln-card-header-right">
          <span className="vuln-score">{vuln.risk_score}<small>/100</small></span>
          <span className="vuln-chevron">{expanded ? '▲' : '▼'}</span>
        </div>
      </div>

      {/* Collapsed summary */}
      {!expanded && vuln.where && (
        <div className="vuln-summary">
          <span className="vuln-summary-url">{vuln.where.url}</span>
          <span className="vuln-summary-param">param: {vuln.where.parameter}</span>
        </div>
      )}

      {/* Expanded detail */}
      {expanded && (
        <div className="vuln-detail">
          {/* WHERE */}
          {vuln.where && (
            <div className="vuln-section">
              <div className="vuln-section-title">Where it occurred</div>
              <div className="vuln-section-row">
                <span className="vuln-section-label">URL</span>
                <span className="vuln-section-value">{vuln.where.url}</span>
              </div>
              <div className="vuln-section-row">
                <span className="vuln-section-label">Parameter</span>
                <span className="vuln-section-value">{vuln.where.parameter}</span>
              </div>
            </div>
          )}

          {/* WHAT */}
          {vuln.what && (
            <div className="vuln-section">
              <div className="vuln-section-title">What caused it</div>
              <div className="vuln-section-row">
                <span className="vuln-section-label">Type</span>
                <span className="vuln-section-value">{vuln.what.vulnerability_type} — {vuln.what.cwe_id}</span>
              </div>
              <div className="vuln-section-row">
                <span className="vuln-section-label">Payload</span>
                <span className="vuln-section-value vuln-code">{vuln.what.payload_used}</span>
              </div>
              <div className="vuln-section-row">
                <span className="vuln-section-label">Evidence</span>
                <span className="vuln-section-value">{vuln.what.evidence}</span>
              </div>
              <div className="vuln-section-row">
                <span className="vuln-section-label">Details</span>
                <span className="vuln-section-value">{vuln.what.description}</span>
              </div>
            </div>
          )}

          {/* HOW TO FIX */}
          {vuln.how_to_fix && (
            <div className="vuln-section vuln-section-fix">
              <div className="vuln-section-title">How to fix it</div>
              <div className="vuln-section-value vuln-remediation">
                {vuln.how_to_fix.remediation.split('\n').map((line, i) => (
                  <div key={i}>{line.trim()}</div>
                ))}
              </div>
            </div>
          )}

          {/* ML explanation */}
          <div className="vuln-section">
            <div className="vuln-section-title">ML Analysis</div>
            <div className="vuln-section-value">{vuln.explanation}</div>
            <div className="vuln-meta">
              <span>CVSS: {vuln.cvss_base}</span>
              <span>Exploitability: {vuln.cvss_exploitability}</span>
              <span>Impact: {vuln.cvss_impact}</span>
              <span>Confidence: {(vuln.confidence * 100).toFixed(0)}%</span>
              <span>{vuln.model_agreement ? 'Models agree' : 'Models disagree'}</span>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
