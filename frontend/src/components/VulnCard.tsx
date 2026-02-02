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

          {/* ML Analysis with Visual Risk Breakdown */}
          <div className="vuln-section vuln-section-ml">
            <div className="vuln-section-title">ML-Based Risk Assessment</div>

            {/* Risk Score Visualization */}
            <div className="risk-score-visual">
              <div className="risk-score-bar-container">
                <div
                  className="risk-score-bar"
                  style={{
                    width: `${vuln.risk_score}%`,
                    backgroundColor: color
                  }}
                >
                  <span className="risk-score-text">{vuln.risk_score}/100</span>
                </div>
              </div>
              <div className="risk-level-indicator" style={{ color }}>
                {vuln.risk_level} Risk → {vuln.remediation_priority}
              </div>
            </div>

            {/* Primary Risk Factors */}
            {vuln.primary_factors && vuln.primary_factors.length > 0 && (
              <div className="risk-factors">
                <div className="risk-factors-title">Key Risk Factors:</div>
                <ul className="risk-factors-list">
                  {vuln.primary_factors.map((factor, i) => (
                    <li key={i} className="risk-factor-item">
                      <span className="risk-factor-bullet">•</span>
                      {factor}
                    </li>
                  ))}
                </ul>
              </div>
            )}

            {/* CVSS Breakdown Chart */}
            <div className="cvss-breakdown">
              <div className="cvss-breakdown-title">CVSS Score Breakdown</div>
              <div className="cvss-bar-chart">
                <div className="cvss-bar-row">
                  <span className="cvss-bar-label">Base Score</span>
                  <div className="cvss-bar-track">
                    <div
                      className="cvss-bar-fill"
                      style={{
                        width: `${(vuln.cvss_base / 10) * 100}%`,
                        backgroundColor: '#ef4444'
                      }}
                    />
                  </div>
                  <span className="cvss-bar-value">{vuln.cvss_base.toFixed(1)}</span>
                </div>
                <div className="cvss-bar-row">
                  <span className="cvss-bar-label">Exploitability</span>
                  <div className="cvss-bar-track">
                    <div
                      className="cvss-bar-fill"
                      style={{
                        width: `${(vuln.cvss_exploitability / 4) * 100}%`,
                        backgroundColor: '#f97316'
                      }}
                    />
                  </div>
                  <span className="cvss-bar-value">{vuln.cvss_exploitability.toFixed(1)}</span>
                </div>
                <div className="cvss-bar-row">
                  <span className="cvss-bar-label">Impact</span>
                  <div className="cvss-bar-track">
                    <div
                      className="cvss-bar-fill"
                      style={{
                        width: `${(vuln.cvss_impact / 6) * 100}%`,
                        backgroundColor: '#eab308'
                      }}
                    />
                  </div>
                  <span className="cvss-bar-value">{vuln.cvss_impact.toFixed(1)}</span>
                </div>
              </div>
            </div>

            {/* ML Explanation */}
            <div className="ml-explanation">
              <div className="ml-explanation-icon">🤖</div>
              <div className="ml-explanation-text">{vuln.explanation}</div>
            </div>

            {/* Model Info */}
            <div className="model-info">
              <span className="model-info-badge">
                <span className="model-info-label">Model Agreement:</span>
                <span className={`model-info-value ${vuln.model_agreement ? 'agree' : 'disagree'}`}>
                  {vuln.model_agreement ? '✓ Both models agree' : '✗ Models disagree'}
                </span>
              </span>
              <span className="model-info-badge">
                <span className="model-info-label">Confidence:</span>
                <span className="model-info-value">{(vuln.confidence * 100).toFixed(0)}%</span>
              </span>
              {vuln.has_exploit && (
                <span className="model-info-badge exploit-badge">
                  ⚠ Public Exploit Available
                </span>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
