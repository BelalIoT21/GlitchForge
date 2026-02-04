import { useState, type FormEvent } from 'react'

interface ScanInputProps {
  onSubmit: (url: string, scanTypes: string[], cookies?: Record<string, string>, crawl?: boolean) => void
  loading: boolean
}

const ALL_TYPES = ['sql', 'xss', 'csrf']

export default function ScanInput({ onSubmit, loading }: ScanInputProps) {
  const [url, setUrl] = useState('')
  const [scanTypes, setScanTypes] = useState<string[]>(ALL_TYPES)
  const [showAdvanced, setShowAdvanced] = useState(false)
  const [phpSessionId, setPhpSessionId] = useState('')
  const [securityLevel, setSecurityLevel] = useState('low')
  const [crawl, setCrawl] = useState(false)

  const toggleType = (type: string) => {
    setScanTypes(prev =>
      prev.includes(type) ? prev.filter(t => t !== type) : [...prev, type]
    )
  }

  const handleSubmit = (e: FormEvent) => {
    e.preventDefault()
    if (!url.trim() || scanTypes.length === 0) return

    // Build cookies object if PHPSESSID is provided
    const cookies = phpSessionId.trim()
      ? { PHPSESSID: phpSessionId.trim(), security: securityLevel }
      : undefined

    onSubmit(url.trim(), scanTypes, cookies, crawl)
  }

  const isDvwaUrl = url.toLowerCase().includes('dvwa')
  const isKnownVulnSite = isDvwaUrl || url.toLowerCase().includes('vulnweb') || url.toLowerCase().includes('bwapp')

  return (
    <form className="gf-scan" onSubmit={handleSubmit}>
      <div className="gf-scan-row">
        <input
          type="text"
          className="gf-scan-input"
          placeholder="Enter target URL (e.g. http://testphp.vulnweb.com)"
          value={url}
          onChange={e => setUrl(e.target.value)}
          disabled={loading}
          autoFocus
        />
        <button
          type="submit"
          className="gf-scan-submit"
          disabled={loading || !url.trim() || scanTypes.length === 0}
        >
          {loading ? 'Scanning...' : crawl ? 'Scan Site' : 'Scan URL'}
        </button>
      </div>

      <div className="gf-scan-options">
        <div className="gf-scan-group">
          <span className="gf-scan-label">Scan Types</span>
          {ALL_TYPES.map(type => (
            <button
              key={type}
              type="button"
              className={`gf-chip ${scanTypes.includes(type) ? 'active' : ''}`}
              onClick={() => toggleType(type)}
              disabled={loading}
            >
              {type}
            </button>
          ))}
        </div>

        <div className="gf-scan-group">
          <span className="gf-scan-label">Mode</span>
          <div className="gf-mode-toggle">
            <button
              type="button"
              className={`gf-mode-option ${!crawl ? 'active' : ''}`}
              onClick={() => setCrawl(false)}
              disabled={loading}
            >
              Single URL
            </button>
            <button
              type="button"
              className={`gf-mode-option ${crawl ? 'active' : ''}`}
              onClick={() => setCrawl(true)}
              disabled={loading}
            >
              Crawl Site
            </button>
          </div>
        </div>

        <button
          type="button"
          className={`gf-chip ${showAdvanced ? 'active' : ''}`}
          onClick={() => setShowAdvanced(!showAdvanced)}
          disabled={loading}
        >
          {showAdvanced ? 'Hide' : 'Show'} Auth Options
        </button>
      </div>

      {crawl && isKnownVulnSite && (
        <div className="gf-scan-hint" style={{ marginTop: '12px' }}>
          {isDvwaUrl && 'DVWA detected - will scan all vulnerability pages automatically'}
          {url.toLowerCase().includes('vulnweb') && 'Acunetix test site detected - will scan known vulnerable endpoints'}
          {url.toLowerCase().includes('bwapp') && 'bWAPP detected - will scan known vulnerable pages'}
        </div>
      )}

      {showAdvanced && (
        <div className="gf-scan-advanced">
          {isDvwaUrl && (
            <div className="gf-scan-hint">
              DVWA detected - enter your session cookie to scan authenticated pages
            </div>
          )}
          <div className="gf-scan-auth-row">
            <div className="gf-scan-auth-field">
              <label htmlFor="phpsessid">PHPSESSID Cookie</label>
              <input
                id="phpsessid"
                type="text"
                className="gf-scan-auth-input"
                placeholder="e.g. f309cc067520e7d8f6de2320f5726cf3"
                value={phpSessionId}
                onChange={e => setPhpSessionId(e.target.value)}
                disabled={loading}
              />
            </div>
            <div className="gf-scan-auth-field">
              <label htmlFor="security">Security Level</label>
              <select
                id="security"
                className="gf-scan-auth-select"
                value={securityLevel}
                onChange={e => setSecurityLevel(e.target.value)}
                disabled={loading}
              >
                <option value="low">Low</option>
                <option value="medium">Medium</option>
                <option value="high">High</option>
                <option value="impossible">Impossible</option>
              </select>
            </div>
          </div>
        </div>
      )}
    </form>
  )
}
