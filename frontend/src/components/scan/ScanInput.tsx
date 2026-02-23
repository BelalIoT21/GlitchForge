import { useState, useCallback, useRef, useEffect, type FormEvent } from 'react'

interface ScanInputProps {
  onSubmit: (url: string, scanTypes: string[], cookies?: Record<string, string>, crawl?: boolean) => void
  loading: boolean
}

const ALL_TYPES = ['sql', 'xss', 'csrf']
const SECURITY_LEVELS = ['low', 'medium', 'high', 'impossible']

export default function ScanInput({ onSubmit, loading }: ScanInputProps) {
  const [url, setUrl] = useState('')
  const [scanTypes, setScanTypes] = useState<string[]>(ALL_TYPES)
  const [showAdvanced, setShowAdvanced] = useState(false)
  const [phpSessionId, setPhpSessionId] = useState('')
  const [securityLevel, setSecurityLevel] = useState('low')
  const [crawl, setCrawl] = useState(false)
  
  // Custom Dropdown State
  const [isOpen, setIsOpen] = useState(false)
  const dropdownRef = useRef<HTMLDivElement>(null)

  // Close dropdown when clicking outside
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setIsOpen(false)
      }
    }
    document.addEventListener('mousedown', handleClickOutside)
    return () => document.removeEventListener('mousedown', handleClickOutside)
  }, [])

  const toggleType = (type: string) => {
    setScanTypes(prev =>
      prev.includes(type) ? prev.filter(t => t !== type) : [...prev, type]
    )
  }

  const handleSubmit = (e: FormEvent) => {
    e.preventDefault()
    if (!url.trim() || scanTypes.length === 0) return
    const cookies = phpSessionId.trim()
      ? { PHPSESSID: phpSessionId.trim(), security: securityLevel }
      : undefined
    onSubmit(url.trim(), scanTypes, cookies, crawl)
  }
  
  const handleMouseMove = useCallback((e: React.MouseEvent<HTMLFormElement>) => {
    const rect = e.currentTarget.getBoundingClientRect()
    const x = ((e.clientX - rect.left) / rect.width) * 100
    const y = ((e.clientY - rect.top) / rect.height) * 100
    e.currentTarget.style.setProperty('--mx', `${x}%`)
    e.currentTarget.style.setProperty('--my', `${y}%`)
  }, [])

  return (
    <form className="gf-scan" onSubmit={handleSubmit} onMouseMove={handleMouseMove}>
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
          {!loading && (
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
              <line x1="5" y1="12" x2="19" y2="12"/>
              <polyline points="12 5 19 12 12 19"/>
            </svg>
          )}
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

      {showAdvanced && (
        <div className="gf-scan-advanced">
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

            <div className="gf-scan-auth-field" ref={dropdownRef}>
              <label>Security Level</label>
              <div className="gf-custom-select-container">
                {/* Trigger stays as a div styled like the original select */}
                <div 
                  className={`gf-scan-auth-select ${isOpen ? 'active' : ''}`} 
                  onClick={() => !loading && setIsOpen(!isOpen)}
                >
                  {securityLevel}
                </div>
                
                {/* Custom List of Items */}
                {isOpen && (
                  <div className="gf-custom-dropdown-list">
                    {SECURITY_LEVELS.map((level) => (
                      <div 
                        key={level}
                        className={`gf-custom-dropdown-item ${securityLevel === level ? 'selected' : ''}`}
                        onClick={() => {
                          setSecurityLevel(level);
                          setIsOpen(false);
                        }}
                      >
                        {level}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      )}
    </form>
  )
}