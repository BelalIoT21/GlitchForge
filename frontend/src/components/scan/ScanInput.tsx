import { useState, type FormEvent } from 'react'

interface ScanInputProps {
  onSubmit: (url: string, scanTypes: string[]) => void
  loading: boolean
}

const ALL_TYPES = ['sql', 'xss', 'csrf']

export default function ScanInput({ onSubmit, loading }: ScanInputProps) {
  const [url, setUrl] = useState('')
  const [scanTypes, setScanTypes] = useState<string[]>(ALL_TYPES)

  const toggleType = (type: string) => {
    setScanTypes(prev =>
      prev.includes(type) ? prev.filter(t => t !== type) : [...prev, type]
    )
  }

  const handleSubmit = (e: FormEvent) => {
    e.preventDefault()
    if (!url.trim() || scanTypes.length === 0) return
    onSubmit(url.trim(), scanTypes)
  }

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
          {loading ? 'Scanning...' : 'Scan Target'}
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
      </div>
    </form>
  )
}