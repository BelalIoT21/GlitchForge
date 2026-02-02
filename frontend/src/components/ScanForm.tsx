import { useState, type FormEvent } from 'react'

interface ScanFormProps {
  onSubmit: (url: string, scanTypes: string[]) => void
  loading: boolean
}

const ALL_TYPES = ['sql', 'xss', 'csrf']

export default function ScanForm({ onSubmit, loading }: ScanFormProps) {
  const [url, setUrl] = useState('')
  const [scanTypes, setScanTypes] = useState<string[]>(ALL_TYPES)

  const toggleType = (type: string) => {
    setScanTypes(prev =>
      prev.includes(type)
        ? prev.filter(t => t !== type)
        : [...prev, type]
    )
  }

  const handleSubmit = (e: FormEvent) => {
    e.preventDefault()
    if (!url.trim() || scanTypes.length === 0) return
    onSubmit(url.trim(), scanTypes)
  }

  return (
    <form className="scan-form" onSubmit={handleSubmit}>
      <div className="form-row">
        <input
          type="text"
          className="url-input"
          placeholder="Enter target URL (e.g. http://testphp.vulnweb.com)"
          value={url}
          onChange={e => setUrl(e.target.value)}
          disabled={loading}
          autoFocus
        />
        <button type="submit" className="scan-btn" disabled={loading || !url.trim() || scanTypes.length === 0}>
          {loading ? 'Scanning...' : 'Scan'}
        </button>
      </div>

      <div className="form-options">
        <div className="scan-types">
          <span className="options-label">Scan Types:</span>
          {ALL_TYPES.map(type => (
            <button
              key={type}
              type="button"
              className={`type-toggle ${scanTypes.includes(type) ? 'active' : ''}`}
              onClick={() => toggleType(type)}
              disabled={loading}
            >
              {type.toUpperCase()}
            </button>
          ))}
        </div>
      </div>
    </form>
  )
}
