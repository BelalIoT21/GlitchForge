const LEVEL_COLORS: Record<string, { color: string; bg: string }> = {
  Critical: { color: '#ef4444', bg: 'rgba(239,68,68,0.12)' },
  High:     { color: '#f97316', bg: 'rgba(249,115,22,0.12)' },
  Medium:   { color: '#eab308', bg: 'rgba(234,179,8,0.12)' },
  Low:      { color: '#22c55e', bg: 'rgba(34,197,94,0.12)' },
  Info:     { color: '#6366f1', bg: 'rgba(99,102,241,0.12)' },
}

interface BadgeProps {
  level: string
  size?: 'sm' | 'md'
}

export default function Badge({ level, size = 'sm' }: BadgeProps) {
  const style = LEVEL_COLORS[level] || { color: '#888', bg: 'rgba(136,136,136,0.1)' }

  return (
    <span
      style={{
        backgroundColor: style.bg,
        color: style.color,
        fontSize: size === 'sm' ? '0.7rem' : '0.78rem',
        fontWeight: 700,
        textTransform: 'uppercase',
        letterSpacing: '0.08em',
        padding: size === 'sm' ? '3px 10px' : '4px 14px',
        borderRadius: '20px',
        display: 'inline-block',
        lineHeight: 1.4,
      }}
    >
      {level}
    </span>
  )
}

export function getLevelColor(level: string): string {
  return LEVEL_COLORS[level]?.color || '#888'
}
