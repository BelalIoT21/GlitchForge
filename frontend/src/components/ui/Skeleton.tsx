interface SkeletonProps {
  width?: string | number
  height?: string | number
  className?: string
  variant?: 'text' | 'circular' | 'rectangular'
}

export default function Skeleton({
  width = '100%',
  height = '1rem',
  className = '',
  variant = 'rectangular'
}: SkeletonProps) {
  const baseClass = 'gf-skeleton'
  const variantClass = variant === 'circular' ? 'gf-skeleton-circular' :
                       variant === 'text' ? 'gf-skeleton-text' : ''

  return (
    <div
      className={`${baseClass} ${variantClass} ${className}`.trim()}
      style={{
        width: typeof width === 'number' ? `${width}px` : width,
        height: typeof height === 'number' ? `${height}px` : height
      }}
    />
  )
}

export function SkeletonCard() {
  return (
    <div className="gf-skeleton-card">
      <div className="gf-skeleton-card-header">
        <Skeleton width={120} height={24} />
        <Skeleton width={60} height={24} />
      </div>
      <div className="gf-skeleton-card-body">
        <Skeleton height={16} />
        <Skeleton height={16} width="80%" />
        <Skeleton height={16} width="60%" />
      </div>
    </div>
  )
}

export function SkeletonList({ count = 3 }: { count?: number }) {
  return (
    <div className="gf-skeleton-list">
      {Array.from({ length: count }).map((_, i) => (
        <SkeletonCard key={i} />
      ))}
    </div>
  )
}
