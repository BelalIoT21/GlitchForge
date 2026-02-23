import { useEffect, useRef, useState } from 'react'

export function useCountUp(target: number, duration = 1200, decimals = 0) {
  const [value, setValue] = useState(0)
  const startRef = useRef<number | null>(null)
  const rafRef = useRef<number | null>(null)

  useEffect(() => {
    startRef.current = null
    const step = (ts: number) => {
      if (!startRef.current) startRef.current = ts
      const progress = Math.min((ts - startRef.current) / duration, 1)
      const eased = 1 - Math.pow(1 - progress, 3)
      setValue(parseFloat((eased * target).toFixed(decimals)))
      if (progress < 1) rafRef.current = requestAnimationFrame(step)
    }
    rafRef.current = requestAnimationFrame(step)
    return () => { if (rafRef.current) cancelAnimationFrame(rafRef.current) }
  }, [target, duration, decimals])

  return value
}
