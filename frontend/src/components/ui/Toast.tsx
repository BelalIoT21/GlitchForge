import { useEffect, useState } from 'react'
import { AnimatePresence, motion } from 'framer-motion'

export type ToastType = 'error' | 'warning' | 'success' | 'info'

export interface ToastItem {
  id: string
  message: string
  type: ToastType
  duration?: number
}

interface ToastProps {
  toasts: ToastItem[]
  onDismiss: (id: string) => void
}

function Toast({ toast, onDismiss }: { toast: ToastItem; onDismiss: (id: string) => void }) {
  const [progress, setProgress] = useState(100)
  const duration = toast.duration ?? 5000

  useEffect(() => {
    const start = Date.now()
    const interval = setInterval(() => {
      const elapsed = Date.now() - start
      const remaining = Math.max(0, 100 - (elapsed / duration) * 100)
      setProgress(remaining)
      if (remaining === 0) {
        clearInterval(interval)
        onDismiss(toast.id)
      }
    }, 16)
    return () => clearInterval(interval)
  }, [toast.id, duration, onDismiss])

  const icons: Record<ToastType, string> = {
    error: '✕',
    warning: '⚠',
    success: '✓',
    info: 'i',
  }

  return (
    <motion.div
      className={`gf-toast gf-toast-${toast.type}`}
      initial={{ opacity: 0, x: 60, scale: 0.92 }}
      animate={{ opacity: 1, x: 0, scale: 1 }}
      exit={{ opacity: 0, x: 60, scale: 0.92 }}
      transition={{ duration: 0.25, ease: [0.22, 1, 0.36, 1] }}
    >
      <div className="gf-toast-icon">{icons[toast.type]}</div>
      <div className="gf-toast-body">
        <div className="gf-toast-type">{toast.type.toUpperCase()}</div>
        <div className="gf-toast-msg">{toast.message}</div>
      </div>
      <button className="gf-toast-close" onClick={() => onDismiss(toast.id)} aria-label="Dismiss">
        ✕
      </button>
      <div
        className="gf-toast-progress"
        style={{ width: `${progress}%` }}
      />
    </motion.div>
  )
}

export default function Toaster({ toasts, onDismiss }: ToastProps) {
  return (
    <div className="gf-toaster">
      <AnimatePresence>
        {toasts.map((t) => (
          <Toast key={t.id} toast={t} onDismiss={onDismiss} />
        ))}
      </AnimatePresence>
    </div>
  )
}
