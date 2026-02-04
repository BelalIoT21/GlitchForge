import axios from 'axios'
import type { HealthStatus, EngineStatus, ScanRequest, ScanResult, QuickScanResult, ScanProgress } from './types'

const API_BASE = '/api'

const api = axios.create({
  baseURL: '/',
  timeout: 0, // No timeout - let server decide
  headers: { 'Content-Type': 'application/json' },
})

export async function getHealth(): Promise<HealthStatus> {
  const { data } = await api.get<HealthStatus>('/health', {
    timeout: 5000, // Short timeout for health checks
    headers: {
      'Cache-Control': 'no-cache',
      'Pragma': 'no-cache',
    },
  })
  return data
}

export async function getStatus(): Promise<EngineStatus> {
  const { data } = await api.get<EngineStatus>(`${API_BASE}/status`)
  return data
}

export async function runScan(request: ScanRequest): Promise<ScanResult> {
  const { data } = await api.post<ScanResult>(`${API_BASE}/scan`, request)
  return data
}

export async function runQuickScan(request: ScanRequest): Promise<QuickScanResult> {
  const { data } = await api.post<QuickScanResult>(`${API_BASE}/quick-scan`, request)
  return data
}

export interface StreamCallbacks {
  onProgress: (progress: ScanProgress) => void
  onResult: (result: ScanResult) => void
  onError: (error: string) => void
}

export function runScanStream(
  request: ScanRequest,
  callbacks: StreamCallbacks
): () => void {
  const controller = new AbortController()

  fetch(`${API_BASE}/scan-stream`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(request),
    signal: controller.signal
  })
    .then(async (response) => {
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`)
      }

      const reader = response.body?.getReader()
      if (!reader) {
        throw new Error('No response body')
      }

      const decoder = new TextDecoder()
      let buffer = ''

      while (true) {
        const { done, value } = await reader.read()
        if (done) break

        buffer += decoder.decode(value, { stream: true })

        // Process complete SSE messages
        const lines = buffer.split('\n')
        buffer = lines.pop() || ''

        for (const line of lines) {
          if (line.startsWith('data: ')) {
            try {
              const event = JSON.parse(line.slice(6))
              if (event.type === 'progress') {
                callbacks.onProgress(event.data)
              } else if (event.type === 'result') {
                callbacks.onResult(event.data)
              } else if (event.type === 'error') {
                callbacks.onError(event.data.error || 'Unknown error')
              }
            } catch {
              // Ignore parse errors
            }
          }
        }
      }
    })
    .catch((err) => {
      if (err.name !== 'AbortError') {
        callbacks.onError(err.message || 'Connection failed')
      }
    })

  // Return abort function
  return () => controller.abort()
}
