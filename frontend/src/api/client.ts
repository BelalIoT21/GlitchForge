import axios from 'axios'
import type { HealthStatus, EngineStatus, ScanRequest, ScanResult, QuickScanResult } from './types'

const API_BASE = '/api'

const api = axios.create({
  baseURL: '/',
  timeout: 300000, // 5 minutes - full scans can take 2-5 minutes depending on target
  headers: { 'Content-Type': 'application/json' },
})

export async function getHealth(): Promise<HealthStatus> {
  const { data } = await api.get<HealthStatus>('/health')
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
