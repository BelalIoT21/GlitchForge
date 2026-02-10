export interface HealthStatus {
  status: string
  message: string
  models_loaded: boolean
}

export interface EngineStatus {
  success: boolean
  engine: string
  models_loaded: {
    random_forest: boolean
    neural_network: boolean
  }
  available_scans: string[]
}

export interface ScanRequest {
  url: string
  scan_types: string[]
  cookies?: Record<string, string>
  crawl?: boolean
  max_urls?: number
}

export interface VulnWhere {
  url: string
  parameter: string
  method?: string
}

export interface VulnWhat {
  vulnerability_type: string
  payload_used: string
  description: string
  evidence: string
  cwe_id: string
  confidence: number
  severity?: string
}

export interface VulnFix {
  remediation: string
  priority?: string
}

export interface XAIFeature {
  feature: string
  contribution_pct: number
  direction: 'increases' | 'decreases'
  description: string
}

export interface XAIExplanation {
  method: string
  summary: string
  features: XAIFeature[]
  model_fit?: number
}

export interface HttpExchange {
  method: string
  url: string
  headers: Record<string, string>
  body: string | null
  status_code: number
  response_headers: Record<string, string>
  response_body: string
  response_time_ms: number
}

export interface PentestEvidence {
  technique: string
  http_exchanges: HttpExchange[]
  poc_command: string
  extracted_data: string[]
  impact_description: string
  reproduction_steps: string[]
}

export interface PentestResult {
  vulnerability_url: string
  vulnerability_parameter: string
  vulnerability_type: string
  verification_status: 'confirmed' | 'likely' | 'unverified' | 'false_positive' | 'not_tested'
  confidence: number
  evidence: PentestEvidence | null
  attempts: number
  duration_seconds: number
  timestamp: string
  error_message: string
}

export interface RiskScore {
  vulnerability_id: string
  risk_score: number
  risk_level: string
  remediation_priority: string
  cvss_base: number
  cvss_exploitability: number
  cvss_impact: number
  has_exploit: boolean
  model_agreement: boolean
  confidence: number
  explanation: string
  primary_factors: string[]
  where?: VulnWhere
  what?: VulnWhat
  how_to_fix?: VulnFix
  shap_explanation?: XAIExplanation
  lime_explanation?: XAIExplanation
  pentest?: PentestResult
  verified?: string
}

export interface ScanStatistics {
  total_vulnerabilities: number
  average_risk_score: number
  median_risk_score: number
  max_risk_score: number
  min_risk_score: number
  model_agreement_rate: number
  risk_levels: Record<string, number>
  remediation_priorities: Record<string, number>
}

export interface ScanResult {
  success: boolean
  url: string
  vulnerabilities_found: number
  scan_time: number
  pentest_time?: number
  prediction_time?: number
  prioritization_time?: number
  total_time?: number
  scanned_count?: number
  filtered_count?: number
  risk_scores: RiskScore[]
  statistics?: ScanStatistics
  timestamp?: string
  message?: string
}

export interface QuickScanVuln {
  where: VulnWhere
  what: VulnWhat
  how_to_fix: VulnFix
}

export interface QuickScanResult {
  success: boolean
  url: string
  vulnerabilities_found: number
  vulnerabilities: QuickScanVuln[]
}

export interface ScanProgress {
  scan_id: string
  phase: 'initializing' | 'crawling' | 'scanning' | 'pentesting' | 'analyzing' | 'complete' | 'error'
  url: string
  urls_discovered: number
  urls_to_scan: number
  current_url: string
  current_url_index: number
  total_urls: number
  vulns_found: number
  current_scanner: string
  pentest_current: number
  pentest_total: number
  pentest_confirmed: number
  pentest_technique: string
  analysis_step: string
  elapsed_seconds: number
  error_message: string
}
