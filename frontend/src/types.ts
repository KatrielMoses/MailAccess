export type ModuleStatus = 'pending' | 'running' | 'success' | 'failed' | 'skipped'
export type InvStatus = 'idle' | 'loading' | 'pending' | 'running' | 'complete' | 'failed'
export type RiskLevel = 'low' | 'medium' | 'high' | 'critical' | 'unknown'

export interface Timeline {
  first_seen_date?: string | null
  first_seen_source?: string | null
  most_recent_date?: string | null
  most_recent_event?: string | null
  most_recent_is_active_risk?: boolean
  established_identity?: boolean
  identity_age_years?: number | null
  active_risk_count?: number
  timeline_span_years?: number | null
  events?: Record<string, unknown>[]
}

export interface EmailCredibility {
  canonical_email?: string
  is_alias?: boolean
  aliases_detected?: string[]
  provider_family?: string
  is_disposable?: boolean
  disposable_provider?: string | null
  reputation_verdict?: string
  reputation_flags?: string[]
  is_malicious?: boolean
  first_seen?: string | null
  sources_checked?: string[]
  emailrep_reputation?: string | null
  emailrep_suspicious?: boolean
  emailrep_malicious_activity?: boolean
  emailrep_malicious_activity_recent?: boolean
  emailrep_credentials_leaked?: boolean
  emailrep_spam?: boolean
  emailrep_blacklisted?: boolean
  emailrep_last_seen?: string | null
  emailrep_free_provider?: boolean
  emailrep_disposable?: boolean
  emailrep_references?: number | null
  spamhaus_list?: string | null
  spamhaus_listed?: boolean
  domain_age_days?: number | null
  domain_age_note?: string | null
}

export interface ModuleState {
  name: string
  status: ModuleStatus
  findings: Record<string, unknown>[]
  runMetadata?: Record<string, unknown>
  error?: string
}

export interface InvestigationSummary {
  id: string
  email: string
  canonical_email?: string | null
  status: string
  exposure_score: number | null
  credential_risk_score: number | null
  created_at: string
  completed_at: string | null
}

export interface PaginatedInvestigations {
  total: number
  page: number
  page_size: number
  pages: number
  items: InvestigationSummary[]
}

// WebSocket event frames from /ws/investigate/:id
export type WsEvent =
  | { type: 'module_start'; module: string; timestamp: string }
  | { type: 'module_result'; module: string; findings: Record<string, unknown>[]; status: string }
  | { type: 'module_error'; module: string; error: string; status: string }
  | {
      type: 'investigation_complete'
      canonical_email?: string | null
      exposure_score: number | null
      risk_level: string
      credential_risk_score: number | null
      credential_risk_band: string
      timeline?: Timeline
    }
  | { type: 'error'; error: string }
