import { create } from 'zustand'
import type { EmailCredibility, ModuleState, ModuleStatus, InvStatus, RiskLevel, Timeline } from '../types'

const DEFAULT_MODULE_NAMES = [
  'hibp',
  'email_credibility',
  'hunter_io',
  'emailrep',
  'gravatar',
  'google_search',
  'shodan',
  'dns_lookup',
  'whois_lookup',
  'social_links',
]

function blankModules(): Record<string, ModuleState> {
  return Object.fromEntries(
    DEFAULT_MODULE_NAMES.map(name => [
      name,
      { name, status: 'pending' as ModuleStatus, findings: [] },
    ])
  )
}

interface Store {
  id: string | null
  email: string
  canonicalEmail: string | null
  status: InvStatus
  exposureScore: number | null
  riskLevel: RiskLevel
  credentialRiskScore: number | null
  credentialRiskBand: string
  timeline: Timeline | null
  emailCredibility: EmailCredibility | null
  scoreDrivers: string[]
  recommendedActions: string[]
  modules: Record<string, ModuleState>
  totalFindings: number
  breachCount: number

  initLive: (id: string, email: string) => void
  loadReport: (report: Record<string, unknown>) => void
  handleWsModuleStart: (module: string) => void
  handleWsModuleResult: (module: string, findings: Record<string, unknown>[], status: string) => void
  handleWsModuleError: (module: string, error: string) => void
  handleWsComplete: (
    canonicalEmail: string | null,
    score: number | null,
    riskLevel: string,
    credentialRiskScore: number | null,
    credentialRiskBand: string,
    timeline?: Timeline
  ) => void
  setStatus: (status: InvStatus) => void
  reset: () => void
}

export const useInvestigationStore = create<Store>((set) => ({
  id: null,
  email: '',
  canonicalEmail: null,
  status: 'idle',
  exposureScore: null,
  riskLevel: 'unknown',
  credentialRiskScore: null,
  credentialRiskBand: 'UNKNOWN',
  timeline: null,
  emailCredibility: null,
  scoreDrivers: [],
  recommendedActions: [],
  modules: blankModules(),
  totalFindings: 0,
  breachCount: 0,

  initLive(id, email) {
    set({
      id,
      email,
      canonicalEmail: null,
      status: 'running',
      exposureScore: null,
      riskLevel: 'unknown',
      credentialRiskScore: null,
      credentialRiskBand: 'UNKNOWN',
      timeline: null,
      emailCredibility: null,
      scoreDrivers: [],
      recommendedActions: [],
      modules: blankModules(),
      totalFindings: 0,
      breachCount: 0,
    })
  },

  loadReport(report) {
    const modules = blankModules()
    const runs = (report.module_runs as Record<string, unknown>[] | undefined) ?? []
    const findings = (report.findings as Record<string, unknown>[] | undefined) ?? []

    for (const run of runs) {
      const name = run.module_name as string
      const rawStatus = run.status as string
      const status: ModuleStatus =
        rawStatus === 'success' ? 'success'
        : rawStatus === 'failed' ? 'failed'
        : rawStatus === 'partial' ? 'success'
        : 'skipped'
      modules[name] = {
        name,
        status,
        findings: findings
          .filter(f => f.module_name === name)
          .map(f => f.data as Record<string, unknown>),
        runMetadata: (run.run_metadata as Record<string, unknown> | undefined) ?? undefined,
        error: run.error as string | undefined,
      }
    }

    const rawStatus = report.status as string
    const invStatus: InvStatus =
      rawStatus === 'complete' ? 'complete'
      : rawStatus === 'running' ? 'running'
      : rawStatus === 'failed' ? 'failed'
      : 'pending'

    set({
      id: report.id as string,
      email: report.email as string,
      canonicalEmail: (report.canonical_email as string | null) ?? null,
      status: invStatus,
      exposureScore: (report.exposure_score as number | null) ?? null,
      riskLevel: ((report.risk_level as string) || 'unknown') as RiskLevel,
      credentialRiskScore: (report.credential_risk_score as number | null) ?? null,
      credentialRiskBand: (report.credential_risk_band as string) || 'UNKNOWN',
      timeline: (report.timeline as Timeline | undefined) ?? null,
      emailCredibility: (report.email_credibility as EmailCredibility | undefined) ?? null,
      scoreDrivers: ((report.score_drivers as string[] | undefined) ?? []).map(String),
      recommendedActions: ((report.recommended_actions as string[] | undefined) ?? []).map(String),
      modules,
      totalFindings: findings.length,
      breachCount: findings.filter(f => f.module_name === 'hibp').length,
    })
  },

  handleWsModuleStart(module) {
    set(s => ({
      modules: {
        ...s.modules,
        [module]: {
          ...(s.modules[module] ?? { name: module, findings: [] }),
          status: 'running' as ModuleStatus,
        },
      },
    }))
  },

  handleWsModuleResult(module, findings, statusStr) {
    set(s => {
      const prev = s.modules[module] ?? { name: module, findings: [] }
      const newFindings = [...prev.findings, ...findings]
      const status: ModuleStatus = statusStr === 'success' ? 'success' : 'failed'
      let canonicalEmail = s.canonicalEmail
      let emailCredibility = s.emailCredibility
      if (module === 'email_credibility' && findings.length > 0) {
        const first = findings[0] as Record<string, unknown>
        const meta = (first.metadata as EmailCredibility | undefined) ?? undefined
        if (meta) {
          canonicalEmail = meta.canonical_email ?? canonicalEmail
          emailCredibility = meta
        }
      }
      return {
        modules: { ...s.modules, [module]: { ...prev, status, findings: newFindings } },
        totalFindings: s.totalFindings + findings.length,
        breachCount:
          module === 'hibp'
            ? s.breachCount + findings.length
            : s.breachCount,
        canonicalEmail,
        emailCredibility,
      }
    })
  },

  handleWsModuleError(module, error) {
    set(s => ({
      modules: {
        ...s.modules,
        [module]: {
          ...(s.modules[module] ?? { name: module, findings: [] }),
          status: 'failed' as ModuleStatus,
          error,
        },
      },
    }))
  },

  handleWsComplete(canonicalEmail, score, riskLevel, credentialRiskScore, credentialRiskBand, timeline) {
    set({
      status: 'complete',
      canonicalEmail: canonicalEmail ?? null,
      exposureScore: score,
      riskLevel: riskLevel as RiskLevel,
      credentialRiskScore,
      credentialRiskBand,
      timeline: timeline ?? null,
    })
  },

  setStatus(status) {
    set({ status })
  },

  reset() {
    set({
      id: null,
      email: '',
      canonicalEmail: null,
      status: 'idle',
      exposureScore: null,
      riskLevel: 'unknown',
      credentialRiskScore: null,
      credentialRiskBand: 'UNKNOWN',
      timeline: null,
      emailCredibility: null,
      scoreDrivers: [],
      recommendedActions: [],
      modules: blankModules(),
      totalFindings: 0,
      breachCount: 0,
    })
  },
}))
