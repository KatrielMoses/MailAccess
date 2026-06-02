import { useInvestigationStore } from '../store/investigationStore'
import ExposureGauge from './ExposureGauge'
import RiskBadge from './RiskBadge'

function Metric({ label, value, highlight }: { label: string; value: number; highlight?: boolean }) {
  return (
    <div className="min-w-[64px]">
      <div className="text-zinc-600 text-xs uppercase tracking-widest mb-1 whitespace-nowrap">{label}</div>
      <div className={`text-xl font-bold font-mono ${highlight && value > 0 ? 'text-red-400' : 'text-zinc-100'}`}>
        {value}
      </div>
    </div>
  )
}

function credentialBandClass(band: string): string {
  switch (band) {
    case 'CRITICAL':
      return 'text-red-300 bg-red-500/10 border-red-500/30'
    case 'HIGH':
      return 'text-orange-300 bg-orange-500/10 border-orange-500/30'
    case 'MODERATE':
      return 'text-yellow-300 bg-yellow-500/10 border-yellow-500/30'
    default:
      return 'text-emerald-300 bg-emerald-500/10 border-emerald-500/30'
  }
}

export default function SummaryBar() {
  const {
    exposureScore,
    riskLevel,
    credentialRiskScore,
    credentialRiskBand,
    timeline,
    canonicalEmail,
    emailCredibility,
    totalFindings,
    breachCount,
    modules,
  } = useInvestigationStore()

  const accountsFound = Object.values(modules).filter(m => m.findings.length > 0).length
  const platformCount = Object.values(modules).reduce((best, mod) => {
    const raw = mod.runMetadata?.unique_platforms
    return typeof raw === 'number' ? Math.max(best, raw) : best
  }, 0)
  const firstSeenYear = timeline?.first_seen_date ? timeline.first_seen_date.slice(0, 4) : '-'
  const activeRisk = (timeline?.active_risk_count ?? 0) > 0
  const providerLabel =
    canonicalEmail?.includes('@') ? canonicalEmail.split('@').pop() ?? '' : ''
  const isDisposable = Boolean(emailCredibility?.is_disposable)
  const isMalicious = Boolean(emailCredibility?.is_malicious)

  return (
    <div className="border-b border-zinc-800 bg-zinc-900/50 px-5 py-4 flex items-center gap-6 flex-shrink-0 overflow-x-auto">
      {isDisposable && (
        <div className="flex-shrink-0 rounded-full border border-yellow-500/30 bg-yellow-500/10 px-3 py-1 text-xs font-bold text-yellow-300">
          ⚠ DISPOSABLE
        </div>
      )}
      <div className="flex items-center gap-3 flex-shrink-0">
        <ExposureGauge score={exposureScore ?? 0} />
        <div>
          <div className="text-zinc-600 text-xs uppercase tracking-widest mb-0.5">Exposure</div>
          <div className="text-2xl font-bold text-zinc-100 leading-none">
            {exposureScore !== null ? exposureScore : '-'}
          </div>
        </div>
      </div>

      <div className="h-10 w-px bg-zinc-800 flex-shrink-0" />

      <div className="flex-shrink-0">
        <div className="text-zinc-600 text-xs uppercase tracking-widest mb-1.5">Risk</div>
        <RiskBadge level={riskLevel} size="lg" />
      </div>

      <div className="h-10 w-px bg-zinc-800 flex-shrink-0" />

      <div className="flex-shrink-0">
        <div className="text-zinc-600 text-xs uppercase tracking-widest mb-1.5">Cred Risk</div>
        <div className={`inline-flex items-center gap-2 rounded-full border px-3 py-1 text-sm font-bold ${credentialBandClass(credentialRiskBand)}`}>
          <span>{credentialRiskScore !== null ? credentialRiskScore : '-'}</span>
          <span>{credentialRiskBand}</span>
        </div>
      </div>

      {providerLabel && !isDisposable && (
        <div className="flex-shrink-0 text-zinc-500 text-sm font-mono">
          {providerLabel}
        </div>
      )}

      {emailCredibility?.reputation_verdict === 'malicious' && !isDisposable && (
        <div className="flex-shrink-0 rounded-full border border-red-500/30 bg-red-500/10 px-3 py-1 text-xs font-bold text-red-300">
          ⚠ MALICIOUS
        </div>
      )}

      <div className="h-10 w-px bg-zinc-800 flex-shrink-0" />

      <div className="flex gap-5 flex-shrink-0">
        <Metric label="Accounts" value={accountsFound} />
        <Metric label="Breaches" value={breachCount} highlight />
        {platformCount > 0 && <Metric label="Platforms" value={platformCount} />}
        <Metric label="Data pts" value={totalFindings} />
      </div>

      <div className="h-10 w-px bg-zinc-800 flex-shrink-0" />

      <div className="flex gap-5 flex-shrink-0">
        <div className="min-w-[76px]">
          <div className="text-zinc-600 text-xs uppercase tracking-widest mb-1 whitespace-nowrap">First seen</div>
          <div className="text-xl font-bold font-mono text-zinc-100">{firstSeenYear}</div>
        </div>
        <div className="min-w-[82px]">
          <div className="text-zinc-600 text-xs uppercase tracking-widest mb-1 whitespace-nowrap">Active risk</div>
          <div className={`text-xl font-bold font-mono ${activeRisk ? 'text-red-400' : 'text-emerald-400'}`}>
            {activeRisk ? 'YES' : 'NO'}
          </div>
        </div>
      </div>
    </div>
  )
}
