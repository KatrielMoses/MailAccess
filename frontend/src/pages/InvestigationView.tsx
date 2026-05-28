import { useEffect } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { api } from '../api/client'
import { useInvestigationStore } from '../store/investigationStore'
import { useInvestigationWS } from '../hooks/useInvestigationWS'
import SummaryBar from '../components/SummaryBar'
import ModuleStatusRail from '../components/ModuleStatusRail'
import FindingCard from '../components/FindingCard'
import SkeletonCard from '../components/SkeletonCard'
import ExportBar from '../components/ExportBar'

export default function InvestigationView() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const store = useInvestigationStore()

  // Connect WS for live updates (no-ops gracefully if already complete or queue gone)
  useInvestigationWS(id ?? null)

  // Load report data if this is a historical view or page refresh
  useEffect(() => {
    if (!id) return
    // If store already has live data for this exact investigation, skip the fetch
    if (store.id === id && store.status !== 'idle') return

    api
      .getReport(id)
      .then(report => store.loadReport(report))
      .catch(() => store.setStatus('failed'))
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [id])

  const allFindings = Object.values(store.modules).flatMap(mod =>
    mod.findings.map(data => ({ module: mod.name, data }))
  )

  const isLive = store.status === 'running' || store.status === 'pending'
  const pendingModules = Object.values(store.modules).filter(m => m.status === 'pending').length
  const isLoading = store.status === 'loading' || store.status === 'idle'

  const statusStyle =
    store.status === 'complete'
      ? 'text-emerald-400 border-emerald-400/30 bg-emerald-400/5'
      : store.status === 'running'
        ? 'text-cyan-400 border-cyan-400/30 bg-cyan-400/5 animate-pulse'
        : store.status === 'failed'
          ? 'text-red-400 border-red-400/30 bg-red-400/5'
          : 'text-zinc-500 border-zinc-700 bg-zinc-800/30'

  return (
    <div className="min-h-screen bg-zinc-950 flex flex-col font-mono">
      {/* Header */}
      <header className="border-b border-zinc-800 bg-zinc-900/60 px-5 py-3 flex items-center gap-3 flex-shrink-0">
        <button
          onClick={() => navigate('/')}
          className="text-zinc-600 hover:text-cyan-400 transition-colors text-sm mr-1"
          title="Back to home"
        >
          ← back
        </button>
        <div className="h-4 w-px bg-zinc-800" />
        <svg width="14" height="14" viewBox="0 0 28 28" fill="none" className="flex-shrink-0 opacity-60">
          <polygon points="14,2 26,8 26,20 14,26 2,20 2,8" stroke="#22d3ee" strokeWidth="1.5" fill="none" />
        </svg>
        <div className="min-w-0 flex flex-col">
          <span className="text-zinc-300 text-sm truncate">{store.email || id}</span>
          {store.canonicalEmail && store.canonicalEmail !== store.email && (
            <span className="text-zinc-500 text-xs truncate">
              canonical: {store.canonicalEmail}
            </span>
          )}
        </div>
        <div className="flex-1" />
        <span className={`text-xs uppercase tracking-widest px-2 py-0.5 border rounded-sm ${statusStyle}`}>
          {store.status}
        </span>
        {store.status === 'complete' && id && (
          <button
            type="button"
            onClick={() => navigate(`/investigation/${id}/graph`)}
            className="ml-2 px-3 py-0.5 text-xs font-mono border border-zinc-700 text-zinc-300 rounded-sm hover:border-cyan-400 hover:text-cyan-400 transition-colors"
          >
            Graph
          </button>
        )}
      </header>

      {/* Summary bar */}
      <SummaryBar />

      {/* Body: rail + findings */}
      <div className="flex flex-1 min-h-0 overflow-hidden">
        <ModuleStatusRail />

        {/* Findings stream */}
        <main className="flex-1 overflow-y-auto p-5 space-y-3">
          {isLoading && (
            <>
              <SkeletonCard />
              <SkeletonCard />
              <SkeletonCard />
            </>
          )}

          {!isLoading && allFindings.map((f, i) => (
            <div key={`${f.module}-${i}`} className="animate-fade-in-up">
              <FindingCard module={f.module} data={f.data} />
            </div>
          ))}

          {isLive && !isLoading && pendingModules > 0 && (
            <>
              <SkeletonCard />
              {pendingModules > 1 && <SkeletonCard />}
            </>
          )}

          {!isLoading && !isLive && allFindings.length === 0 && (
            <div className="flex flex-col items-center justify-center py-20 text-zinc-700">
              <span className="text-3xl mb-3">○</span>
              <p className="text-sm">No findings collected for this investigation.</p>
            </div>
          )}
        </main>
      </div>

      <ExportBar investigationId={id ?? ''} />
    </div>
  )
}
