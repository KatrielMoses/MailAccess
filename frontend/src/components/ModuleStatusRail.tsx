import { useInvestigationStore } from '../store/investigationStore'
import type { ModuleStatus } from '../types'

const MODULE_META: Record<string, { label: string; icon: string }> = {
  hibp: { label: 'HIBP', icon: '⚠' },
  email_credibility: { label: 'Cred', icon: 'ℹ' },
  hunter_io: { label: 'Hunter', icon: '◎' },
  emailrep: { label: 'EmailRep', icon: '≡' },
  gravatar: { label: 'Gravatar', icon: '◉' },
  google_dork: { label: 'Dork', icon: '◈' },
  google_search: { label: 'Google', icon: '◈' },
  domain_intel: { label: 'Domain', icon: '⬡' },
  shodan: { label: 'Shodan', icon: '⬡' },
  dns_lookup: { label: 'DNS', icon: '⬢' },
  whois_lookup: { label: 'WHOIS', icon: '⎖' },
  social: { label: 'Social', icon: '⊕' },
  social_links: { label: 'SocLinks', icon: '⊕' },
  duolingo: { label: 'Duolingo', icon: 'D' },
  spotify: { label: 'Spotify', icon: '♪' },
  adobe: { label: 'Adobe', icon: 'A' },
  github: { label: 'GitHub', icon: '' },
  patreon: { label: 'Patreon', icon: 'ⓟ' },
  snapchat: { label: 'Snapchat', icon: '👻' },
  skype_microsoft: { label: 'Skype', icon: 'S' },
  zoom: { label: 'Zoom', icon: 'Z' },
  dropbox: { label: 'Dropbox', icon: 'D' },
  apple: { label: 'Apple', icon: '' },
  linkedin: { label: 'LinkedIn', icon: 'in' },
  discord: { label: 'Discord', icon: '👾' },
  account_discovery: { label: 'AcctDisc', icon: '⌞' },
  whatsmyname: { label: 'WMN', icon: '⊙' },
  user_scanner: { label: 'UsrScan', icon: '⊛' },
  username_pivot: { label: 'UsrPivot', icon: '↻' },
  breachdirectory: { label: 'BrchDir', icon: '⚠' },
  hudson_rock: { label: 'HudsnRck', icon: '☠' },
  permutation_discovery: { label: 'Permute', icon: '⇌' },
  ghunt: { label: 'GHunt', icon: '◉' },
  phone_intel: { label: 'Phone', icon: '☎' },
  messaging_hints: { label: 'MsgHint', icon: '✉' },
}

interface DotProps {
  status: ModuleStatus
}

function StatusDot({ status }: DotProps) {
  const base = 'w-1.5 h-1.5 rounded-full flex-shrink-0'
  switch (status) {
    case 'running':
      return <span className={`${base} bg-cyan-400 animate-pulse-dot`} />
    case 'success':
      return <span className={`${base} bg-emerald-400`} />
    case 'failed':
      return <span className={`${base} bg-red-500`} />
    case 'skipped':
      return <span className={`${base} bg-zinc-700`} />
    default:
      return <span className={`${base} bg-zinc-800`} />
  }
}

function labelColor(status: ModuleStatus): string {
  switch (status) {
    case 'running': return 'text-cyan-400'
    case 'success': return 'text-zinc-300'
    case 'failed': return 'text-red-400'
    case 'skipped': return 'text-zinc-600'
    default: return 'text-zinc-700'
  }
}

export default function ModuleStatusRail() {
  const { modules } = useInvestigationStore()

  return (
    <aside className="w-44 border-r border-zinc-800 bg-zinc-900/30 flex flex-col flex-shrink-0 overflow-y-auto">
      <div className="px-4 py-2.5 border-b border-zinc-800">
        <span className="text-zinc-700 text-xs uppercase tracking-widest">Modules</span>
      </div>

      <div className="py-1">
        {Object.values(modules).map(mod => {
          const meta = MODULE_META[mod.name] ?? { label: mod.name, icon: '◌' }
          return (
            <div
              key={mod.name}
              className={`flex items-center gap-2.5 px-4 py-2 ${
                mod.status === 'running' ? 'bg-cyan-400/5' : ''
              }`}
            >
              <StatusDot status={mod.status} />
              <span className="text-sm flex-shrink-0 opacity-60">{meta.icon}</span>
              <div className="min-w-0 flex-1">
                <div className={`text-xs font-mono font-medium truncate ${labelColor(mod.status)}`}>
                  {meta.label}
                </div>
                {mod.status === 'failed' && mod.error && (
                  <div className="text-red-500/60 text-xs truncate">{mod.error.slice(0, 20)}</div>
                )}
                {mod.status !== 'failed' && (
                  <div className="text-zinc-700 text-xs capitalize">{mod.status}</div>
                )}
              </div>
              {mod.findings.length > 0 && (
                <span className="text-zinc-600 text-xs font-mono flex-shrink-0">
                  {mod.findings.length}
                </span>
              )}
            </div>
          )
        })}
      </div>
    </aside>
  )
}
