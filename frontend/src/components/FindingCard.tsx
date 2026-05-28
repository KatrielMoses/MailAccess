const MODULE_LABELS: Record<string, string> = {
  haveibeenpwned: 'Have I Been Pwned',
  hibp: 'Have I Been Pwned',
  hunter_io: 'Hunter.io',
  email_credibility: 'Email Credibility',
  emailrep: 'EmailRep',
  gravatar: 'Gravatar',
  google_search: 'Google Search',
  shodan: 'Shodan',
  dns_lookup: 'DNS Lookup',
  whois_lookup: 'WHOIS Lookup',
  social_links: 'Social Links',
}

const MODULE_ACCENT: Record<string, string> = {
  haveibeenpwned: 'text-red-400',
  hibp: 'text-red-400',
  hunter_io: 'text-cyan-400',
  email_credibility: 'text-amber-300',
  emailrep: 'text-blue-400',
  gravatar: 'text-violet-400',
  google_search: 'text-yellow-400',
  shodan: 'text-orange-400',
  dns_lookup: 'text-emerald-400',
  whois_lookup: 'text-teal-400',
  social_links: 'text-pink-400',
}

function isUrl(v: unknown): v is string {
  return typeof v === 'string' && (v.startsWith('http://') || v.startsWith('https://'))
}

function isImageUrl(v: unknown): v is string {
  if (!isUrl(v)) return false
  return /\.(jpg|jpeg|png|gif|webp|svg)(\?|$)/i.test(v)
}

function formatValue(value: unknown): string {
  if (value === null || value === undefined) return '—'
  if (Array.isArray(value)) return value.map(v => String(v)).join(', ')
  if (typeof value === 'object') return JSON.stringify(value, null, 0)
  return String(value)
}

interface Props {
  module: string
  data: Record<string, unknown>
}

export default function FindingCard({ module, data }: Props) {
  const label = MODULE_LABELS[module] ?? module
  const accent = MODULE_ACCENT[module] ?? 'text-cyan-400'

  const entries = Object.entries(data).filter(([, v]) => v !== null && v !== undefined && v !== '')

  return (
    <div className="bg-zinc-900 border border-zinc-800 hover:border-zinc-700 transition-colors rounded-sm overflow-hidden">
      <div className="flex items-center gap-2 px-4 py-2.5 border-b border-zinc-800/80">
        <span className={`text-xs font-bold uppercase tracking-widest font-mono ${accent}`}>
          {label}
        </span>
        <div className="flex-1 h-px bg-zinc-800" />
        <span className="text-zinc-700 text-xs font-mono">{entries.length} fields</span>
      </div>

      <div className="px-4 py-3">
        {entries.length === 0 ? (
          <p className="text-zinc-700 text-xs">No data fields.</p>
        ) : (
          <div className="space-y-1.5">
            {entries.map(([key, value]) => (
              <div key={key} className="flex gap-3 items-start">
                <span className="text-zinc-600 text-xs font-mono w-28 flex-shrink-0 pt-px truncate">
                  {key}
                </span>
                <div className="flex-1 min-w-0">
                  {isImageUrl(value) ? (
                    <div className="flex items-center gap-2">
                      <img
                        src={value}
                        alt={key}
                        className="w-8 h-8 rounded-full border border-zinc-700 object-cover flex-shrink-0"
                        onError={e => { (e.target as HTMLImageElement).style.display = 'none' }}
                      />
                      <a
                        href={value}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-cyan-400 text-xs font-mono hover:text-cyan-300 truncate transition-colors"
                      >
                        {value}
                      </a>
                    </div>
                  ) : isUrl(value) ? (
                    <a
                      href={value}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-cyan-400 text-xs font-mono hover:text-cyan-300 transition-colors break-all"
                    >
                      {value}
                    </a>
                  ) : (
                    <span className="text-zinc-300 text-xs font-mono break-words">
                      {formatValue(value)}
                    </span>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
