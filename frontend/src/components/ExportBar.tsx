import { useInvestigationStore } from '../store/investigationStore'
import { api } from '../api/client'

interface Format {
  id: string
  label: string
  available: boolean
}

const FORMATS: Format[] = [
  { id: 'json',     label: 'JSON',     available: true  },
  { id: 'csv',      label: 'CSV',      available: true  },
  { id: 'markdown', label: 'Markdown', available: true  },
  { id: 'html',     label: 'HTML',     available: true  },
  { id: 'pdf',      label: 'PDF',      available: true  },
  { id: 'stix',     label: 'STIX',     available: true  },
  { id: 'maltego',  label: 'Maltego',  available: true  },
]

interface Props {
  investigationId: string
}

export default function ExportBar({ investigationId }: Props) {
  const { status } = useInvestigationStore()
  const isDone = status === 'complete'

  function handleExport(format: string) {
    if (!investigationId || !isDone) return
    window.open(api.exportUrl(investigationId, format), '_blank')
  }

  return (
    <footer className="border-t border-zinc-800 bg-zinc-900/50 px-5 py-2.5 flex items-center gap-2 flex-shrink-0">
      <span className="text-zinc-700 text-xs uppercase tracking-widest mr-1 font-mono">Export</span>

      {FORMATS.map(fmt => (
        <button
          key={fmt.id}
          onClick={() => fmt.available && handleExport(fmt.id)}
          disabled={fmt.available && !isDone}
          title={!fmt.available ? 'Coming soon' : !isDone ? 'Investigation must complete first' : `Export as ${fmt.label}`}
          className={`
            relative px-3 py-1 text-xs font-mono border rounded-sm transition-colors
            ${fmt.available
              ? isDone
                ? 'border-zinc-700 text-zinc-300 hover:border-cyan-400 hover:text-cyan-400 cursor-pointer'
                : 'border-zinc-800 text-zinc-600 cursor-not-allowed'
              : 'border-zinc-800/50 text-zinc-700 cursor-default'
            }
          `}
        >
          {fmt.label}
          {!fmt.available && (
            <span className="ml-1 text-zinc-700 text-xs">·soon</span>
          )}
        </button>
      ))}

      <div className="flex-1" />
      {isDone && (
        <span className="text-zinc-700 text-xs font-mono">investigation complete</span>
      )}
    </footer>
  )
}
