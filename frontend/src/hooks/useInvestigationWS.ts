import { useEffect, useRef } from 'react'
import { useInvestigationStore } from '../store/investigationStore'
import type { WsEvent } from '../types'

export function useInvestigationWS(investigationId: string | null) {
  const store = useInvestigationStore()
  const wsRef = useRef<WebSocket | null>(null)

  useEffect(() => {
    if (!investigationId) return
    if (store.status === 'complete' || store.status === 'failed') return

    const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:'
    const url = `${protocol}//${location.host}/ws/investigate/${investigationId}`
    const ws = new WebSocket(url)
    wsRef.current = ws
    // R9 — track whether a terminal frame arrived; if the socket closes without
    // one (reconnect-uncertainty), we must fetch persisted truth to converge.
    let sawTerminal = false

    ws.onmessage = (ev: MessageEvent<string>) => {
      let frame: WsEvent
      try {
        frame = JSON.parse(ev.data) as WsEvent
      } catch {
        return
      }

      switch (frame.type) {
        case 'module_start':
          store.handleWsModuleStart(frame.module)
          break
        case 'module_result':
          // `findings` may be absent on an oversized/_truncated frame — the store
          // tolerates it; the persisted report is the source of truth.
          store.handleWsModuleResult(frame.module, frame.findings, frame.status)
          break
        case 'module_error':
          store.handleWsModuleError(frame.module, frame.error)
          break
        case 'investigation_complete':
          sawTerminal = true
          store.handleWsComplete(
            frame.canonical_email ?? null,
            frame.exposure_score,
            frame.risk_level,
            frame.credential_risk_score,
            frame.credential_risk_band,
            frame.timeline
          )
          // R9 — converge to the persisted report (live frames may be partial).
          void store.syncFromServer(investigationId)
          break
        case 'investigation_failed':
          // R9 — a persisted failure must move the view out of "running".
          sawTerminal = true
          store.handleWsFailed(frame.error)
          void store.syncFromServer(investigationId)
          break
        case 'error':
          // Queue already consumed (historical view) — ignore
          break
      }
    }

    ws.onclose = () => {
      wsRef.current = null
      // R9 — reconnect-uncertainty: the socket closed before any terminal frame,
      // so we can't trust the live view. Fetch persisted truth to converge (it
      // may reveal completion or a failure the stream never delivered).
      if (!sawTerminal) {
        void store.syncFromServer(investigationId)
      }
    }

    return () => {
      if (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING) {
        ws.close()
      }
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [investigationId])

  return wsRef
}
