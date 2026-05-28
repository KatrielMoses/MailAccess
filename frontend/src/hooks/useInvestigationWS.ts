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
          store.handleWsModuleResult(frame.module, frame.findings, frame.status)
          break
        case 'module_error':
          store.handleWsModuleError(frame.module, frame.error)
          break
        case 'investigation_complete':
          store.handleWsComplete(
            frame.canonical_email ?? null,
            frame.exposure_score,
            frame.risk_level,
            frame.credential_risk_score,
            frame.credential_risk_band,
            frame.timeline
          )
          break
        case 'error':
          // Queue already consumed (historical view) — ignore
          break
      }
    }

    ws.onclose = () => {
      wsRef.current = null
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
