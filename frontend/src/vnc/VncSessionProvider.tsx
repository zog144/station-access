import { createContext, useCallback, useContext, useMemo, useState, useRef, type ReactNode } from 'react'
import { api } from '../api'

export type VncSession = { workspaceId: string; novncUrl: string; openedAt: number }
// Viewer preferences are terminal-local. They never affect Xvnc or the RFB geometry.
export type ViewerPreferences = { fit: boolean; zoom: number }
export const DEFAULT_VIEWER: ViewerPreferences = { fit: true, zoom: 1 }
export const MIN_ZOOM = 0.5
export const MAX_ZOOM = 2
export const ZOOM_STEP = 0.25
type VncContextValue = {
  sessions: VncSession[]
  open: (workspaceId: string) => Promise<void>
  close: (workspaceId: string) => void
  has: (workspaceId: string) => boolean
  preferences: Record<string, ViewerPreferences>
  setFit: (workspaceId: string, fit: boolean) => void
  setZoom: (workspaceId: string, zoom: number) => void
}
const VncContext = createContext<VncContextValue | null>(null)

export function VncSessionProvider({ children }: { children: ReactNode }) {
  const [sessions, setSessions] = useState<VncSession[]>([])
  // Do not discard preferences on close/reconnect; remove only the VNC grant.
  const [preferences, setPreferences] = useState<Record<string, ViewerPreferences>>({})
  const currentSessions = useRef(sessions)
  currentSessions.current = sessions
  const pending = useRef(new Map<string, Promise<void>>())
  const epochs = useRef(new Map<string, number>())
  const open = useCallback((workspaceId: string): Promise<void> => {
    if (currentSessions.current.some(session => session.workspaceId === workspaceId)) return Promise.resolve()
    const existing = pending.current.get(workspaceId)
    if (existing) return existing
    const epoch = epochs.current.get(workspaceId) ?? 0
    const request = api.vncGrant(workspaceId).then(grant => {
      if ((epochs.current.get(workspaceId) ?? 0) !== epoch) return
      setSessions(current => current.some(s => s.workspaceId === workspaceId)
        ? current
        : [...current, { workspaceId, novncUrl: grant.novnc_url, openedAt: Date.now() }])
    }).finally(() => { if (pending.current.get(workspaceId) === request) pending.current.delete(workspaceId) })
    pending.current.set(workspaceId, request)
    return request
  }, [])
  const close = useCallback((workspaceId: string) => {
    epochs.current.set(workspaceId, (epochs.current.get(workspaceId) ?? 0) + 1)
    pending.current.delete(workspaceId)
    setSessions(current => current.filter(s => s.workspaceId !== workspaceId))
  }, [])
  const setFit = useCallback((workspaceId: string, fit: boolean) => {
    setPreferences(current => ({ ...current, [workspaceId]: { ...(current[workspaceId] ?? DEFAULT_VIEWER), fit } }))
  }, [])
  const setZoom = useCallback((workspaceId: string, zoom: number) => {
    if (!Number.isFinite(zoom)) return
    const bounded = Math.max(MIN_ZOOM, Math.min(MAX_ZOOM, Math.round(zoom / ZOOM_STEP) * ZOOM_STEP))
    setPreferences(current => ({ ...current, [workspaceId]: { ...(current[workspaceId] ?? DEFAULT_VIEWER), zoom: bounded } }))
  }, [])
  const value = useMemo(() => ({
    sessions,
    preferences, setFit, setZoom,
    open,
    close,
    has: (id: string) => sessions.some(s => s.workspaceId === id),
  }), [sessions, preferences, setFit, setZoom, open, close])
  return <VncContext.Provider value={value}>{children}</VncContext.Provider>
}

export function useVncSessions() {
  const value = useContext(VncContext)
  if (!value) throw new Error('useVncSessions must be used inside VncSessionProvider')
  return value
}
