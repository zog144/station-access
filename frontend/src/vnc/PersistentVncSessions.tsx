import { useLayoutEffect, useRef, useState } from 'react'
import { matchPath, useLocation } from 'react-router-dom'
import { DEFAULT_VIEWER, useVncSessions, type ViewerPreferences } from './VncSessionProvider'

// The iframe viewport matches the intended Xvnc display, not the browser window.
// Only CSS transforms change local presentation; no RFB SetDesktopSize is issued.
export const REMOTE_WIDTH = 1920
export const REMOTE_HEIGHT = 1080

export function viewerScale(width: number, height: number, preference: ViewerPreferences): number {
  const fit = preference.fit
    ? Math.min(1, Math.max(0.01, width / REMOTE_WIDTH), Math.max(0.01, height / REMOTE_HEIGHT))
    : 1
  return fit * preference.zoom
}

// Useful for testing and future overlay placement. Native browser hit-testing
// handles CSS-transformed iframe input, so do not proxy pointer events through React.
export function remotePoint(x: number, y: number, left: number, top: number, scale: number) {
  return { x: (x - left) / scale, y: (y - top) / scale }
}

export function PersistentVncSessions() {
  const { sessions, preferences } = useVncSessions()
  const location = useLocation()
  const match = matchPath('/vnc/:workspaceId', location.pathname)
  const activeWorkspaceId = match?.params.workspaceId ?? null
  const layer = useRef<HTMLDivElement>(null)
  const [viewport, setViewport] = useState({ width: REMOTE_WIDTH, height: REMOTE_HEIGHT })
  useLayoutEffect(() => {
    const element = layer.current
    if (!element) return
    const measure = () => {
      const rect = element.getBoundingClientRect()
      if (rect.width > 0 && rect.height > 0) {
        setViewport({ width: rect.width, height: rect.height })
      }
    }
    measure()
    const observer = typeof ResizeObserver === 'undefined' ? null : new ResizeObserver(measure)
    observer?.observe(element)
    window.addEventListener('resize', measure)
    return () => { observer?.disconnect(); window.removeEventListener('resize', measure) }
  }, [])
  return (
    <div ref={layer} className="vnc-session-layer" aria-hidden={activeWorkspaceId === null}>
      {sessions.map(session => {
        const active = activeWorkspaceId === session.workspaceId
        const scale = viewerScale(viewport.width, viewport.height, preferences[session.workspaceId] ?? DEFAULT_VIEWER)
        return <div key={session.workspaceId}
          className={`vnc-viewport ${active ? 'active' : ''}`} aria-hidden={!active}>
          <div className="vnc-scaled-display"
            data-workspace-id={session.workspaceId}
            data-local-scale={scale}
            style={{ width: REMOTE_WIDTH * scale, height: REMOTE_HEIGHT * scale }}>
            <iframe className={`vnc-frame ${active ? 'active' : ''}`}
              src={session.novncUrl}
              title={`VNC workspace ${session.workspaceId}`}
              style={{ transform: `scale(${scale})` }}
              tabIndex={active ? 0 : -1}
              allow="clipboard-read; clipboard-write" />
          </div>
        </div>
      })}
    </div>
  )
}
