import { WorkspaceReadinessPanel } from './WorkspaceReadinessPanel'
import { WorkspaceApplicationsPanel } from './WorkspaceApplicationsPanel'
import { useEffect, useLayoutEffect, useRef, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { DEFAULT_VIEWER, useVncSessions } from '../vnc/VncSessionProvider'

export function VncPage() {
  const { workspaceId = '' } = useParams()
  const [statusDismissed, setStatusDismissed] = useState(false)
  const [showStatus, setShowStatus] = useState(false)
  const [showApplications, setShowApplications] = useState(false)
  const applicationsButton = useRef<HTMLButtonElement>(null)
  const toolbar = useRef<HTMLElement>(null)
  const closeApplications = () => { setShowApplications(false); applicationsButton.current?.focus() }
  useLayoutEffect(() => {
    const measure = () => document.documentElement.style.setProperty('--workspace-toolbar-height', `${(toolbar.current?.getBoundingClientRect().height ?? 48) + 12}px`)
    measure()
    const observer = typeof ResizeObserver !== 'undefined' ? new ResizeObserver(measure) : null
    if (toolbar.current) observer?.observe(toolbar.current)
    return () => { observer?.disconnect(); document.documentElement.style.removeProperty('--workspace-toolbar-height') }
  }, [])
  const { open, close, has, preferences, setFit, setZoom } = useVncSessions()
  const view = preferences[workspaceId] ?? DEFAULT_VIEWER
  const [error, setError] = useState<string | null>(null)
  const [closed, setClosed] = useState(false)
  const [retry, setRetry] = useState(0)
  useEffect(() => { setClosed(false); setError(null); setStatusDismissed(false); setShowStatus(false); setShowApplications(false) }, [workspaceId])
  useEffect(() => {
    if (!workspaceId || has(workspaceId) || closed) return
    let active = true
    setError(null)
    open(workspaceId).catch(reason => { if (active) setError(reason instanceof Error ? reason.message : String(reason)) })
    return () => { active = false }
  }, [workspaceId, has, open, closed, retry])
  const connect = () => { setClosed(false); setRetry(value => value + 1) }
  const statusVisible = showStatus || (!has(workspaceId) && !closed && !statusDismissed && !showApplications)
  return <><section ref={toolbar} className="vnc-toolbar">
    <button aria-expanded={statusVisible} onClick={() => { setShowStatus(!statusVisible); setStatusDismissed(statusVisible); setShowApplications(false) }}>Workspace status</button>
    <button ref={applicationsButton} aria-expanded={showApplications} aria-controls="workspace-applications" onClick={() => { setShowApplications(value => !value); setShowStatus(false) }}>Applications</button>
    <div className="vnc-zoom-controls" aria-label="Viewer scale controls">
      <label><input type="checkbox" checked={view.fit} onChange={event => setFit(workspaceId, event.target.checked)} />Fit window</label>
      <button aria-label="Zoom out" disabled={view.zoom <= 0.5} onClick={() => setZoom(workspaceId, view.zoom - 0.25)}>−</button>
      <output aria-label="Viewer zoom">{Math.round(view.zoom * 100)}%</output>
      <button aria-label="Zoom in" disabled={view.zoom >= 2} onClick={() => setZoom(workspaceId, view.zoom + 0.25)}>+</button>
      <button onClick={() => { setFit(workspaceId, true); setZoom(workspaceId, 1) }}>Reset view</button>
    </div>
    <Link to="/workspaces">← Workspaces</Link>
    <span>{error ?? (closed ? 'Viewer closed. Closing the viewer does not stop the workspace.' : has(workspaceId) ? 'Viewer stays open while you navigate.' : 'Starting workspace and connecting…')}</span>
    {(error || closed) && <button onClick={() => { setClosed(false); setRetry(value => value + 1) }}>Connect</button>}
    {has(workspaceId) && <button onClick={() => { setClosed(true); close(workspaceId) }}>Close viewer</button>}
  </section>
    {statusVisible && <WorkspaceReadinessPanel key={workspaceId} workspaceId={workspaceId} onStopped={() => { setClosed(true); close(workspaceId); setShowStatus(true) }} onConnect={connect} onApplications={() => { setShowStatus(false); setShowApplications(true) }} onClose={() => { setShowStatus(false); setStatusDismissed(true) }} />}
    {showApplications && <WorkspaceApplicationsPanel key={workspaceId} workspaceId={workspaceId} onClose={closeApplications} />}
  </>
}
