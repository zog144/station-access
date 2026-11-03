// @vitest-environment jsdom
// Synthetic combination of the exact PR #19 viewer and PR #20 readiness
// source candidates. The accompanying workflow overlays the PR #19 files;
// this test does not assume either branch is a production source selection.
import { afterEach, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { Link, MemoryRouter, Route, Routes } from 'react-router-dom'
import { api, type WorkspaceDiagnosticCheck, type WorkspaceReadiness } from '../src/api'
import { VncSessionProvider, useVncSessions } from '../src/vnc/VncSessionProvider'
import { PersistentVncSessions } from '../src/vnc/PersistentVncSessions'
import { VncPage } from '../src/pages/VncPage'

type Status = WorkspaceDiagnosticCheck['status']
const conditions: WorkspaceDiagnosticCheck['condition'][] = [
  'accepted-runtime', 'desktop-readiness', 'x11-authorization',
  'rfb-availability', 'browser-grant',
]
function observation(options: {
  controller?: string, desktop?: string, rfb?: Status, grant?: Status,
} = {}): WorkspaceReadiness {
  const checks: WorkspaceDiagnosticCheck[] = conditions.map(condition => ({
    condition,
    status: condition === 'rfb-availability' ? (options.rfb ?? 'confirmed') :
            condition === 'browser-grant' ? (options.grant ?? 'unknown') : 'confirmed',
    code: condition === 'browser-grant' ? 'grant-not-verified' :
          condition === 'rfb-availability' && options.rfb === 'failed' ? 'rfb-invalid' : 'ok',
    explanation: 'Synthetic separately observed stage; not a grant.',
    source: condition === 'browser-grant' ? 'saved-record' : 'current-controller',
  }))
  return {
    observed_at: '2026-11-03T12:00:00Z', read_only: true, advisory: true,
    controller: options.controller ?? 'available', desktop: options.desktop ?? 'ready',
    desktop_runtime_id: 'desktop-one', registration: 'recorded',
    launch_pending: false, cleanup_pending: false, pending_count: 0,
    cleanup_count: 0, launch_actions: [], preflight: null,
    diagnostics: {schema: 'station-workspace-diagnostics-v1',read_only:true,advisory:true,checks},
  }
}
function grant(revision: string) {
  return {token: 'inert-fixture-only', expires_at: '2026-11-03T13:00:00Z',
          novnc_url: '/inert-viewer.html?revision=' + revision}
}
function App() {
  return <MemoryRouter initialEntries={['/vnc/one']}>
    <VncSessionProvider>
      <nav><Link to="/away">Away</Link> <Link to="/vnc/one">Workspace one</Link>
        <Link to="/vnc/two">Workspace two</Link></nav>
      <Routes>
        <Route path="/vnc/:workspaceId" element={<VncPage />} />
        <Route path="/away" element={<p data-testid="away">Away, iframe stays mounted.</p>} />
      </Routes>
      <PersistentVncSessions />
    </VncSessionProvider>
  </MemoryRouter>
}
afterEach(() => { cleanup(); vi.restoreAllMocks() })

it('read-only changing X11/RFB and controller evidence never rotates an open iframe or grant', async () => {
  let current = observation({grant:'confirmed'})
  const status = vi.spyOn(api, 'workspaceReadiness').mockImplementation(async () => current)
  const authorize = vi.spyOn(api, 'vncGrant').mockResolvedValue(grant('first'))
  const launch = vi.spyOn(api, 'startWorkspace')
  const stop = vi.spyOn(api, 'stopWorkspace')
  render(<App />)
  const iframe = await screen.findByTitle('VNC workspace one') as HTMLIFrameElement
  const originalSrc = iframe.getAttribute('src')
  expect(authorize).toHaveBeenCalledTimes(1)
  fireEvent.click(screen.getByRole('button', {name:'Zoom in'}))
  expect(screen.getByLabelText('Viewer zoom').textContent).toBe('125%')
  fireEvent.click(screen.getByRole('button',{name:'Workspace status'}))
  const diagnostic = await screen.findByLabelText('Workspace diagnostics')
  await waitFor(() => expect(diagnostic.textContent).toContain('rfb availability · confirmed'))
  expect(diagnostic.textContent).toContain('browser grant · confirmed')

  current = observation({rfb:'failed', desktop:'running',grant:'unknown'})
  fireEvent.click(screen.getByRole('button',{name:'Refresh status'}))
  await waitFor(() => expect(diagnostic.textContent).toContain('rfb availability · failed'))
  expect(diagnostic.textContent).toContain('browser grant · unknown')
  // A diagnostic indication of a saved grant cannot create/replace one.
  expect(authorize).toHaveBeenCalledTimes(1)
  expect(screen.getByTitle('VNC workspace one')).toBe(iframe)

  current = observation({controller:'unavailable',desktop:'unknown',rfb:'unknown'})
  fireEvent.click(screen.getByRole('button',{name:'Refresh status'}))
  await waitFor(() => expect(screen.getByText('unavailable')).toBeTruthy())
  expect((screen.getByRole('button',{name:'Connect desktop'}) as HTMLButtonElement).disabled).toBe(true)
  expect(screen.getByTitle('VNC workspace one')).toBe(iframe)

  status.mockRejectedValueOnce(new Error('controller offline'))
  fireEvent.click(screen.getByRole('button',{name:'Refresh status'}))
  await screen.findByRole('alert')
  expect(diagnostic.textContent).toContain('Previous observation only')
  expect((screen.getByRole('button',{name:'Connect desktop'}) as HTMLButtonElement).disabled).toBe(true)
  expect(authorize).toHaveBeenCalledTimes(1)
  expect(launch).not.toHaveBeenCalled()
  expect(stop).not.toHaveBeenCalled()
  expect(screen.getByTitle('VNC workspace one')).toBe(iframe)
  expect(iframe.getAttribute('src')).toBe(originalSrc)
  fireEvent.click(screen.getByRole('link',{name:'Away'}))
  expect(screen.getByTestId('away').textContent).toContain('iframe')
  expect(screen.getByTitle('VNC workspace one')).toBe(iframe)
  expect(iframe.closest('.vnc-viewport')?.classList.contains('active')).toBe(false)
  fireEvent.click(screen.getByRole('link',{name:'Workspace one'}))
  await waitFor(() => expect(screen.getByTitle('VNC workspace one')).toBe(iframe))
  expect(screen.getByLabelText('Viewer zoom').textContent).toBe('125%')
  expect(authorize).toHaveBeenCalledTimes(1)
})

it('saved diagnostic browser-grant confirmation cannot reuse a closed grant on reconnect', async () => {
  let current = observation({grant:'confirmed'})
  vi.spyOn(api, 'workspaceReadiness').mockImplementation(async () => current)
  const authorize = vi.spyOn(api,'vncGrant')
    .mockResolvedValueOnce(grant('old'))
    .mockRejectedValueOnce(new Error('old grant refused by server'))
    .mockResolvedValueOnce(grant('replacement'))
  render(<App />)
  const first = await screen.findByTitle('VNC workspace one') as HTMLIFrameElement
  fireEvent.click(screen.getByRole('button',{name:'Zoom in'}))
  fireEvent.click(screen.getByRole('button',{name:'Close viewer'}))
  await waitFor(() => expect(screen.queryByTitle('VNC workspace one')).toBeNull())
  fireEvent.click(screen.getByRole('button',{name:'Workspace status'}))
  const diagnostic = await screen.findByLabelText('Workspace diagnostics')
  await waitFor(() => expect(diagnostic.textContent).toContain('browser grant · confirmed'))
  current = observation({controller:'unavailable',desktop:'unknown',grant:'unknown'})
  fireEvent.click(screen.getByRole('button',{name:'Refresh status'}))
  await waitFor(() => expect(screen.getByText('unavailable')).toBeTruthy())
  expect(diagnostic.textContent).toContain('browser grant · unknown')
  expect((screen.getByRole('button',{name:'Connect desktop'}) as HTMLButtonElement).disabled).toBe(true)
  expect(authorize).toHaveBeenCalledTimes(1)
  // Explicit request is routed through vncGrant, not through diagnostic data.
  fireEvent.click(screen.getByRole('button',{name:'Connect',exact:true}))
  await screen.findByText('old grant refused by server')
  expect(screen.queryByTitle('VNC workspace one')).toBeNull()
  expect(authorize).toHaveBeenCalledTimes(2)
  // Only another explicit request with server authorization can reconnect.
  fireEvent.click(screen.getByRole('button',{name:'Connect',exact:true}))
  const second = await screen.findByTitle('VNC workspace one') as HTMLIFrameElement
  expect(second).not.toBe(first)
  expect(second.getAttribute('src')).toContain('revision=replacement')
  expect(second.getAttribute('src')).not.toContain('revision=old')
  expect(screen.getByLabelText('Viewer zoom').textContent).toBe('125%')
  expect(authorize).toHaveBeenCalledTimes(3)
})

function DirectControls() {
  const {open,close,setZoom,preferences} = useVncSessions()
  return <div>
    <button onClick={() => void open('one')}>Request grant</button>
    <button onClick={() => close('one')}>Cancel pending viewer</button>
    <button onClick={() => setZoom('one',1.25)}>Set zoom</button>
    <output aria-label="Stored zoom">{preferences.one?.zoom ?? 1}</output>
  </div>
}
it('late original grant response cannot resurrect a closed or replaced iframe', async () => {
  let resolveOld!: (g: ReturnType<typeof grant>) => void
  const authorize = vi.spyOn(api,'vncGrant')
    .mockImplementationOnce(() => new Promise(resolve => {resolveOld = resolve}))
    .mockResolvedValueOnce(grant('new'))
  render(<MemoryRouter initialEntries={['/vnc/one']}>
    <VncSessionProvider><DirectControls /><PersistentVncSessions /></VncSessionProvider>
  </MemoryRouter>)
  fireEvent.click(screen.getByRole('button',{name:'Set zoom'}))
  fireEvent.click(screen.getByRole('button',{name:'Request grant'}))
  expect(authorize).toHaveBeenCalledTimes(1)
  fireEvent.click(screen.getByRole('button',{name:'Cancel pending viewer'}))
  fireEvent.click(screen.getByRole('button',{name:'Request grant'}))
  const frame = await screen.findByTitle('VNC workspace one') as HTMLIFrameElement
  expect(frame.getAttribute('src')).toContain('revision=new')
  resolveOld(grant('stale'))
  await waitFor(() => expect(authorize).toHaveBeenCalledTimes(2))
  expect(screen.getByTitle('VNC workspace one')).toBe(frame)
  expect(frame.getAttribute('src')).not.toContain('revision=stale')
  expect(screen.getByLabelText('Stored zoom').textContent).toBe('1.25')
})


it('an explicitly completed desktop stop closes its viewer but never starts replacement access', async () => {
  vi.spyOn(api,'workspaceReadiness').mockResolvedValue(observation())
  const authorize = vi.spyOn(api,'vncGrant').mockResolvedValue(grant('before-stop'))
  const stop = vi.spyOn(api,'stopWorkspace').mockResolvedValue({
    workspace: {id:'one'} as import('../src/api').Workspace,
  })
  render(<App />)
  const frame = await screen.findByTitle('VNC workspace one')
  fireEvent.click(screen.getByRole('button',{name:'Zoom in'}))
  fireEvent.click(screen.getByRole('button',{name:'Workspace status'}))
  await screen.findByLabelText('Workspace diagnostics')
  fireEvent.click(screen.getByRole('button',{name:'Stop or cancel desktop'}))
  expect(stop).not.toHaveBeenCalled()
  fireEvent.click(screen.getByRole('button',{name:'Confirm desktop stop'}))
  await waitFor(() => expect(screen.queryByTitle('VNC workspace one')).toBeNull())
  expect(stop).toHaveBeenCalledTimes(1)
  expect(stop).toHaveBeenCalledWith('one')
  expect(authorize).toHaveBeenCalledTimes(1)
  expect(frame.isConnected).toBe(false)
  expect(screen.getByLabelText('Viewer zoom').textContent).toBe('125%')
  // Stop completion is an explicit successful mutation, unlike read-only
  // failed/unknown diagnostic stages. It closes; it does not auto-relaunch.
  expect(screen.getByText(/Viewer closed/)).toBeTruthy()
})
