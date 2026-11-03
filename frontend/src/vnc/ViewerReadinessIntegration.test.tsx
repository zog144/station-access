// @vitest-environment jsdom
// Exact two-feature source composition: viewer PR #19 + diagnostic PR #20.
// Neither a diagnostic result nor a previously issued grant is an authority
// to resize, replace, reconnect or stop the persistent iframe.
import { afterEach, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { api, type WorkspaceReadiness } from '../api'
import { VncPage } from '../pages/VncPage'
import { PersistentVncSessions } from './PersistentVncSessions'
import { VncSessionProvider, useVncSessions } from './VncSessionProvider'

const base: WorkspaceReadiness = {
  observed_at: '2026-11-02T12:00:00Z',
  read_only: true, advisory: true, controller: 'available', desktop: 'ready',
  desktop_runtime_id: 'runtime-one', launch_pending: false, cleanup_pending: false,
  registration: 'recorded', pending_count: 0, cleanup_count: 0,
  launch_actions: [], preflight: null,
  diagnostics: {
    schema: 'station-workspace-diagnostics-v1', read_only: true, advisory: true,
    checks: [
      { condition: 'accepted-runtime', status: 'confirmed', code: 'runtime-running', source: 'current-controller', explanation: 'Original runtime selected.' },
      { condition: 'desktop-readiness', status: 'confirmed', code: 'desktop-access-verified', source: 'current-controller', explanation: 'Combined root probe.' },
      { condition: 'x11-authorization', status: 'confirmed', code: 'x11-authorized', source: 'current-controller', explanation: 'Read-only X11 evidence.' },
      { condition: 'rfb-availability', status: 'failed', code: 'rfb-invalid', source: 'current-controller', explanation: 'RFB probe rejected.' },
      { condition: 'browser-grant', status: 'unknown', code: 'grant-not-verified', source: 'not-observed', explanation: 'No live browser connection was observed.' },
    ],
  },
}
afterEach(() => { cleanup(); vi.restoreAllMocks() })

function Viewer() {
  return <MemoryRouter initialEntries={['/vnc/one']}>
    <VncSessionProvider>
      <Routes><Route path="/vnc/:workspaceId" element={<VncPage />} /></Routes>
      <PersistentVncSessions />
    </VncSessionProvider>
  </MemoryRouter>
}

it('keeps iframe identity, zoom and browser grant when X11/RFB evidence changes', async () => {
  const grant = vi.spyOn(api, 'vncGrant').mockResolvedValue({
    token: 'never-display-this', expires_at: 'later', novnc_url: 'about:blank#original-grant',
  })
  const read = vi.spyOn(api, 'workspaceReadiness').mockResolvedValue(base)
  const view = render(<Viewer />)
  await waitFor(() => expect(view.container.querySelectorAll('iframe')).toHaveLength(1))
  const frame = view.container.querySelector('iframe')!
  const initialSrc = frame.getAttribute('src')
  fireEvent.click(screen.getByRole('button', { name: 'Zoom in' }))
  expect(screen.getByLabelText('Viewer zoom').textContent).toBe('125%')
  fireEvent.click(screen.getByRole('button', { name: 'Workspace status' }))
  await screen.findByLabelText('Workspace diagnostics')
  expect(screen.getByLabelText('Workspace diagnostics').textContent).toContain('x11 authorization · confirmed')
  expect(screen.getByLabelText('Workspace diagnostics').textContent).toContain('rfb availability · failed')
  const callsBeforeRefresh = read.mock.calls.length
  read.mockResolvedValueOnce({
    ...base, desktop: 'running', diagnostics: {
      ...base.diagnostics!,
      checks: base.diagnostics!.checks.map(check => ({
        ...check, status: 'unknown' as const, code: 'probe-unavailable',
      })),
    },
  })
  fireEvent.click(screen.getByRole('button', { name: 'Refresh status' }))
  await waitFor(() => expect(read.mock.calls.length).toBeGreaterThan(callsBeforeRefresh))
  await waitFor(() => expect(screen.getByLabelText('Workspace diagnostics').textContent).toContain('rfb availability · unknown'))
  expect(view.container.querySelector('iframe')).toBe(frame)
  expect(frame.getAttribute('src')).toBe(initialSrc)
  expect(screen.getByLabelText('Viewer zoom').textContent).toBe('125%')
  expect(grant).toHaveBeenCalledTimes(1)
  expect(screen.getByLabelText('Workspace diagnostics').textContent).not.toContain('never-display-this')
})

it('controller outage makes diagnostics stale without revoking the iframe; explicit reconnect obtains a new grant', async () => {
  const grant = vi.spyOn(api, 'vncGrant')
    .mockResolvedValueOnce({ token: 'old-secret', expires_at: 'later', novnc_url: 'about:blank#grant-1' })
    .mockResolvedValueOnce({ token: 'new-secret', expires_at: 'later', novnc_url: 'about:blank#grant-2' })
  const read = vi.spyOn(api, 'workspaceReadiness').mockResolvedValue(base)
  const view = render(<Viewer />)
  await waitFor(() => expect(view.container.querySelectorAll('iframe')).toHaveLength(1))
  const first = view.container.querySelector('iframe')!
  fireEvent.click(screen.getByRole('button', { name: 'Zoom in' }))
  fireEvent.click(screen.getByRole('button', { name: 'Workspace status' }))
  await screen.findByLabelText('Workspace diagnostics')
  const callsBeforeOutage = read.mock.calls.length
  read.mockRejectedValueOnce(new Error('controller unavailable'))
  fireEvent.click(screen.getByRole('button', { name: 'Refresh status' }))
  await screen.findByRole('alert')
  expect(read.mock.calls.length).toBeGreaterThan(callsBeforeOutage)
  expect(screen.getByLabelText('Workspace diagnostics').textContent).toContain('unknown (last: confirmed)')
  expect((screen.getByRole('button', { name: 'Connect desktop' }) as HTMLButtonElement).disabled).toBe(true)
  expect(view.container.querySelector('iframe')).toBe(first)
  expect(grant).toHaveBeenCalledTimes(1)
  fireEvent.click(screen.getByRole('button', { name: 'Close viewer' }))
  expect(view.container.querySelector('iframe')).toBeNull()
  fireEvent.click(screen.getByRole('button', { name: 'Connect', exact: true }))
  await waitFor(() => expect(view.container.querySelector('iframe')?.getAttribute('src')).toBe('about:blank#grant-2'))
  expect(view.container.querySelector('iframe')).not.toBe(first)
  expect(screen.getByLabelText('Viewer zoom').textContent).toBe('125%')
  expect(grant).toHaveBeenCalledTimes(2)
})

function SessionCommands() {
  const { open, close } = useVncSessions()
  return <><button onClick={() => { void open('one') }}>Grant</button>
    <button onClick={() => close('one')}>Discard pending grant</button></>
}
it('discards an obsolete in-flight grant after close and accepts only the renewed request', async () => {
  let resolveOld!: (value: Awaited<ReturnType<typeof api.vncGrant>>) => void
  const grant = vi.spyOn(api, 'vncGrant').mockImplementationOnce(() =>
    new Promise(resolve => { resolveOld = resolve })).mockResolvedValueOnce({
      token: 'new-secret', expires_at: 'later', novnc_url: 'about:blank#grant-new',
    })
  const view = render(<MemoryRouter initialEntries={['/vnc/one']}><VncSessionProvider>
    <SessionCommands/><PersistentVncSessions/>
  </VncSessionProvider></MemoryRouter>)
  fireEvent.click(screen.getByRole('button', { name: 'Grant' }))
  await waitFor(() => expect(grant).toHaveBeenCalledTimes(1))
  fireEvent.click(screen.getByRole('button', { name: 'Discard pending grant' }))
  fireEvent.click(screen.getByRole('button', { name: 'Grant' }))
  await waitFor(() => expect(view.container.querySelector('iframe')?.getAttribute('src')).toBe('about:blank#grant-new'))
  const current = view.container.querySelector('iframe')
  resolveOld({ token: 'old-secret', expires_at: 'later', novnc_url: 'about:blank#grant-old' })
  await Promise.resolve()
  expect(view.container.querySelector('iframe')).toBe(current)
  expect(current?.getAttribute('src')).toBe('about:blank#grant-new')
  expect(grant).toHaveBeenCalledTimes(2)
})
