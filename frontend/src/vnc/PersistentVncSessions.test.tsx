// @vitest-environment jsdom
import { VncPage } from '../pages/VncPage'
import { afterEach, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter, Link, Routes, Route } from 'react-router-dom'
import { api } from '../api'
import { VncSessionProvider, useVncSessions } from './VncSessionProvider'
import { PersistentVncSessions, viewerScale, remotePoint } from './PersistentVncSessions'
function Controls() {
  const { open, close } = useVncSessions()
  return <><button onClick={() => { void open('one'); void open('one') }}>Open</button><button onClick={() => close('one')}>Close</button><Link to="/applications">Applications</Link><Link to="/vnc/one">Viewer</Link></>
}
afterEach(() => { cleanup(); vi.restoreAllMocks() })
it('keeps the same iframe during navigation and coalesces simultaneous opens', async () => {
  const grant = vi.spyOn(api, 'vncGrant').mockResolvedValue({ token: 'fixture', expires_at: 'later', novnc_url: 'about:blank' })
  const view = render(<MemoryRouter initialEntries={['/vnc/one']}><VncSessionProvider><Controls/><PersistentVncSessions/></VncSessionProvider></MemoryRouter>)
  fireEvent.click(screen.getByText('Open'))
  await waitFor(() => expect(view.container.querySelectorAll('iframe')).toHaveLength(1))
  expect(grant).toHaveBeenCalledTimes(1)
  const frame = view.container.querySelector('iframe')
  fireEvent.click(screen.getByText('Applications'))
  expect(view.container.querySelector('iframe')).toBe(frame)
  expect(frame?.classList.contains('active')).toBe(false)
  fireEvent.click(screen.getByText('Close'))
  expect(view.container.querySelector('iframe')).toBeNull()
})

it('opening and closing the application panel preserves the desktop iframe', async () => {
  const grant = vi.spyOn(api, 'vncGrant').mockResolvedValue({ token:'fixture',expires_at:'later',novnc_url:'about:blank' })
  vi.spyOn(api, 'workspaceApplications').mockResolvedValue({workspace:{id:'one',number:1,name:'Research',network:'default',application_name:'vnc-workspace',desired_running:true,runtime_id:'desktop-one',instance_id:'desktop-one',status:'running',runtime_state:'running',endpoint_ready:true,endpoint_bound:true,last_error:null,created_at:'now',updated_at:'now'},applications:[],runtimes:[],launch:{available:false,code:'pending',reason:'Controller support pending'},membership:{source:'recorded_launch_parameters',authoritative:false},state_source:'recorded'} as import('../api').WorkspaceApplications)
  const view = render(<MemoryRouter initialEntries={['/vnc/one']}><VncSessionProvider><Routes><Route path="/vnc/:workspaceId" element={<VncPage />} /></Routes><PersistentVncSessions /></VncSessionProvider></MemoryRouter>)
  await waitFor(() => expect(view.container.querySelectorAll('iframe')).toHaveLength(1))
  const frame = view.container.querySelector('iframe')
  fireEvent.click(screen.getByRole('button',{name:'Applications'}))
  await screen.findByText('Workspace: Research')
  fireEvent.click(screen.getByRole('button',{name:'Close application panel'}))
  expect(view.container.querySelector('iframe')).toBe(frame)
  expect(grant).toHaveBeenCalledTimes(1)
})

it('fits the terminal viewport without changing the remote display geometry', async () => {
  vi.spyOn(api, 'vncGrant').mockResolvedValue({ token:'fixture', expires_at:'later', novnc_url:'/novnc/?resize=scale' })
  const view = render(<MemoryRouter initialEntries={['/vnc/one']}><VncSessionProvider><Controls/><PersistentVncSessions/></VncSessionProvider></MemoryRouter>)
  fireEvent.click(screen.getByRole('button', { name:'Open' }))
  const frame = await waitFor(() => {
    const frame = view.container.querySelector('iframe')
    expect(frame).toBeTruthy()
    return frame!
  })
  const layer = view.container.querySelector('.vnc-session-layer')!
  vi.spyOn(layer, 'getBoundingClientRect').mockReturnValue({ width:960, height:540, x:0, y:0, top:0, left:0, right:960, bottom:540, toJSON:() => ({}) })
  fireEvent(window, new Event('resize'))
  await waitFor(() => expect(view.container.querySelector('.vnc-scaled-display')?.getAttribute('data-local-scale')).toBe('0.5'))
  expect(frame.style.width).toBe('') // intrinsic frame size is CSS-fixed, not rewritten by JS
  expect(frame.style.transform).toBe('scale(0.5)')
  expect(frame.src).toContain('resize=scale') // noVNC local scale, not resize=remote
  vi.mocked(layer.getBoundingClientRect).mockReturnValue({ width:480, height:270, x:0, y:0, top:0, left:0, right:480, bottom:270, toJSON:() => ({}) })
  fireEvent(window, new Event('resize'))
  await waitFor(() => expect(frame.style.transform).toBe('scale(0.25)'))
  expect(view.container.querySelector('iframe')).toBe(frame)
})

it('retains per-workspace zoom across navigation and reconnection', async () => {
  const grant = vi.spyOn(api, 'vncGrant').mockResolvedValue({token:'fixture', expires_at:'later', novnc_url:'about:blank'})
  const view = render(<MemoryRouter initialEntries={['/vnc/one']}><VncSessionProvider>
    <Controls/><Routes><Route path="/vnc/:workspaceId" element={<VncPage />}/></Routes><PersistentVncSessions/>
  </VncSessionProvider></MemoryRouter>)
  const frame = await waitFor(() => { expect(view.container.querySelector('iframe')).toBeTruthy(); return view.container.querySelector('iframe')! })
  fireEvent.click(screen.getByRole('button',{name:'Zoom in'}))
  expect(screen.getByLabelText('Viewer zoom').textContent).toBe('125%')
  fireEvent.click(screen.getByRole('link',{name:'Applications'}))
  expect(view.container.querySelector('iframe')).toBe(frame)
  fireEvent.click(screen.getByRole('link',{name:'Viewer'}))
  expect(screen.getByLabelText('Viewer zoom').textContent).toBe('125%')
  fireEvent.click(screen.getByRole('button',{name:'Close viewer'}))
  expect(view.container.querySelector('iframe')).toBeNull()
  fireEvent.click(screen.getByRole('button',{name:'Connect'}))
  await waitFor(() => expect(view.container.querySelectorAll('iframe')).toHaveLength(1))
  expect(grant).toHaveBeenCalledTimes(2)
  expect(screen.getByLabelText('Viewer zoom').textContent).toBe('125%')
  expect(view.container.querySelector('iframe')?.getAttribute('style')).toContain('scale(1.25)')
})

it('maps transformed pointer coordinates without changing the 1920x1080 remote pixel grid', () => {
  expect(viewerScale(960, 540, {fit:true, zoom:1})).toBe(0.5)
  expect(viewerScale(3000, 2000, {fit:true, zoom:1.25})).toBe(1.25)
  expect(remotePoint(580, 320, 100, 50, 0.5)).toEqual({x:960,y:540})
  expect(remotePoint(1060, 590, 100, 50, 0.5)).toEqual({x:1920,y:1080})
  expect(remotePoint(1060, 590, 100, 50, 1)).toEqual({x:960,y:540})
})
