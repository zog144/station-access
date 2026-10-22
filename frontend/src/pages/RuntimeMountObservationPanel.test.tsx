// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, expect, test, vi } from 'vitest'
import { api, type RuntimeMountObservation } from '../api'
import { RuntimeMountObservationPanel } from './RuntimeMountObservationPanel'

let admin = true
vi.mock('../auth/AuthProvider', () => ({ useAuth: () => ({ user: { is_superuser: admin } }) }))
afterEach(() => { cleanup(); vi.restoreAllMocks(); admin = true })

const response: RuntimeMountObservation = {
  schema: 'zog-runtime-mount-observation-v1', runtime_id: 'old-runtime',
  basis: 'kernel-mount-namespace', snapshot: 'non-atomic', observed_at: 1791650000,
  status: 'partial', truncated: false,
  programs: [{
    program: 'web', status: 'partial', truncated: false,
    mount_namespace: 'mnt:[123]', multiple_mount_namespaces: true,
    mounts: [], mount_namespaces: [
      {mount_namespace: 'mnt:[123]', truncated:false, mounts:[{
        destination:'/applications/kate', kind:'application-software-view',
        expected_access:'read-only', observed_presence:'present',
        observed_access:'read-only', backing_identity:'inconclusive'
      }]},
      {mount_namespace: 'mnt:[456]', truncated:true, mounts:[{
        destination:'/data', kind:'application-data',
        expected_access:'read-write', observed_presence:'unknown',
        observed_access:'unknown', backing_identity:'inconclusive'
      }]}
    ]
  }]
}

test('no automatic privileged polling and no misleading healthy status for partial evidence', async () => {
  const spy = vi.spyOn(api,'runtimeMounts').mockResolvedValue({observation:response})
  render(<RuntimeMountObservationPanel runtimeId="old-runtime"/>)
  expect(spy).not.toHaveBeenCalled()
  expect(screen.getByText(/Not probed in this page session/)).toBeTruthy()
  fireEvent.click(screen.getByRole('button',{name:'Refresh observation'}))
  expect((await screen.findAllByText(/Partial \/ inconclusive/)).length).toBeGreaterThan(0)
  expect(spy).toHaveBeenCalledTimes(1)
  expect(screen.getByText(/multiple mount namespaces/)).toBeTruthy()
  expect(screen.getByText('/applications/kate')).toBeTruthy()
  expect(screen.getAllByText('inconclusive').length).toBeGreaterThan(0)
  expect(screen.getByText(/unseen mounts remain unknown/)).toBeTruthy()
})

test('observed integrity fault remains an explicit warning', async () => {
  vi.spyOn(api,'runtimeMounts').mockResolvedValue({observation:{
    ...response, status:'integrity-fault', programs:[{...response.programs[0], status:'integrity-fault'}]
  }})
  render(<RuntimeMountObservationPanel runtimeId="old-runtime"/>)
  fireEvent.click(screen.getByRole('button',{name:'Refresh observation'}))
  expect(await screen.findByRole('alert')).toBeTruthy()
  expect(screen.getAllByText(/Integrity fault/).length).toBeGreaterThan(0)
})

test('admin request failures do not manufacture a healthy mount state', async () => {
  vi.spyOn(api,'runtimeMounts').mockRejectedValue(Error('/proc/54321/private'))
  render(<RuntimeMountObservationPanel runtimeId="old-runtime"/>)
  fireEvent.click(screen.getByRole('button',{name:'Refresh observation'}))
  expect(await screen.findByRole('alert')).toBeTruthy()
  expect(screen.queryByText('/proc/54321/private')).toBeNull()
  await waitFor(() => expect(screen.getByRole('button',{name:'Refresh observation'})).toBeTruthy())
})

test('nonadministrators do not see mount observation and never call privileged API', () => {
  admin = false
  const spy = vi.spyOn(api,'runtimeMounts')
  const {container} = render(<RuntimeMountObservationPanel runtimeId="old-runtime"/>)
  expect(container.textContent).toBe('')
  expect(spy).not.toHaveBeenCalled()
})
