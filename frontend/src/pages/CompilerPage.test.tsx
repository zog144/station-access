// @vitest-environment jsdom
import { cleanup, render, screen } from '@testing-library/react'
import { afterEach, expect, test, vi } from 'vitest'
import { compilerApi } from '../api'
import { CompilerPage } from './CompilerPage'

vi.mock('../auth/AuthProvider', () => ({
  useAuth: () => ({user:{id:1,username:'admin',is_superuser:true}}),
}))
afterEach(() => {cleanup();vi.restoreAllMocks()})

test('shows only bounded owner-ledger evidence, not live EC2 health', async () => {
  const spy=vi.spyOn(compilerApi,'status').mockResolvedValue({
    schema:'host-deploy-compiler-rpc-v1',state:'observed',ownership:'owned',
    compiler:'registered',evidence_basis:'owner-ledger',live_host_health:'not-observed',
  })
  render(<CompilerPage />)
  expect(await screen.findByText('Ownership: owned')).toBeTruthy()
  expect(screen.getByText('Live host health: not-observed')).toBeTruthy()
  expect(screen.getByText(/does not establish live EC2/)).toBeTruthy()
  expect(spy).toHaveBeenCalledTimes(1)
  expect(screen.queryByText(/workspace_id|instance_id|ownership_epoch/)).toBeNull()
})

test('unavailable RPC gives bounded status without backend error detail', async () => {
  vi.spyOn(compilerApi,'status').mockRejectedValue(new Error('private: /var/lib/hidden'))
  render(<CompilerPage />)
  expect(await screen.findByRole('alert')).toHaveProperty('textContent',expect.stringMatching(/unavailable or not authorized/))
  expect(screen.queryByText(/\/var\/lib\/hidden/)).toBeNull()
})
