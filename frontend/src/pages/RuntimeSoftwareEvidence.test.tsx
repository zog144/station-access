// @vitest-environment jsdom
import { cleanup, render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, expect, test, vi } from 'vitest'
import { api, type Runtime } from '../api'
import { RuntimeSoftwareEvidence } from './RuntimeSoftwareEvidence'

let admin = true
vi.mock('../auth/AuthProvider', () => ({ useAuth: () => ({ user: {is_superuser: admin} }) }))
afterEach(() => { cleanup(); vi.restoreAllMocks(); admin = true })

const runtime: Runtime = {
  runtime_id:'runtime-one', instance_id:'editor', application_name:'editor', state:'running',
  generation:'generation-old', created_at:0, completed_at:null, request_id:null, fault:null,
  programs:[],
  software:{
    basis:'expected-launched', view:'sha256:' + 'a'.repeat(64),
    artifacts:['sha256:' + 'b'.repeat(64)], binding_digest:'sha256:' + 'c'.repeat(64),
    manifest_digest:'sha256:' + 'd'.repeat(64), mount_observation:'not-probed'
  }
}

test('historical runtime software remains unchanged when current selection differs', async () => {
  vi.spyOn(api,'applicationSoftwareDetail').mockResolvedValue({application_software:{
    schema:1, application:'editor', selection_basis:'current-application-specification',
    view:'sha256:' + 'e'.repeat(64), state:'verified',
    profile:'everything', view_contract:'v1', composition_count:0, artifacts:[],
    launch_readiness:'ready-to-attempt', mount_observation:'not-probed', read_only:true
  }})
  render(<MemoryRouter><RuntimeSoftwareEvidence runtime={runtime}/></MemoryRouter>)
  expect(await screen.findByText(/Launched view differs from the current selection/)).toBeTruthy()
  expect(screen.getByText(runtime.software!.view!)).toBeTruthy()
  expect(screen.getByText(runtime.software!.artifacts[0])).toBeTruthy()
  expect(screen.getByText(/contains no kernel mount observation/)).toBeTruthy()
})

test('ordinary owner sees own launch evidence but never queries admin selection', async () => {
  admin = false
  const spy = vi.spyOn(api,'applicationSoftwareDetail')
  render(<MemoryRouter><RuntimeSoftwareEvidence runtime={runtime}/></MemoryRouter>)
  expect(screen.getByText(runtime.software!.view!)).toBeTruthy()
  expect(screen.queryByText(/Current application selection/)).toBeNull()
  expect(spy).not.toHaveBeenCalled()
})
