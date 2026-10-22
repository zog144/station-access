// @vitest-environment jsdom
import { cleanup, render, screen } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { afterEach, expect, test, vi } from 'vitest'
import { api, type ApplicationSoftwareDetail } from '../api'
import { ApplicationSoftwareDetailPage } from './ApplicationSoftwareDetailPage'

afterEach(() => { cleanup(); vi.restoreAllMocks() })

const detail: ApplicationSoftwareDetail = {
  schema: 1, application: 'editor', selection_basis: 'current-application-specification',
  view: 'sha256:' + 'a'.repeat(64), state: 'verified', profile: 'everything',
  view_contract: 'application-software-view-v1', composition_count: 42,
  launch_readiness: 'ready-to-attempt', mount_observation: 'not-probed', read_only: true,
  artifacts: [{
    artifact: 'sha256:' + 'b'.repeat(64), application: 'editor',
    revision: 'revision-2', architecture: 'x86_64',
    compatibility: {
      schema: 1, mount_contract: 'applications-v1', architecture: 'x86_64',
      python: {implementation: 'cpython', version: '3.13', soabi: 'cpython-313'},
      libraries: ['libc.so.6'],
    },
    source_count: 1, https_sources: [{name: 'Verified source identity', url: 'https://example.org/source.tar', sha256: 'c'.repeat(64)}],
    notice_count: 1, notice_files: ['share/licenses/LICENSE.txt'],
    license_state: 'notice-files-recorded', provenance_state: 'recorded'
  }],
}

function page() {
  return render(<MemoryRouter initialEntries={['/application-software/applications/editor']}>
    <Routes><Route path="/application-software/applications/:applicationName" element={<ApplicationSoftwareDetailPage />}/></Routes>
  </MemoryRouter>)
}

test('displays selected identity compatibility and bounded source/license facts', async () => {
  vi.spyOn(api, 'applicationSoftwareDetail').mockResolvedValue({application_software: detail})
  page()
  expect(await screen.findByText('revision-2', {exact:false})).toBeTruthy()
  expect(screen.getByText(/Verified immutable publication/)).toBeTruthy()
  expect(screen.queryByText('No Python requirement recorded', {exact:false})).toBeNull()
  expect(screen.getByText(/cpython 3.13/)).toBeTruthy()
  expect(screen.getByText(/libc.so.6/)).toBeTruthy()
  expect(screen.getByRole('link',{name:'Verified source identity'}).getAttribute('href')).toBe('https://example.org/source.tar')
  expect(screen.getByText(/not a verified SPDX expression/i)).toBeTruthy()
  expect(screen.getByText(/Not probed/)).toBeTruthy()
})

test('unselected software remains explicit, never interpreted as empty verified artifact store', async () => {
  vi.spyOn(api, 'applicationSoftwareDetail').mockResolvedValue({application_software:{
    ...detail, state:'not-selected', view:null, profile:null, view_contract:null, artifacts:[], launch_readiness:'not-verified'
  }})
  page()
  expect(await screen.findByText('No software view selected')).toBeTruthy()
  expect(screen.queryByText('Verified immutable publication')).toBeNull()
})
