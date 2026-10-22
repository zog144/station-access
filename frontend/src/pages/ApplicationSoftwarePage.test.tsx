// @vitest-environment jsdom
import { cleanup, render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, expect, test, vi } from 'vitest'
import { api, type ApplicationSoftwareInspection } from '../api'
import { ApplicationSoftwarePage } from './ApplicationSoftwarePage'

afterEach(() => { cleanup(); vi.restoreAllMocks() })

test('shows verified evidence without claiming live mounts or license review', async () => {
  const id = 'sha256:' + 'a'.repeat(64)
  const artifact = 'sha256:' + 'b'.repeat(64)
  const result: ApplicationSoftwareInspection = {
    schema: 1, basis: 'verified-publication-and-expected-launched',
    store: 'available', views_truncated: false, artifacts_truncated: false,
    read_only: true, mount_observation: 'not-probed',
    views: [{
      view: id, application: 'editor', selected: true, state: 'verified',
      profile: 'everything', artifacts: [artifact], composition_count: 5,
      runtime_count: 1, launch_readiness: 'ready-to-attempt', mount_observation: 'not-probed'
    }],
    artifacts: [{
      artifact, application: 'editor', revision: 'v1', architecture: 'x86_64',
      source_count: 1, notice_count: 1, license_state: 'notice-files-recorded',
      provenance_state: 'recorded',
      https_sources: [{name: 'Source', url: 'https://example.org/software.tar.gz', sha256: 'c'.repeat(64)}],
    }]
  }
  vi.spyOn(api, 'applicationSoftware').mockResolvedValue(result)
  render(<MemoryRouter><ApplicationSoftwarePage /></MemoryRouter>)
  expect(await screen.findByText('editor · Selected')).toBeTruthy()
  expect(screen.getByText(/Verified publication/)).toBeTruthy()
  expect(screen.getByText(/ready-to-attempt/)).toBeTruthy()
  expect(screen.getAllByText(/not probed/i).length).toBeGreaterThan(0)
  expect(screen.getByText(/License evidence: notice-files-recorded/)).toBeTruthy()
  expect(screen.getByRole('link', {name:'Source'}).getAttribute('href')).toBe('https://example.org/software.tar.gz')
})

test('missing software store is unknown, never an empty verified inventory', async () => {
  vi.spyOn(api, 'applicationSoftware').mockResolvedValue({
    schema: 1, basis: 'verified-publication-and-expected-launched', store: 'unavailable',
    views_truncated: false, artifacts_truncated: false, views: [], artifacts: [],
    read_only: true, mount_observation: 'not-probed'
  })
  render(<MemoryRouter><ApplicationSoftwarePage /></MemoryRouter>)
  expect(await screen.findByText(/No inspectable application-software store/)).toBeTruthy()
})
