// @vitest-environment jsdom
import {render,screen,fireEvent,waitFor,cleanup} from '@testing-library/react'
import {afterEach,expect,test,vi} from 'vitest'
import {setupApi,type ApplicationProgressView} from '../api'
import {ApplicationProgressPanel} from './ApplicationProgressPanel'

afterEach(()=>{cleanup();vi.restoreAllMocks()})
const base:ApplicationProgressView={
  schema:'zog-station-application-progress-view-v1',read_only:true,
  availability:'observed',observed_at:'2026-10-16T17:00:00Z',
  snapshot_id:'b'.repeat(32),boot_id:null,
  host_id:null,installation_id:null,
  installation_state:'unobserved',publication_state:'unobserved',
  items:[],page:{build_has_more:false,runtime_has_more:false,
    next_build:null,next_runtime:null},
  local_session:{availability:'observed',capabilities:{
    schema:'zog-local-session-capabilities-v1',supported:false,
    status:'not-implemented',physical_seat:'unavailable',
    virtual_seat:'unavailable',login_role:'not-authorized',
    workspace_v1_is_local_seat:false
  }}
}
test('never polls or starts build merely because page loads',async()=>{
  const get=vi.spyOn(setupApi,'applicationProgress')
  render(<ApplicationProgressPanel/>)
  expect(get).not.toHaveBeenCalled()
  expect(screen.getByText(/During first boot the local console remains available/)).toBeTruthy()
  expect(screen.queryByText(/greetd ready/i)).toBeNull()
})
test('clearly distinguishes successful build command from software publication and local seat',async()=>{
  const get=vi.spyOn(setupApi,'applicationProgress').mockResolvedValue({
    ...base,items:[{producer:'box-control',application:null,operation_id:'build:'+'a'.repeat(32),
      build_job_id:'a'.repeat(32),runtime_id:null,controller_request_id:'req',
      selected_software_id:null,phase:'building',state:'succeeded',
      message_code:'build-command-succeeded',
      message:'Build command succeeded; publication is not verified'}]
  })
  render(<ApplicationProgressPanel/>)
  fireEvent.click(screen.getByRole('button',{name:'Refresh controller progress'}))
  await screen.findByText(/Unassociated build command/)
  expect(get).toHaveBeenCalledWith(null,null)
  expect(screen.getByText(/Software publication:/)).toBeTruthy()
  expect(screen.getByText(/Not implemented/)).toBeTruthy()
  expect(screen.getByText(/remote sessions and cannot/)).toBeTruthy()
  expect(screen.queryByText('Firefox ready')).toBeNull()
})
test('missing build record and controller absence never appear as completed',async()=>{
  const get=vi.spyOn(setupApi,'applicationProgress')
    .mockResolvedValueOnce({...base,items:[{producer:'box-control',
      application:null,operation_id:'build:'+'a'.repeat(32),
      build_job_id:'a'.repeat(32),runtime_id:null,controller_request_id:null,
      selected_software_id:null,phase:'building',state:'unknown',
      message_code:'build-evidence-unavailable',
      message:'Build job evidence is missing or inconsistent'}]})
    .mockResolvedValueOnce({...base,availability:'unavailable',items:[],
      observed_at:null,snapshot_id:null,page:null,
      local_session:{availability:'unavailable',capabilities:null}})
  render(<ApplicationProgressPanel/>)
  fireEvent.click(screen.getByRole('button',{name:'Refresh controller progress'}))
  await screen.findByText(/Build job evidence is missing or inconsistent/)
  expect(screen.getByText(/Unknown/)).toBeTruthy()
  fireEvent.click(screen.getByRole('button',{name:'Refresh controller progress'}))
  await screen.findByText(/Controller progress unavailable/)
  expect(screen.queryByText(/Phase succeeded/)).toBeNull()
  expect(get).toHaveBeenCalledTimes(2)
})
test('uncertain or blocked evidence remains explicit and pagination is manual',async()=>{
  const get=vi.spyOn(setupApi,'applicationProgress').mockResolvedValueOnce({
    ...base,
    page:{build_has_more:true,runtime_has_more:false,next_build:'a'.repeat(32),next_runtime:null},
    items:[{producer:'box-control',application:null,operation_id:'build:'+'a'.repeat(32),
      build_job_id:'a'.repeat(32),runtime_id:null,controller_request_id:null,
      selected_software_id:null,phase:'building',state:'uncertain',
      message_code:'build-outcome-uncertain',message:'Build command outcome needs reconciliation'}]
  }).mockResolvedValueOnce({...base,items:[]})
  render(<ApplicationProgressPanel/>)
  fireEvent.click(screen.getByRole('button',{name:'Refresh controller progress'}))
  await screen.findByText(/Uncertain — needs reconciliation/)
  expect(get).toHaveBeenCalledTimes(1)
  fireEvent.click(screen.getByRole('button',{name:'Next bounded page'}))
  await waitFor(()=>expect(get).toHaveBeenCalledWith('a'.repeat(32),null))
  await screen.findByText(/No controller records on this page/)
})
test('failed API refresh discards previously displayed observations and private errors',async()=>{
  const get=vi.spyOn(setupApi,'applicationProgress').mockResolvedValueOnce(base)
    .mockRejectedValueOnce(new Error('internal/protected/project secret'))
  render(<ApplicationProgressPanel/>)
  fireEvent.click(screen.getByRole('button',{name:'Refresh controller progress'}))
  await screen.findByText(/Controller observation at/)
  fireEvent.click(screen.getByRole('button',{name:'Refresh controller progress'}))
  await screen.findByRole('alert')
  expect(screen.queryByText(/Controller observation at/)).toBeNull()
  expect(screen.queryByText(/internal\/protected/)).toBeNull()
  expect(get).toHaveBeenCalledTimes(2)
})
