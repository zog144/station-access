// @vitest-environment jsdom
import {render,screen,fireEvent,waitFor,cleanup} from '@testing-library/react'
import {afterEach,expect,test,vi} from 'vitest'
import {certificateAssignmentApi,type CertificateAssignmentData,type CertificatePolicy} from '../api'
import {CertificateAssignmentsPanel} from './CertificateAssignmentsPanel'

afterEach(()=>{cleanup();vi.restoreAllMocks()})
const proposal:CertificatePolicy={
  schema:'zog-certify-manage-v1',certificate_id:'station-web',
  hostnames:['local.extra.example.test'],email:'ops@example.test',
  acme_directory:'https://acme.example.test/directory',
  challenge:'dns-01',dns_plugin:'dns-cloudflare',
}
const listing:CertificateAssignmentData={
  schema:'zog-certificate-assignment-v1',read_only:true,assignments:[],hosts:[],
  bindings:[{binding_id:'zone-1',zone_id:'zone-id',zone_name:'example.test',
     prefix:'extra.example.test',credential_id:'credential-uuid',credential_revision:4}]
}
test('read-only load never creates assignment or calls issuer',async()=>{
  const list=vi.spyOn(certificateAssignmentApi,'list').mockResolvedValue(listing)
  const decide=vi.spyOn(certificateAssignmentApi,'decide')
  render(<CertificateAssignmentsPanel proposal={proposal}/>)
  expect(await screen.findByText(/No assignment recorded/)).toBeTruthy()
  expect(list).toHaveBeenCalledTimes(1)
  expect(decide).not.toHaveBeenCalled()
  expect(screen.getByText(/neither approval nor retrieval starts an issuer/i)).toBeTruthy()
})
test('explicit standalone selection carries reviewed zone identity but no token',async()=>{
  vi.spyOn(certificateAssignmentApi,'list').mockResolvedValue(listing)
  const decide=vi.spyOn(certificateAssignmentApi,'decide').mockResolvedValue({
    receipt:{schema:'zog-certificate-assignment-receipt-v1',statement:{
       schema:'zog-certificate-assignment-v1',signer_id:'fixture',origin:'local',
       assignment_id:'id',installation_id:'install',host_id:null,host_fingerprint:null,
       credential_id:'credential-uuid',credential_revision:4,
       zone_id:'zone-id',zone_name:'example.test',binding_id:'zone-1',
       policy:proposal,consumer:'station-nginx-https',revision:1,state:'approved',
       approved_at:'2026-10-15T12:00:00Z',expires_at:'2026-10-21T12:00:00Z',
       operation_id:'00000000-0000-4000-8000-000000000001'
    },signature_ed25519:'fixture'}
  })
  Object.defineProperty(globalThis.crypto,'randomUUID',{configurable:true,value:()=> '00000000-0000-4000-8000-000000000001'})
  render(<CertificateAssignmentsPanel proposal={proposal}/>)
  await screen.findByText(/No assignment recorded/)
  fireEvent.change(screen.getByLabelText('Reviewed DNS zone binding'),{target:{value:'zone-1'}})
  fireEvent.change(screen.getByLabelText('Exact hostname'),{target:{value:'local.extra.example.test'}})
  fireEvent.click(screen.getByRole('button',{name:'Approve signed assignment (no issuance)'}))
  await waitFor(()=>expect(decide).toHaveBeenCalledWith(expect.objectContaining({
    origin:'local',host_id:null,binding_id:'zone-1',zone_id:'zone-id',
    credential_id:'credential-uuid',credential_revision:4,
    policy:expect.objectContaining({hostnames:['local.extra.example.test']}),
  })))
  expect(JSON.stringify(decide.mock.calls)).not.toContain('api_token')
})
test('no issuer policy means assignment approval remains disabled',async()=>{
  vi.spyOn(certificateAssignmentApi,'list').mockResolvedValue(listing)
  const decide=vi.spyOn(certificateAssignmentApi,'decide')
  render(<CertificateAssignmentsPanel proposal={null}/>)
  await screen.findByText(/No assignment recorded/)
  expect((screen.getByRole('button',{name:'Approve signed assignment (no issuance)'}) as HTMLButtonElement).disabled).toBe(true)
  expect(decide).not.toHaveBeenCalled()
})
