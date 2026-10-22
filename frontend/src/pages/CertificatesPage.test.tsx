// @vitest-environment jsdom
import {render,screen,fireEvent,waitFor,cleanup} from '@testing-library/react'
import {afterEach,beforeEach,expect,test,vi} from 'vitest'
import {certificateApi,certificateAssignmentApi,type CertificateSetup} from '../api'
import {CertificatesPage} from './CertificatesPage'
const session=vi.hoisted(()=>({user:{is_superuser:true}}))
vi.mock('../auth/AuthProvider',()=>({useAuth:()=>session}))
beforeEach(()=>{vi.spyOn(certificateAssignmentApi,'list').mockResolvedValue({
 schema:'zog-certificate-assignment-v1',read_only:true,bindings:[],hosts:[],assignments:[]
})})
afterEach(()=>{cleanup();vi.restoreAllMocks();session.user.is_superuser=true})
const empty:CertificateSetup={
 schema:'zog-station-certificate-setup-v1',read_only_status:true,
 owner_request_available:false,authorization:'operator-proposal-only',revision:0,
 updated_at:null,proposal:null,owner:{state:'unavailable',reason:'owner-interface-not-configured'},
 certificate:{health:'not_observed',expires_at:null,days_remaining:null,fingerprint_sha256:null,renewal:'not_observed'},
 lifecycle:{issued:'not_observed',delivered:'not_observed',nginx_loaded:'not_observed',browser_verified:'not_observed'},
 https_readiness:'not_verified',
}
test('never issues certificates on load and explains separate unknown stages',async()=>{
 const inspect=vi.spyOn(certificateApi,'inspect').mockResolvedValue(empty)
 const request=vi.spyOn(certificateApi,'request')
 render(<CertificatesPage/>)
 await screen.findByText(/Owner authorization:/)
 expect(inspect).toHaveBeenCalledTimes(1)
 expect(request).not.toHaveBeenCalled()
 expect(screen.getByText(/Loaded by nginx: not_observed/i)).toBeTruthy()
 expect(screen.getByText(/Externally verified HTTPS: not_observed/i)).toBeTruthy()
 expect(screen.getByText(/External HTTPS readiness: Not verified/i)).toBeTruthy()
 expect(screen.queryByText('Issue certificate')).toBeNull()
})
test('saves explicit ACME choice as proposal without implying host approval',async()=>{
 vi.spyOn(certificateApi,'inspect').mockResolvedValue(empty)
 const save=vi.spyOn(certificateApi,'save').mockResolvedValue({...empty,revision:1,proposal:{
   schema:'zog-certify-manage-v1',certificate_id:'station-web',hostnames:['station.example.org'],
   email:'ops@example.org',acme_directory:'https://acme.example.org/directory',
   challenge:'dns-01',dns_plugin:'dns-cloudflare'}})
 render(<CertificatesPage/>)
 await screen.findByText(/Owner authorization:/)
 fireEvent.change(screen.getByLabelText('Proposed HTTPS hostname'),{target:{value:'station.example.org'}})
 fireEvent.change(screen.getByLabelText('ACME contact email'),{target:{value:'ops@example.org'}})
 fireEvent.change(screen.getByLabelText('Explicit ACME directory URL'),{target:{value:'https://acme.example.org/directory'}})
 fireEvent.change(screen.getByLabelText('ACME challenge'),{target:{value:'dns-01'}})
 fireEvent.click(screen.getByRole('button',{name:'Save proposal (no issuance)'}))
 await waitFor(()=>expect(save).toHaveBeenCalledWith(0,expect.objectContaining({
   hostnames:['station.example.org'],challenge:'dns-01',dns_plugin:'dns-cloudflare'
 })))
 expect(await screen.findByRole('status')).toHaveProperty('textContent',expect.stringMatching(/not approved or issued/i))
})
test('status failure clears old observations and never exposes raw error',async()=>{
 vi.spyOn(certificateApi,'inspect').mockResolvedValueOnce(empty).mockRejectedValueOnce(new Error('secret from host owner'))
 render(<CertificatesPage/>)
 await screen.findByText(/Owner authorization:/)
 fireEvent.click(screen.getByText('Refresh certificate observations'))
 await screen.findByRole('alert')
 expect(screen.queryByText('secret from host owner')).toBeNull()
 expect(screen.getByText(/External HTTPS readiness: Unknown/)).toBeTruthy()
})
test('non-administrator cannot load certificate setup',()=>{
 session.user.is_superuser=false
 const read=vi.spyOn(certificateApi,'inspect')
 render(<CertificatesPage/>)
 expect(screen.getByText('Administrator access required.')).toBeTruthy()
 expect(read).not.toHaveBeenCalled()
})
