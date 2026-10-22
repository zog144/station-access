// @vitest-environment jsdom
import {cleanup,fireEvent,render,screen,waitFor} from '@testing-library/react'
import {afterEach,expect,test,vi} from 'vitest'
import {DnsReconciliationPanel} from './DnsReconciliationPreview'
import {api,type DnsReconciliationPreview} from '../api'

vi.mock('../api',()=>({api:{dnsReconciliationPreview:vi.fn()}}))
afterEach(()=>{cleanup();vi.clearAllMocks()})

const preview:DnsReconciliationPreview={
 schema:1,read_only:true,owner_id:'owner',binding_id:'one',resource_id:'host',
 provider:'cloudflare',zone_name:'example.org',hostname:'compiler.hosts.example.org',
 connection_revision:2,binding_revision:3,desired_revision:4,
 desired:{name:'compiler.hosts.example.org',address:'8.8.8.8',ttl:300,type:'A',proxied:false},
 last_applied:null,outcome:'candidate',proposed_action:'create',
 reason:'create-candidate',authorized:true,observed_count:0,observed:[],
}

test('manual preview uses primary route and never offers a dispatch action',async()=>{
 vi.mocked(api.dnsReconciliationPreview).mockResolvedValue({preview})
 render(<DnsReconciliationPanel hostId="host" revision={4}/>)
 expect(api.dnsReconciliationPreview).not.toHaveBeenCalled()
 fireEvent.click(screen.getByText('Inspect DNS decision'))
 await waitFor(()=>expect(api.dnsReconciliationPreview).toHaveBeenCalledWith('host',undefined))
 expect(screen.getByText('Possible change')).toBeTruthy()
 expect(screen.getByText('create (proposal only)')).toBeTruthy()
 expect(screen.getByText(/Read-only, non-binding/)).toBeTruthy()
 expect(screen.queryByText('Apply DNS change')).toBeNull()
})

test('additional destination is scoped and unchanged provider inventory is not inferred',async()=>{
 vi.mocked(api.dnsReconciliationPreview).mockResolvedValue({preview:{
  ...preview,provider:'porkbun',observed_count:null,outcome:'blocked',
  proposed_action:'none',reason:'provider-transient',authorized:true
 }})
 render(<DnsReconciliationPanel hostId="host" bindingId="additional" revision={1}/>)
 fireEvent.click(screen.getByText('Inspect DNS decision'))
 await waitFor(()=>expect(api.dnsReconciliationPreview).toHaveBeenCalledWith('host','additional'))
 expect(screen.getByText('Blocked')).toBeTruthy()
 expect(screen.getByText(/Not checked — absence is not proved/)).toBeTruthy()
})

test('failed inspection does not show an old candidate or leak provider error',async()=>{
 vi.mocked(api.dnsReconciliationPreview).mockResolvedValueOnce({preview})
  .mockRejectedValueOnce(new Error('SECRET PROVIDER CREDENTIAL'))
 render(<DnsReconciliationPanel hostId="host" revision={4}/>)
 fireEvent.click(screen.getByText('Inspect DNS decision'))
 await screen.findByText('Possible change')
 fireEvent.click(screen.getByText('Inspect DNS decision'))
 await screen.findByRole('alert')
 expect(screen.queryByText('Possible change')).toBeNull()
 expect(screen.queryByText(/SECRET PROVIDER CREDENTIAL/)).toBeNull()
})

test('unknown schema never becomes an actionable result',async()=>{
 vi.mocked(api.dnsReconciliationPreview).mockResolvedValue({preview:{...preview,read_only:false} as unknown as DnsReconciliationPreview})
 render(<DnsReconciliationPanel hostId="host" revision={4}/>)
 fireEvent.click(screen.getByText('Inspect DNS decision'))
 await screen.findByRole('alert')
 expect(screen.queryByText('Possible change')).toBeNull()
})
