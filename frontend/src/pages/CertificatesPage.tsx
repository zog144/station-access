import {useEffect,useState,type FormEvent} from 'react'
import {CertificateAssignmentsPanel} from './CertificateAssignmentsPanel'
import {certificateApi,type CertificateSetup,type CertificateProposal} from '../api'
import {useAuth} from '../auth/AuthProvider'

const UNKNOWN='Not observed'
const stages:[keyof CertificateSetup['lifecycle'],string][]=[
  ['issued','Certificate issued'],
  ['delivered','Delivered to TLS consumer'],
  ['nginx_loaded','Loaded by nginx'],
  ['browser_verified','Externally verified HTTPS'],
]

export function CertificatesPage(){
 const {user}=useAuth()
 const [state,setState]=useState<CertificateSetup|null>(null)
 const [hostname,setHostname]=useState(''),[email,setEmail]=useState('')
 const [directory,setDirectory]=useState('')
 const [challenge,setChallenge]=useState<'http-01'|'dns-01'>('http-01')
 const [provider,setProvider]=useState<'dns-cloudflare'>('dns-cloudflare')
 const [error,setError]=useState(''),[saved,setSaved]=useState(''),[busy,setBusy]=useState(false)

 function hydrate(data:CertificateSetup){
   setState(data)
   setHostname(data.proposal?.hostnames?.[0]??'')
   setEmail(data.proposal?.email??'')
   setDirectory(data.proposal?.acme_directory??'')
   setChallenge(data.proposal?.challenge??'http-01')
   setProvider('dns-cloudflare')
 }
 async function reload(){
   setBusy(true);setError('');setSaved('')
   try{hydrate(await certificateApi.inspect())}
   catch{setState(null);setError('Certificate setup information is unavailable.')}
   finally{setBusy(false)}
 }
 useEffect(()=>{if(user?.is_superuser)void reload()},[user?.is_superuser])
 async function save(event:FormEvent){
   event.preventDefault()
   if(!state)return
   setBusy(true);setError('');setSaved('')
   const proposal:CertificateProposal={
     schema:'zog-certify-manage-v1',certificate_id:'station-web',
     hostnames:[hostname],email,acme_directory:directory,challenge,
     dns_plugin:challenge==='dns-01'?provider:null,
   }
   try{hydrate(await certificateApi.save(state.revision,proposal))
     setSaved('Proposal saved. The host owner has not approved or issued a certificate.')}
   catch{setError('Could not save the proposal. Verify the hostname, ACME directory, challenge and revision; refresh if another administrator changed it.')}
   finally{setBusy(false)}
 }
 if(!user?.is_superuser)return <section><h1>HTTPS certificates</h1><p>Administrator access required.</p></section>
 return <section className="setup-page"><h1>HTTPS certificates</h1>
   <p>Configure a proposed station HTTPS hostname and ACME challenge. Certificate management runs in a separate controller-owned application. This page cannot issue certificates, control nginx, or choose provider credentials.</p>
   <p>During first boot, the host owner must select a restricted pre-HTTPS bootstrap path. This page does not enable a public HTTP fallback.</p>
   <button disabled={busy} onClick={()=>void reload()} type="button">{busy?'Loading…':'Refresh certificate observations'}</button>
   {error&&<p role="alert">{error}</p>}
   {saved&&<p role="status">{saved}</p>}
   <div className="setup-grid">
     <form className="setup-pane" onSubmit={save}>
       <h2>Operator proposal</h2>
       <p>Proposal only. The host owner must independently approve and bind the protected policy before preparation or issuance.</p>
       <label>Proposed HTTPS hostname<input required value={hostname} maxLength={253}
         placeholder="station.example.org" autoComplete="off"
         onChange={e=>setHostname(e.target.value)}/></label>
       <label>ACME contact email<input required type="email" value={email}
         onChange={e=>setEmail(e.target.value)} maxLength={254}/></label>
       <label>Explicit ACME directory URL<input required type="url" value={directory}
         placeholder="https://acme.example.org/directory"
         onChange={e=>setDirectory(e.target.value)} maxLength={2048}/></label>
       <label>ACME challenge<select value={challenge} onChange={e=>setChallenge(e.target.value as 'http-01'|'dns-01')}>
          <option value="http-01">HTTP-01 — requires approved port-80 challenge route</option>
          <option value="dns-01">DNS-01 — requires separately authorized provider token</option>
       </select></label>
       {challenge==='dns-01'&&<label>Approved DNS challenge plugin<select value={provider} onChange={e=>setProvider(e.target.value as 'dns-cloudflare')}>
          <option value="dns-cloudflare">Cloudflare DNS plugin</option>
       </select></label>}
       <p>No ACME account keys, DNS tokens, Certbot arguments or TLS private keys are accepted by this form.</p>
       <button type="submit" disabled={busy||!state}>Save proposal (no issuance)</button>
       <p>Revision: {state?.revision??'unavailable'}. No hostname or production ACME directory is guessed.</p>
     </form>
     <article className="setup-pane">
       <h2>Owner and certificate observations</h2>
       <p>Host-owner request binding: {state?.owner_request_available?'Available':'Not configured'}</p>
       <p>Owner authorization: {state?.authorization==='operator-proposal-only'?'Proposal only':'Not observed'}</p>
       <p>Certificate health: {state?.certificate.health??UNKNOWN}</p>
       <p>Certificate expiration: {state?.certificate.expires_at??UNKNOWN}</p>
       <p>Days remaining: {state?.certificate.days_remaining??UNKNOWN}</p>
       <p>Certificate fingerprint: {state?.certificate.fingerprint_sha256??UNKNOWN}</p>
       <p>Renewal result: {state?.certificate.renewal??UNKNOWN}</p>
       <h3>Independent readiness stages</h3>
       <ul>{stages.map(([name,label])=><li key={name}>{label}: {state?.lifecycle[name]??UNKNOWN}</li>)}</ul>
       <p><strong>External HTTPS readiness: {state?.https_readiness==='not_verified'?'Not verified':'Unknown'}</strong></p>
       <p>Only host-deploy can request authorized preparation, issuance and reconciliation, publish certificate generations, reload nginx or verify the public endpoint. These functions are not yet connected to station-access.</p>
     </article>
   </div>
   <CertificateAssignmentsPanel proposal={state?.proposal??null}/>
 </section>
}
