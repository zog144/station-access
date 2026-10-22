import {useEffect,useState,type FormEvent} from 'react'
import {certificateAssignmentApi,type CertificateAssignmentData,type CertificatePolicy,type CertificateAssignmentRequest} from '../api'

/** Reviewed signed certificate intent; never invokes Certbot or nginx. */
export function CertificateAssignmentsPanel({proposal}:{proposal:CertificatePolicy|null}){
  const [state,setState]=useState<CertificateAssignmentData|null>(null)
  const [origin,setOrigin]=useState<'managed'|'local'>('local')
  const [hostId,setHostId]=useState('')
  const [bindingId,setBindingId]=useState('')
  const [hostname,setHostname]=useState('')
  const [days,setDays]=useState(7)
  const [pending,setPending]=useState<CertificateAssignmentRequest|null>(null)
  const [busy,setBusy]=useState(false)
  const [error,setError]=useState('')
  const [message,setMessage]=useState('')
  const binding=state?.bindings.find(item=>item.binding_id===bindingId)
  const host=state?.hosts.find(item=>item.host_id===hostId)
  async function refresh(){
    setBusy(true);setError('');setMessage('')
    try{setState(await certificateAssignmentApi.list())}
    catch{setState(null);setError('Certificate assignment records are unavailable.')}
    finally{setBusy(false)}
  }
  useEffect(()=>{void refresh()},[])
  async function send(value:CertificateAssignmentRequest){
    setBusy(true);setError('');setMessage('')
    try{
      await certificateAssignmentApi.decide(value)
      setPending(null)
      setState(await certificateAssignmentApi.list())
      setMessage(value.action==='revoke'?'Revocation receipt recorded. The host owner must observe and enforce it.':
        'Signed station assignment recorded. The root-controlled host owner must still independently approve and install its issuer policy.')
    }catch{
      setError('Assignment unavailable or conflicting. Inspect the host identity, DNS record, credential revision, signer and prior operation. Retry retains the same operation ID.')
    }finally{setBusy(false)}
  }
  function approve(event:FormEvent){
    event.preventDefault()
    if(pending){void send(pending);return}
    if(!proposal||!binding||!hostname||!Number.isInteger(days)||days<1||days>30||
       (origin==='managed'&&!hostId))return
    const value:CertificateAssignmentRequest={
      schema:'zog-certificate-assignment-v1',action:'approve',
      origin,host_id:origin==='managed'?hostId:null,
      binding_id:binding.binding_id,
      credential_id:binding.credential_id,credential_revision:binding.credential_revision,
      zone_id:binding.zone_id,zone_name:binding.zone_name,
      policy:{...proposal,hostnames:[hostname]},
      expires_at:new Date(Date.now()+days*86400000).toISOString().slice(0,19)+'Z',
      operation_id:crypto.randomUUID(),expected_revision:0,
    }
    setPending(value);void send(value)
  }
  function revoke(item:CertificateAssignmentData['assignments'][number]){
    // Persisted policy is the producer-validated canonical certificate
    // proposal, independent of managed/local signed envelope serialization.
    // Preserve the exact original binding rather than trusting a re-typed
    // browser version. A new operation ID is durable and cannot replay issue.
    const value:CertificateAssignmentRequest={
      schema:'zog-certificate-assignment-v1',action:'revoke',
      origin:item.origin,host_id:item.host_id,
      binding_id:item.binding_id,credential_id:item.credential_id,
      credential_revision:item.credential_revision,
      zone_id:item.zone_id,zone_name:item.zone_name,
      policy:item.policy,expires_at:item.expires_at,
      expected_revision:item.revision,operation_id:crypto.randomUUID(),
    }
    setPending(value);void send(value)
  }
  return <section aria-label="Certificate assignments" className="setup-page">
    <h2>Versioned certificate assignments</h2>
    <p>Approve an exact local or managed DNS/hostname assignment for the host owner.
      Receipts are signed and expire; neither approval nor retrieval starts an issuer,
      installs a DNS token, changes nginx or establishes HTTPS readiness.</p>
    <button type="button" disabled={busy} onClick={()=>void refresh()}>Refresh assignments</button>
    {error&&<p role="alert">{error}</p>}{message&&<p role="status">{message}</p>}
    <div className="setup-grid">
      <form className="setup-pane" onSubmit={approve}>
        <h3>Approve bounded hostname intent</h3>
        <label>Authority origin<select value={origin} disabled={!!pending||busy}
          onChange={e=>{setOrigin(e.target.value as typeof origin);setHostId('');setHostname('')}}>
          <option value="local">Standalone local station</option>
          <option value="managed">Command-center managed host</option>
        </select></label>
        {origin==='managed'&&<label>Approved managed installation<select
          required value={hostId} disabled={!!pending||busy}
          onChange={e=>{setHostId(e.target.value);setHostname('')}}>
          <option value="">Choose a managed host</option>
          {state?.hosts.map(item=><option key={item.host_id} value={item.host_id}>
            {item.label||item.host_id} — {item.host_id}
          </option>)}
        </select></label>}
        <label>Reviewed DNS zone binding<select required value={bindingId}
          disabled={!!pending||busy} onChange={e=>{setBindingId(e.target.value);setHostname('')}}>
          <option value="">Choose a saved binding</option>
          {state?.bindings.map(item=><option value={item.binding_id} key={item.binding_id}>
            {item.prefix} · {item.zone_name} · credential revision {item.credential_revision}
          </option>)}
        </select></label>
        {binding&&<p>Zone: {binding.zone_name} · Binding: {binding.binding_id}. The server rechecks
          this exact zone, credential identity and revision before approval.</p>}
        {origin==='managed'&&host?.dns_names.length?
          <label>Confirmed host DNS name<select required value={hostname}
            disabled={!!pending||busy} onChange={e=>setHostname(e.target.value)}>
            <option value="">Choose a synchronized name</option>
            {host.dns_names.map(name=><option key={name} value={name}>{name}</option>)}
          </select></label>:
          <label>Exact hostname<input required autoComplete="off" maxLength={253}
            value={hostname} disabled={!!pending||busy} onChange={e=>setHostname(e.target.value)}
            placeholder="local.extra.example.org"/></label>}
        <label>Authority lifetime (days, maximum 30)<input required type="number" min={1} max={30}
          disabled={!!pending||busy} value={days} onChange={e=>setDays(Number(e.target.value))}/></label>
        <p>Issuer policy: {proposal?'Explicit proposal saved':'Save a proposed ACME policy above before assigning.'}
          {' '}Certificate ID and local consumer are fixed by the service.</p>
        <button type="submit" disabled={!proposal||!binding||!hostname||busy||
          (origin==='managed'&&!hostId)}>
          {pending?'Retry exact prior operation':'Approve signed assignment (no issuance)'}
        </button>
        {pending&&<button type="button" disabled={busy} onClick={()=>setPending(null)}>
          Discard retry / start new review</button>}
        <p>Root-control must verify the signed receipt and install its own protected policy.
          An absent signer, stale DNS or missing Cloudflare zone access blocks approval.</p>
      </form>
      <article className="setup-pane">
        <h3>Recorded decisions</h3>
        {state?.assignments.length===0&&<p>No assignment recorded. There is no presumed hostname.</p>}
        <ul>{state?.assignments.map(item=><li key={item.assignment_id}>
          <strong>{item.hostname}</strong> — {item.origin} · {item.state} ·
          revision {item.revision} · expires {item.expires_at} ·
          consumer {item.consumer}
          {item.state==='approved'&&<button type="button" disabled={busy||!!pending}
            onClick={()=>revoke(item)}>Revoke assignment</button>}
        </li>)}</ul>
        <p>Revocation produces a newer signed statement. Disconnected installations
          must expire/fence cached authority under their separately trusted host-owner rules.</p>
      </article>
    </div>
  </section>
}
