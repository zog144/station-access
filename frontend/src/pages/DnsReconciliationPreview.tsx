import {useEffect,useState} from 'react'
import {api,type DnsReconciliationPreview as Preview} from '../api'

const readable=(reason:string)=>reason.replaceAll('-', ' ')

/** Manual, read-only inspection; never an actionable DNS approval. */
export function DnsReconciliationPanel({hostId,bindingId,revision}:{
 hostId:string;bindingId?:string;revision:number
}) {
 const [value,setValue]=useState<Preview|null>(null)
 const [error,setError]=useState('')
 const [busy,setBusy]=useState(false)
 useEffect(()=>{setValue(null);setError('')},[hostId,bindingId,revision])
 async function inspect(){
  setBusy(true);setError('');setValue(null)
  try{
   const answer=await api.dnsReconciliationPreview(hostId,bindingId)
   if(answer.preview.schema!==1 || answer.preview.read_only!==true)throw Error('Unsupported read-only DNS preview')
   setValue(answer.preview)
  }catch{setError('DNS inspection is unavailable. Check controller, host verification and destination status.')}
  finally{setBusy(false)}
 }
 return <details aria-label="DNS reconciliation inspection" className="host-dns-preview">
  <summary>Reconciliation preview</summary>
  <p>This inspection only reads the central DNS ledger, verified host evidence and provider inventory.
   It does not reserve, publish, unpublish or approve any change.</p>
  <button type="button" disabled={busy} onClick={()=>void inspect()}>{busy?'Inspecting DNS…':'Inspect DNS decision'}</button>
  {error&&<p role="alert">{error}</p>}
  {value&&<section aria-label="DNS preview result">
   <p><strong>{value.outcome==='no-op'?'No change':value.outcome==='candidate'?'Possible change':'Blocked'}</strong>
    {' · '}{readable(value.reason)}</p>
   <dl className="host-details">
    <dt>DNS provider</dt><dd>{value.provider}</dd>
    <dt>Hostname</dt><dd>{value.hostname ?? 'No managed hostname'}</dd>
    <dt>Decision</dt><dd>{value.proposed_action==='none'?'No action':value.proposed_action+' (proposal only)'}</dd>
    <dt>Inspection authorization</dt><dd>{value.authorized===null?'Not evaluated':value.authorized?'Read authorized':'Denied'}</dd>
    <dt>Desired record</dt><dd>{value.desired?
      `${value.desired.address} · TTL ${value.desired.ttl}s`:'Explicitly unpublished or no desired record'}</dd>
    <dt>Last applied</dt><dd>{value.last_applied?
      `${value.last_applied.address} · TTL ${value.last_applied.ttl}s`:'No owned record recorded'}</dd>
    <dt>Desired revision</dt><dd>{value.desired_revision}</dd>
    <dt>Provider inventory</dt><dd>{value.observed_count===null?
      'Not checked — absence is not proved':`${value.observed_count} matching hostname records observed`}</dd>
   </dl>
   {value.observed.length>0&&<div><strong>Provider records (up to 20)</strong>
    <ul>{value.observed.map((record,i)=><li key={record.record_id+'-'+i}>
     {record.type} · {record.address??'No A address'} · TTL {record.ttl??'unknown'} ·
     {' '}{record.matches_last_applied?'Matches retained owned record':'Not an exact owned match'}
    </li>)}</ul>
   </div>}
   {value.observed_count!==null&&value.observed_count>value.observed.length&&
    <p>Additional records omitted by the bounded provider preview.</p>}
   <p><strong>Read-only, non-binding.</strong> Any later DNS change needs a separate reviewed
    operation and fresh authority, ownership and provider checks. Provider inventory
    does not prove public DNS propagation.</p>
  </section>}
 </details>
}
