import {useState} from 'react'
import {setupApi, type ApplicationProgressView} from '../api'

const stateLabels:Record<string,string>={
  waiting:'Waiting',running:'In progress',succeeded:'Phase succeeded',
  blocked:'Blocked',failed:'Failed',cancelled:'Cancelled',
  uncertain:'Uncertain — needs reconciliation',unknown:'Unknown',
}
function stageLabel(item:ApplicationProgressView['items'][number]){
  if(item.build_job_id)return 'Unassociated build command'
  return item.application ? 'Application runtime: '+item.application : 'Unidentified runtime'
}

export function ApplicationProgressPanel(){
  const [data,setData]=useState<ApplicationProgressView|null>(null)
  const [checking,setChecking]=useState(false)
  const [error,setError]=useState('')
  const [pages,setPages]=useState(0)
  async function observe(afterBuild?:string|null,afterRuntime?:string|null){
    if(checking)return
    setChecking(true);setError('')
    try{
      const value=await setupApi.applicationProgress(afterBuild??null,afterRuntime??null)
      setData(value)
      setPages(afterBuild||afterRuntime ? pages+1 : 1)
    }catch{
      setData(null);setPages(0)
      setError('The authenticated progress observation is unavailable.')
    }finally{setChecking(false)}
  }
  const page=data?.page
  const hasMore=Boolean(page&&(page.build_has_more||page.runtime_has_more))
  return <section id="application-progress" aria-label="Application installation progress">
    <h2>Application build and runtime progress</h2>
    <p>Read-only controller observations. Application installation, verified software
      publication, graphical rendering and a logged-in local seat are separate
      authorities. No build or login action starts from this panel.</p>
    <button type="button" disabled={checking} onClick={()=>void observe()}>
      {checking?'Checking controller…':'Refresh controller progress'}
    </button>
    {error&&<p role="alert">{error}</p>}
    {!data&&!error&&<p>Not checked. During first boot the local console remains
      available even when this website has not started.</p>}
    {data?.availability==='unavailable'&&<p role="status">Controller progress unavailable.
      This does not mean the build completed or failed. Verify the protected observer
      connection before drawing conclusions.</p>}
    {data?.availability==='observed'&&<>
      <p role="status">Controller observation at {data.observed_at}.
        {' '}This is page {pages} of independently sampled records, not an atomic installation checkpoint.</p>
      <p>Installation completion: not independently observed. Software publication:
        not independently observed. No remaining time or percentage is estimated.</p>
      <h3>Controller records</h3>
      {data.items.length===0&&<p>No controller records on this page.
        This does not prove that graphical applications were never requested.</p>}
      <ul>{data.items.map(item=><li key={item.operation_id}>
        <strong>{stageLabel(item)}</strong> — {item.phase}:
        {' '}{stateLabels[item.state]??'Unknown'}. {item.message}
        {item.build_job_id&&<p>Build job: <code>{item.build_job_id}</code>.
          {' '}An image-build attempt and published application have not been associated.</p>}
        {item.runtime_id&&<p>Controller runtime: <code>{item.runtime_id}</code>.
          {' '}Remote workspace activity is not a physical console login.</p>}
        {item.selected_software_id&&<p>Selected view recorded: <code>{item.selected_software_id}</code>.
          {' '}The controller observation does not establish publication or local display readiness.</p>}
      </li>)}</ul>
      {hasMore&&<button type="button" disabled={checking||
        Boolean(page?.build_has_more&&!page?.next_build)||
        Boolean(page?.runtime_has_more&&!page?.next_runtime)}
        onClick={()=>void observe(page?.build_has_more?page?.next_build:null,
                                   page?.runtime_has_more?page?.next_runtime:null)}>
        Next bounded page
      </button>}
      <p>Missing or pruned jobs, interrupted operations and previous-boot observations
        must be reconciled with the producer. A successful command is not a
        published Firefox, X11 or greetd installation.</p>
      <h3>Local login and graphical seat</h3>
      {data.local_session.availability==='observed'&&data.local_session.capabilities?<>
        <p>Local seat support: {data.local_session.capabilities.supported?'Reported supported':'Not implemented'}.
          Physical seat: {data.local_session.capabilities.physical_seat}.
          Virtual seat: {data.local_session.capabilities.virtual_seat}.
          Login role: {data.local_session.capabilities.login_role}.</p>
        <p>Existing noVNC/TurboVNC workspaces are remote sessions and cannot
          authenticate a local greetd/PAM seat.</p>
      </>:<p>Local-seat capability unavailable; no greetd, PAM or physical
        console readiness is inferred. Remote VNC workspaces remain separate.</p>}
    </>}
    <p>Optional graphical applications are not a prerequisite for a healthy headless
      installation. Only the host-install request authority can say a graphical
      application was explicitly <em>not requested</em>.</p>
  </section>
}
