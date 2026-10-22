import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { api, type ApplicationSoftwareInspection } from '../api'

function identity(value: string | null) {
  return value ? value.slice(0, 20) + '…' : 'Unknown identity'
}

export function ApplicationSoftwarePage() {
  const [snapshot, setSnapshot] = useState<ApplicationSoftwareInspection | null>(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)

  const refresh = () => {
    setLoading(true)
    setError('')
    api.applicationSoftware().then(data => setSnapshot(data))
      .catch(reason => { setError(String(reason)); setSnapshot(null) })
      .finally(() => setLoading(false))
  }

  useEffect(() => { refresh() }, [])
  return <section>
    <h1>Application software</h1>
    <p>Immutable software publications from image-build and the application views selected by box-control. Read-only administrator inspection.</p>
    <p>Manifest verification is not proof that software is mounted or running. Launch readiness is an advisory controller preflight; actual mounts are <strong>not probed</strong>.</p>
    <button onClick={refresh} disabled={loading}>Refresh inspection</button>
    {loading && <p role="status">Inspecting immutable software…</p>}
    {error && <p className="error" role="alert">{error}</p>}
    {snapshot && <>
      {snapshot.store === 'unavailable' && <p role="status">No inspectable application-software store is available on this controller. This does not mean no software has ever been published.</p>}
      {snapshot.views_truncated && <p role="status">View listing was capped; additional publications may exist. Selected views are retained in the inspection.</p>}
      {snapshot.artifacts_truncated && <p role="status">Artifact detail listing was capped. No additional artifact details are inferred.</p>}
      {snapshot.views.length === 0 && <p>No published or selected application views were found in this inspection.</p>}
      <div className="cards">
        {snapshot.views.map((view, index) => <article className="card" key={view.view ?? index}>
          <h2>{view.application ?? 'Unidentified application'}{view.selected ? ' · Selected' : ' · Published'}</h2>
          {view.selected && view.application && <p><Link to={`/application-software/applications/${encodeURIComponent(view.application)}`}>Inspect selected software →</Link></p>}
          <p><strong>{view.state === 'verified' ? 'Verified publication' : 'Unavailable or unverified publication'}</strong></p>
          <p>View: <code title={view.view ?? ''}>{identity(view.view)}</code></p>
          <p>Profile: {view.profile ?? 'Unknown'} · Entries: {view.composition_count ?? 'Unknown'} · Retained runtime bindings: {view.runtime_count}</p>
          <p>Launch preflight: <strong>{view.launch_readiness}</strong> (advisory) · Actual mount observation: not probed</p>
          {view.artifacts.length > 0 ? <div>
            <h3>Referenced immutable artifacts</h3>
            {view.artifacts.map(artifactId => {
              const artifact = snapshot.artifacts.find(item => item.artifact === artifactId)
              return <div key={artifactId}>
                <p><code title={artifactId}>{identity(artifactId)}</code>{artifact ? <> · {artifact.revision} · {artifact.architecture}</> : ' · Details unavailable'}</p>
                {artifact && <>
                  <p>Source identities: {artifact.source_count} · Provenance: {artifact.provenance_state} · License evidence: {artifact.license_state} ({artifact.notice_count} notice files)</p>
                  {artifact.https_sources.length > 0 && <p>HTTPS source links: {artifact.https_sources.map((source, i) => <span key={source.sha256 + i}>
                    {i > 0 ? ' · ' : ''}<a href={source.url} target="_blank" rel="noopener noreferrer">{source.name || 'Source'}</a>
                  </span>)}</p>}
                </>}
              </div>
            })}
          </div> : <p>No verified artifact references available.</p>}
        </article>)}
      </div>
      <p>Notice files being recorded does not establish a reviewed license expression, and a prior runtime binding does not establish a currently mounted filesystem.</p>
    </>}
  </section>
}
