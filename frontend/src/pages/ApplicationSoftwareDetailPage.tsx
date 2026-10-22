import { useEffect, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { api, type ApplicationSoftwareDetail } from '../api'

export function ApplicationSoftwareDetailPage() {
  const { applicationName = '' } = useParams()
  const [detail, setDetail] = useState<ApplicationSoftwareDetail | null>(null)
  const [error, setError] = useState('')
  useEffect(() => {
    let active = true
    setDetail(null)
    setError('')
    api.applicationSoftwareDetail(applicationName)
      .then(r => { if (active) setDetail(r.application_software) })
      .catch(e => { if (active) setError(String(e)) })
    return () => { active = false }
  }, [applicationName])
  return <section>
    <Link to="/application-software">← Application software</Link>
    <h1>Application software: {applicationName}</h1>
    <p>Read-only current selection, not a historical launch snapshot or an observation of live mounts.</p>
    {error && <p role="alert" className="error">{error}</p>}
    {!detail && !error && <p>Inspecting current software selection…</p>}
    {detail && <>
      <dl>
        <dt>Publication</dt><dd>{detail.state === 'verified' ? 'Verified immutable publication' : detail.state === 'not-selected' ? 'No software view selected' : 'Unavailable or unverified'}</dd>
        <dt>Selected view</dt><dd>{detail.view ? <code>{detail.view}</code> : 'Unavailable'}</dd>
        <dt>Profile</dt><dd>{detail.profile ?? 'Unknown'}</dd>
        <dt>View contract</dt><dd>{detail.view_contract ?? 'Unknown'}</dd>
        <dt>Composed entries</dt><dd>{detail.composition_count ?? 'Unknown'}</dd>
        <dt>Launch preflight</dt><dd>{detail.launch_readiness} (advisory only)</dd>
        <dt>Live mount verification</dt><dd>Not probed</dd>
      </dl>
      {detail.artifacts.map(artifact => <article key={artifact.artifact} className="card">
        <h2>Immutable artifact</h2>
        <p><code>{artifact.artifact}</code></p>
        <p>Revision: {artifact.revision} · Architecture: {artifact.architecture}</p>
        <h3>Compatibility requirements</h3>
        <p>Contract: {artifact.compatibility.mount_contract} · Architecture: {artifact.compatibility.architecture}</p>
        <p>Python: {artifact.compatibility.python ? `${artifact.compatibility.python.implementation} ${artifact.compatibility.python.version} · ${artifact.compatibility.python.soabi}` : 'No Python requirement recorded'}</p>
        <p>Libraries: {artifact.compatibility.libraries.length ? artifact.compatibility.libraries.join(', ') : 'None declared'}</p>
        <h3>Source &amp; license evidence</h3>
        <p>Sources recorded: {artifact.source_count} · Provenance: {artifact.provenance_state}</p>
        {artifact.https_sources.length ? <ul>{artifact.https_sources.map((source, i) =>
          <li key={source.sha256 + i}><a href={source.url} target="_blank" rel="noopener noreferrer">{source.name || 'Upstream source'}</a> · SHA-256 <code>{source.sha256}</code></li>
        )}</ul> : <p>No publishable HTTPS source links available.</p>}
        <p>License evidence: {artifact.license_state} · Notice files: {artifact.notice_count}</p>
        {artifact.notice_files.length > 0 && <ul>{artifact.notice_files.map(file => <li key={file}><code>{file}</code></li>)}</ul>}
        <p>Recorded notices are not a verified SPDX expression or a complete license review. Raw license file contents are not exposed by this view.</p>
      </article>)}
    </>}
  </section>
}
