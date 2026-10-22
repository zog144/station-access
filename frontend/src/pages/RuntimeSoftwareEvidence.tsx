import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { api, type ApplicationSoftwareDetail, type Runtime } from '../api'
import { useAuth } from '../auth/AuthProvider'

export function RuntimeSoftwareEvidence({runtime}: {runtime: Runtime}) {
  const { user } = useAuth()
  const [selection, setSelection] = useState<ApplicationSoftwareDetail | null>(null)
  const [selectionError, setSelectionError] = useState(false)
  useEffect(() => {
    let active = true
    setSelection(null)
    setSelectionError(false)
    if (user?.is_superuser) {
      api.applicationSoftwareDetail(runtime.application_name)
        .then(r => { if (active) setSelection(r.application_software) })
        .catch(() => { if (active) setSelectionError(true) })
    }
    return () => { active = false }
  }, [runtime.application_name, user?.is_superuser])
  const launched = runtime.software
  return <section>
    <h2>Software recorded at launch</h2>
    <p>Immutable expected-launched controller record; it contains no kernel mount observation. Administrators can inspect a separate on-demand snapshot below.</p>
    <dl>
      <dt>Launch rootfs generation</dt><dd>{runtime.generation ?? 'Unavailable'}</dd>
      <dt>Launched software view</dt><dd>{launched?.view ? <code>{launched.view}</code> : 'No software view recorded'}</dd>
      <dt>Binding digest</dt><dd>{launched?.binding_digest ? <code>{launched.binding_digest}</code> : 'Not recorded'}</dd>
      <dt>Manifest digest</dt><dd>{launched?.manifest_digest ? <code>{launched.manifest_digest}</code> : 'Not recorded'}</dd>
    </dl>
    {launched?.artifacts.length ? <>
      <h3>Bound immutable artifacts</h3>
      <ul>{launched.artifacts.map(id => <li key={id}><code>{id}</code></li>)}</ul>
    </> : <p>No artifact identities recorded at launch.</p>}
    {user?.is_superuser && <>
      <h3>Current application selection (separate snapshot)</h3>
      {selection && <>
        <p>Current view: {selection.view ? <code>{selection.view}</code> : 'Not selected'} · {selection.state}</p>
        {launched?.view && <p>{launched.view === selection.view
          ? 'Launched view matches the current selection identity.'
          : 'Launched view differs from the current selection; historical software evidence is retained.'}</p>}
        <p><Link to={`/application-software/applications/${encodeURIComponent(runtime.application_name)}`}>Current software and source details →</Link></p>
      </>}
      {selectionError && <p>Current application selection could not be inspected; historical launch evidence is unchanged.</p>}
      {!selection && !selectionError && <p>Inspecting current selection…</p>}
    </>}
  </section>
}
