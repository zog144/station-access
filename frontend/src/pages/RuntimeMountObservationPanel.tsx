import { useEffect, useState } from 'react'
import { api, type RuntimeMountEntry, type RuntimeMountObservation, type RuntimeMountProgram } from '../api'
import { useAuth } from '../auth/AuthProvider'

const statusLabel: Record<string, string> = {
  observed: 'Observed', partial: 'Partial / inconclusive',
  absent: 'Absent', 'previous-boot': 'Previous boot',
  'identity-unavailable': 'Identity unavailable',
  'changed-during-read': 'Changed during read',
  'integrity-fault': 'Integrity fault',
  unavailable: 'Unavailable', 'legacy-unrecorded': 'Legacy: not recorded',
}

function MountTable({ mounts }: { mounts: RuntimeMountEntry[] }) {
  return mounts.length ? <table>
    <thead><tr>
      <th scope="col">Destination</th>
      <th scope="col">Kind</th>
      <th scope="col">Expected access</th>
      <th scope="col">Kernel presence</th>
      <th scope="col">Observed access</th>
      <th scope="col">Backing identity</th>
    </tr></thead>
    <tbody>{mounts.map((mount, i) => <tr key={mount.destination + i}>
      <td><code>{mount.destination}</code></td>
      <td>{mount.kind}</td>
      <td>{mount.expected_access}</td>
      <td>{mount.observed_presence}</td>
      <td>{mount.observed_access}</td>
      <td>{mount.backing_identity}</td>
    </tr>)}</tbody>
  </table> : <p>No mount entries were returned for this observation. This does not verify absence or health.</p>
}

function ProgramMounts({program}: {program: RuntimeMountProgram}) {
  const observedNamespaces = program.mount_namespaces
  return <article className="card">
    <h3>{program.program}: {statusLabel[program.status] ?? program.status}</h3>
    {program.truncated && <p role="status">Observation truncated; unreported mounts are unknown.</p>}
    {program.multiple_mount_namespaces && <p role="status">Processes occupy multiple mount namespaces. Each is shown separately.</p>}
    {observedNamespaces.length ? observedNamespaces.map((namespace, i) => <section key={namespace.mount_namespace + i}>
      <h4>Mount namespace <code>{namespace.mount_namespace}</code></h4>
      {namespace.truncated && <p>Namespace observation truncated; unseen mounts remain unknown.</p>}
      <MountTable mounts={namespace.mounts}/>
    </section>) : program.mounts.length ? <MountTable mounts={program.mounts}/> :
      <p>Kernel mount evidence is unavailable for this service. Its saved launch record is retained separately.</p>}
  </article>
}

export function RuntimeMountObservationPanel({runtimeId}: {runtimeId: string}) {
  const { user } = useAuth()
  const [observation, setObservation] = useState<RuntimeMountObservation | null>(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    // Never reuse a snapshot from a different immutable runtime identity.
    setObservation(null)
    setError('')
    setLoading(false)
  }, [runtimeId])

  if (!user?.is_superuser) return null

  const refresh = () => {
    setLoading(true)
    setObservation(null)
    setError('')
    api.runtimeMounts(runtimeId)
      .then(({observation: result}) => {
        if (result.runtime_id !== runtimeId || result.schema !== 'zog-runtime-mount-observation-v1')
          throw new Error('Unexpected runtime observation identity or contract')
        setObservation(result)
      })
      .catch(() => setError('Kernel mount observation is unavailable. No mount health is inferred.'))
      .finally(() => setLoading(false))
  }

  return <section>
    <h2>Observed mounts</h2>
    <p>Administrator-only, on-demand read of kernel mount namespaces. Historical launch evidence above remains unchanged.</p>
    <button type="button" onClick={refresh} disabled={loading}>
      {loading ? 'Inspecting mounts…' : 'Refresh observation'}
    </button>
    {!observation && !error && !loading && <p>Not probed in this page session.</p>}
    {loading && <p role="status">Reading an identity-checked, non-atomic kernel snapshot…</p>}
    {error && <p role="alert">{error}</p>}
    {observation && <>
      <p><strong>Overall result: {statusLabel[observation.status] ?? observation.status}</strong></p>
      <p>Observed at: <time dateTime={new Date(observation.observed_at * 1000).toISOString()}>
        {new Date(observation.observed_at * 1000).toLocaleString()}</time>. Evidence: kernel mount namespace; non-atomic snapshot.
      </p>
      {observation.truncated && <p role="status">Observation truncated: unseen destinations remain unknown.</p>}
      {observation.status === 'integrity-fault' && <p role="alert">An observed mount or execution identity differs from the persisted launch expectation. This view never repairs or restarts services.</p>}
      {observation.status === 'partial' && <p>Some mount or backing identities could not be verified. Partial is not a healthy verdict.</p>}
      {observation.programs.length ? observation.programs.map((program, i) =>
        <ProgramMounts key={program.program + i} program={program}/>) :
        <p>No program observations were returned; no active mount state is established.</p>}
    </>}
  </section>
}
