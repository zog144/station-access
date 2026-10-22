import { useEffect, useState } from 'react'
import { compilerApi, type CompilerOwnerStatus } from '../api'
import { useAuth } from '../auth/AuthProvider'

// No mutable state, owner identifier, AWS target, source path or endpoint
// selector appears in the frontend. Requests use the fixed backend config.
export function CompilerPage() {
  const { user } = useAuth()
  const [result, setResult] = useState<CompilerOwnerStatus | null>(null)
  const [state, setState] = useState<'loading' | 'observed' | 'unavailable'>('loading')
  const [busy, setBusy] = useState(false)

  async function refresh() {
    setBusy(true)
    try {
      const result = await compilerApi.status()
      setResult(result)
      setState('observed')
    } catch {
      setResult(null)
      setState('unavailable')
    } finally {
      setBusy(false)
    }
  }

  useEffect(() => { if (user?.is_superuser) void refresh() }, [user?.is_superuser])
  if (!user?.is_superuser) return <p>Administrator access required.</p>

  return <section>
    <h1>Compiler visibility</h1>
    <p>Read-only host-deploy ownership evidence. This does not establish live EC2, SSM or systemd compiler health.</p>
    <button disabled={busy} onClick={() => void refresh()}>{busy ? 'Refreshing…' : 'Refresh compiler observation'}</button>
    {state === 'loading' && <p>Inspecting compiler owner ledger…</p>}
    {state === 'unavailable' && <p role="alert">Compiler ownership observation is unavailable or not authorized. No fallback connection will be attempted.</p>}
    {state === 'observed' && result && <article className="card">
      <h2>Owner ledger observation</h2>
      <p>Ownership: {result.ownership}</p>
      <p>Compiler registration: {result.compiler}</p>
      <p>Evidence basis: {result.evidence_basis}</p>
      <p>Live host health: {result.live_host_health}</p>
    </article>}
    <p>No compiler commands, dispatch mutations, host target selection or AWS access are available on this page.</p>
  </section>
}
