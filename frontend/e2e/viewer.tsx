import { createRoot } from 'react-dom/client'
import { MemoryRouter, Link, Route, Routes } from 'react-router-dom'
import { api } from '../src/api'
import { VncPage } from '../src/pages/VncPage'
import { VncSessionProvider } from '../src/vnc/VncSessionProvider'
import { PersistentVncSessions } from '../src/vnc/PersistentVncSessions'
import '../src/styles.css'

// Browser-only probe. The source noVNC iframe is a same-origin local test page,
// never a fake RFB service, grant authority, or real Workspace connection.
api.vncGrant = async () => ({
  token: 'local-e2e-only', expires_at: '2099-01-01T00:00:00Z',
  novnc_url: '/e2e/fake-novnc.html?resize=scale',
})
function TestNavigation() {
  return <nav aria-label="Browser test navigation" style={{position:'fixed',zIndex:40,top:0,left:0}}>
    <Link to="/vnc/one">Workspace one</Link> <Link to="/applications">Away</Link>
    <Link to="/vnc/two">Workspace two</Link>
  </nav>
}
createRoot(document.getElementById('root')!).render(
  <MemoryRouter initialEntries={['/vnc/one']}><VncSessionProvider>
    <TestNavigation />
    <Routes>
      <Route path="/vnc/:workspaceId" element={<VncPage />} />
      <Route path="/applications" element={<p data-testid="away">Navigated away without unmounting the session</p>} />
    </Routes>
    <PersistentVncSessions />
  </VncSessionProvider></MemoryRouter>
)
