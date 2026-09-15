import { useEffect, useState } from 'react'
import Dashboard from './pages/Dashboard.jsx'
import Upload from './pages/Upload.jsx'
import Result from './pages/Result.jsx'

const PAGES = ['dashboard', 'upload', 'result']

function parseHash() {
  const h = window.location.hash.replace(/^#\/?/, '')
  const [page, ...rest] = h.split('/')
  return {
    page: PAGES.includes(page) ? page : 'dashboard',
    param: rest.join('/'),
  }
}

/** Hash routing, kept rather than swapped for a router library.
 *  The URLs (#/dashboard, #/upload, #/result/<case_id>) are unchanged from
 *  the pre-React page, so links an analyst pasted into a ticket still open
 *  the same case - and it needs no dependency and no server rewrite rule. */
function useHashRoute() {
  const [route, setRoute] = useState(parseHash)
  useEffect(() => {
    const onChange = () => setRoute(parseHash())
    window.addEventListener('hashchange', onChange)
    if (!window.location.hash) window.location.hash = '#/dashboard'
    return () => window.removeEventListener('hashchange', onChange)
  }, [])
  return route
}

export default function App() {
  const { page, param } = useHashRoute()

  // A result route with no case id is a dead end; send it home.
  useEffect(() => {
    if (page === 'result' && !param) window.location.hash = '#/dashboard'
  }, [page, param])

  return (
    <>
      <nav className="topnav">
        <div className="topnav-brand">Forensic Analyzer</div>
        <div className="topnav-links">
          <a href="#/dashboard" className={page === 'dashboard' ? 'active' : ''}>
            Dashboard
          </a>
          <a href="#/upload" className={page === 'upload' ? 'active' : ''}>
            Upload
          </a>
        </div>
      </nav>

      <div className="layout">
        {page === 'dashboard' && <Dashboard />}
        {page === 'upload' && <Upload />}
        {page === 'result' && param && <Result caseId={param} key={param} />}
      </div>
    </>
  )
}
