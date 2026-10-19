import { useEffect, useState } from 'react'
import { AUTH_REQUIRED, getMe, listFindings, logout } from './api.js'
import Overview from './pages/Overview.jsx'
import Upload from './pages/Upload.jsx'
import Customers from './pages/Customers.jsx'
import Findings from './pages/Findings.jsx'
import CustomerDetail from './pages/CustomerDetail.jsx'
import CaseView, { VIEWS } from './pages/CaseView.jsx'
import CasePicker from './components/CasePicker.jsx'
import FindingDetail from './pages/FindingDetail.jsx'
import Placeholder from './pages/Placeholder.jsx'
import Login from './pages/Login.jsx'
import Sidebar, { NAV_GROUPS } from './components/Sidebar.jsx'

const MENU = NAV_GROUPS.flatMap((g) => g.items)
const PAGES = [...MENU.map((it) => it.route), 'result', 'finding']

function parseHash() {
  const h = window.location.hash.replace(/^#\/?/, '')
  const [page, ...rest] = h.split('/')
  return {
    page: PAGES.includes(page) ? page : 'dashboard',
    param: rest.join('/'),
  }
}

/** Hash routing, kept rather than swapped for a router library.
 *  The URLs (#/dashboard, #/upload, #/reports/<case_id>) replace the old #/result/<case_id>, which still redirects) are unchanged from
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

/** undefined while the session is being checked, null when signed out. */
function useSession() {
  const [user, setUser] = useState(undefined)
  useEffect(() => {
    getMe()
      .then(setUser)
      .catch(() => setUser(null))
    const expired = () => setUser(null)
    window.addEventListener(AUTH_REQUIRED, expired)
    return () => window.removeEventListener(AUTH_REQUIRED, expired)
  }, [])
  return [user, setUser]
}

/** The count beside the Findings menu item (FR-0.2): findings in the status
 *  workflow that are not Resolved. null - no badge at all - until the server has
 *  answered, so an unknown count is never shown as 0. It is asked again when the
 *  page changes, because a status change on a case page changes it. */
function useOpenFindings(user, page, param) {
  const [open, setOpen] = useState(null)
  useEffect(() => {
    if (!user) return undefined
    let dead = false
    listFindings({ limit: 1 })
      .then((r) => !dead && setOpen(r.open_count))
      .catch(() => !dead && setOpen(null))
    return () => {
      dead = true
    }
  }, [user, page, param])
  return open
}

/** #/finding/<case id>/<finding key, URL-encoded>. The old #/result/<case> and
 *  #/result/<case>/<key> have the same shape and still open: a case lands on
 *  its Reports page, a finding on its own page (see the redirect below). */
function splitResult(param) {
  const i = param.indexOf('/')
  if (i < 0) return { caseId: param, findingKey: null }
  let findingKey = null
  try {
    findingKey = decodeURIComponent(param.slice(i + 1)) || null
  } catch {
    // a malformed key just opens the case without a target
  }
  return { caseId: param.slice(0, i), findingKey }
}

export default function App() {
  const { page, param } = useHashRoute()
  const [user, setUser] = useSession()
  const openFindings = useOpenFindings(user, page, param)

  // A new page opens at its top. The document is one scroll container
  // shared by every route, so without this a page opened from halfway down
  // another one started halfway down too (Upload showed only its table).
  useEffect(() => {
    window.scrollTo(0, 0)
  }, [page, param])

  // #/result was the old case page. Links pasted into tickets still work: a
  // finding opens its page, a case opens its Reports; no case is a dead end.
  useEffect(() => {
    if (page === 'result') {
      const { caseId, findingKey } = splitResult(param)
      if (!caseId) window.location.hash = '#/dashboard'
      else if (findingKey) window.location.hash = `#/finding/${caseId}/${encodeURIComponent(findingKey)}`
      else window.location.hash = `#/reports/${caseId}`
    }
    if (page === 'finding' && !splitResult(param).findingKey) window.location.hash = '#/findings'
  }, [page, param])

  const placeholder = MENU.find((it) => it.route === page && it.ready === false)

  async function signOut() {
    await logout().catch(() => {})
    setUser(null)
  }

  // Nothing renders until the session check answers, so a signed-out user
  // never sees the shell flash, and a signed-in one never sees the login form.
  // The hash is left alone: signing in lands on the page the link pointed to.
  if (user === undefined) return null
  if (user === null) return <Login onLogin={setUser} />

  return (
    <div className="app">
      {/* A case is opened from the Overview list, so that is what stays lit. */}
      <Sidebar
        active={page === 'result' ? 'dashboard' : page === 'finding' ? 'findings' : page}
        counts={{ findings: openFindings }}
        user={user}
        onLogout={signOut}
      />

      <main className="layout">
        {page === 'dashboard' && <Overview companyId={param || null} />}
        {page === 'upload' && <Upload user={user} />}
        {page === 'findings' && <Findings param={param || null} key={param} />}
        {page === 'customers' && !param && <Customers />}
        {page === 'customers' && param && (
          // #/customers/<id> or #/customers/<id>/projects/<project id>
          <CustomerDetail companyId={param.split('/')[0]} projectId={param.split('/')[2]} key={param} />
        )}
        {VIEWS[page] && !param && <CasePicker route={VIEWS[page].route} title={VIEWS[page].title} />}
        {VIEWS[page] && param && (
          // #/reports/<case> or #/reports/<case>/<tab>
          <CaseView caseId={param.split('/')[0]} initialTab={param.split('/')[1]} view={page}
                    key={`${page}/${param}`} />
        )}
        {page === 'finding' && splitResult(param).findingKey && (
          <FindingDetail {...splitResult(param)} key={param} />
        )}
        {placeholder && <Placeholder title={placeholder.label} />}
      </main>
    </div>
  )
}
