import { useEffect, useState } from 'react'
import { AUTH_REQUIRED, getMe, listFindings, logout } from './api.js'
import Overview from './pages/Overview.jsx'
import Upload from './pages/Upload.jsx'
import Customers from './pages/Customers.jsx'
import Findings from './pages/Findings.jsx'
import CustomerDetail from './pages/CustomerDetail.jsx'
import CaseFlow from './pages/CaseFlow.jsx'
import Cases from './pages/Cases.jsx'
import FindingDetail from './pages/FindingDetail.jsx'
import Placeholder from './pages/Placeholder.jsx'
import Login from './pages/Login.jsx'
import Users from './pages/Users.jsx'
import Sidebar, { NAV_GROUPS } from './components/Sidebar.jsx'
import { UserContext } from './permissions.js'

const MENU = NAV_GROUPS.flatMap((g) => g.items)
// The case page's older addresses, kept so links pasted into tickets still open.
const LEGACY = ['result', 'reports', 'timeline', 'attack-graph']
const PAGES = [...MENU.map((it) => it.route), 'case', 'finding', ...LEGACY]

// Where each tab of the old Reports page lives now (specs/case_flow_design.md R13).
const REPORTS_TAB_STEP = {
  overview: 'report',
  chain: 'report',
  recs: 'report',
  events: 'ingest',
  evidence: 'ingest',
  findings: 'attack-events',
}

// Revision 1's case steps (IAI-89) -> the step holding their content since
// story 1 (specs/story1_case_flow_steps.md).
const OLD_STEPS = {
  triage: 'attack-events',
  investigate: 'attack-path',
  respond: 'attack-events',
  analyse: 'report',
}

function parseHash() {
  const h = window.location.hash.replace(/^#\/?/, '')
  const [page, ...rest] = h.split('/')
  if (page === 'login') return { page: 'login', param: '' }
  return {
    page: PAGES.includes(page) ? page : 'dashboard',
    param: rest.join('/'),
  }
}

/** Hash routing, kept rather than swapped for a router library: it needs no
 *  dependency and no server rewrite rule. A case is #/case/<case_id>/<step>;
 *  every older case address (#/result, #/reports, #/timeline, #/attack-graph)
 *  redirects to its step, so links an analyst pasted into a ticket still open
 *  the same case. */
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

/** The count beside the Findings menu item (FR-0.2): high and critical findings
 *  the analyst has not decided (since 2026-10-27; it was the status workflow's
 *  not-Resolved, which nothing on screen moves any more). null - no badge at all -
 *  until the server has answered, so an unknown count is never shown as 0. It is
 *  asked again when the page changes, because a decision on a case page changes it. */
function useOpenFindings(user, page, param) {
  const [open, setOpen] = useState(null)
  useEffect(() => {
    if (!user) return undefined
    let dead = false
    listFindings({ limit: 1 })
      .then((r) => !dead && setOpen(r.undecided_count))
      .catch(() => !dead && setOpen(null))
    return () => {
      dead = true
    }
  }, [user, page, param])
  return open
}

/** #/finding/<case id>/<finding key, URL-encoded>. The old #/result/<case> and
 *  #/result/<case>/<key> have the same shape and still open: a case lands on
 *  its current step, a finding on its own page (see the redirect below). */
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

  // Signed out, the address says so: #/login. Signing in always lands on
  // the Overview (the user's call, 2026-10-16) - not on the page a link
  // pointed to. replace() keeps the login step out of the Back history.
  useEffect(() => {
    if (user === null && page !== 'login') window.location.replace('#/login')
    if (user && page === 'login') window.location.replace('#/dashboard')
  }, [user, page])

  // A new page opens at its top. The document is one scroll container
  // shared by every route, so without this a page opened from halfway down
  // another one started halfway down too (Upload showed only its table).
  useEffect(() => {
    window.scrollTo(0, 0)
  }, [page, param])

  // The older case addresses. Links pasted into tickets still work: a finding
  // opens its page, a case opens the matching step (or the one it is on); no
  // case is a dead end. replace() keeps the old address out of Back.
  useEffect(() => {
    const go = (hash) => window.location.replace(hash)
    if (page === 'result') {
      const { caseId, findingKey } = splitResult(param)
      if (!caseId) go('#/cases')
      else if (findingKey) go(`#/finding/${caseId}/${encodeURIComponent(findingKey)}`)
      else go(`#/case/${caseId}`)
    }
    if (page === 'reports' || page === 'timeline' || page === 'attack-graph') {
      const [caseId, tab] = param.split('/')
      const step =
        page === 'reports' ? REPORTS_TAB_STEP[tab] : page === 'timeline' ? 'timeline' : 'attack-path'
      go(caseId ? `#/case/${caseId}${step ? `/${step}` : ''}` : '#/cases')
    }
    if (page === 'case' && !param) go('#/cases')
    if (page === 'case' && param) {
      const [caseId, step] = param.split('/')
      if (OLD_STEPS[step]) go(`#/case/${caseId}/${OLD_STEPS[step]}`)
    }
    if (page === 'finding' && !splitResult(param).findingKey) go('#/findings')
  }, [page, param])

  const placeholder = MENU.find((it) => it.route === page && it.ready === false)

  async function signOut() {
    await logout().catch(() => {})
    setUser(null)
  }

  // Nothing renders until the session check answers, so a signed-out user
  // never sees the shell flash, and a signed-in one never sees the login form.
  if (user === undefined) return null
  if (user === null) return <Login onLogin={setUser} />
  if (page === 'login') return null

  return (
    <UserContext.Provider value={user}>
    <div className="app">
      <Sidebar
        active={page === 'case' ? 'cases' : page === 'finding' ? 'findings' : page}
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
        {page === 'cases' && <Cases />}
        {page === 'case' && param && (
          // #/case/<case>/<step>. Keyed by the case only, so moving between
          // steps keeps the page - and a running analysis - in place.
          <CaseFlow caseId={param.split('/')[0]} stepId={param.split('/')[1] || null}
                    key={param.split('/')[0]} />
        )}
        {page === 'finding' && splitResult(param).findingKey && (
          <FindingDetail {...splitResult(param)} key={param} />
        )}
        {page === 'settings' && <Users />}
        {placeholder && <Placeholder title={placeholder.label} />}
      </main>
    </div>
    </UserContext.Provider>
  )
}
