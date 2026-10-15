import { useCallback, useEffect, useState } from 'react'
import { AUTH_REQUIRED, getMe, listCompanies, logout } from './api.js'
import Overview from './pages/Overview.jsx'
import Upload from './pages/Upload.jsx'
import Customers from './pages/Customers.jsx'
import Result from './pages/Result.jsx'
import Placeholder from './pages/Placeholder.jsx'
import Login from './pages/Login.jsx'
import Sidebar, { NAV_GROUPS } from './components/Sidebar.jsx'

const MENU = NAV_GROUPS.flatMap((g) => g.items)
const PAGES = [...MENU.map((it) => it.route), 'result']

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

const CUSTOMER_KEY = 'fa_customer'

/** The customer every page shows (IAI-88): one at a time, never all of them -
 *  the display is separated by customer as the stores are (CLAUDE.md #40).
 *  The choice is a per-browser convenience; storage can throw in a private
 *  window, and then the first customer is used. */
function useCustomer(signedIn) {
  const [customers, setCustomers] = useState(null)
  const [chosen, setChosen] = useState(() => {
    try {
      return localStorage.getItem(CUSTOMER_KEY) || ''
    } catch {
      return ''
    }
  })

  const reload = useCallback(async () => {
    try {
      setCustomers(await listCompanies())
    } catch {
      setCustomers((prev) => prev || [])
    }
  }, [])

  useEffect(() => {
    if (signedIn) reload()
  }, [signedIn, reload])

  const select = useCallback((id) => {
    setChosen(id)
    try {
      localStorage.setItem(CUSTOMER_KEY, id)
    } catch {
      // only the remembered choice is lost
    }
  }, [])

  // A remembered customer that no longer exists (store reset) falls back to
  // the first one rather than to nothing.
  const list = customers || []
  const customerId = list.some((c) => c.company_id === chosen) ? chosen : list[0]?.company_id || ''
  return { customers: list, loaded: customers !== null, customerId, select, reload }
}

export default function App() {
  const { page, param } = useHashRoute()
  const [user, setUser] = useSession()
  const { customers, loaded, customerId, select, reload } = useCustomer(!!user)

  // #/dashboard/<company_id> (a Customers row, an old pasted link) selects
  // that customer; the Overview itself always reads the selection.
  useEffect(() => {
    if (page === 'dashboard' && param && customers.some((c) => c.company_id === param)) select(param)
  }, [page, param, customers, select])

  // Switching customer while a case is open leaves that case behind: it is
  // another customer's, so go to the new customer's Overview instead.
  function chooseCustomer(id) {
    select(id)
    if (page === 'dashboard' || page === 'result') window.location.hash = `#/dashboard/${id}`
  }

  // An upload can create a customer; reload the list, then show that one.
  async function uploaded(companyId) {
    await reload()
    select(companyId)
  }

  // A result route with no case id is a dead end; send it home.
  useEffect(() => {
    if (page === 'result' && !param) window.location.hash = '#/dashboard'
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
      {/* A case is opened from the Overview list, so that is what stays lit.
          The open-findings count waits for the finding status workflow
          (IAI-78); until then it is left unset and the badge does not
          render. */}
      <Sidebar
        active={page === 'result' ? 'dashboard' : page}
        counts={{ findings: null }}
        user={user}
        onLogout={signOut}
        customers={customers}
        customerId={customerId}
        onCustomer={chooseCustomer}
      />

      <main className="layout">
        {page === 'dashboard' && loaded && <Overview companyId={customerId} />}
        {page === 'upload' && <Upload user={user} customerId={customerId} onUploaded={uploaded} />}
        {page === 'customers' && <Customers />}
        {page === 'result' && param && <Result caseId={param} key={param} onCustomer={select} />}
        {placeholder && <Placeholder title={placeholder.label} />}
      </main>
    </div>
  )
}
