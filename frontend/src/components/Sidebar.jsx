/** Menu groups from FR-0.1. `route` is the hash page; `ready: false` marks a
 *  page that is still a placeholder, so the menu says so instead of the
 *  analyst finding out by clicking.
 *
 *  Overview keeps the #/dashboard URL: it is today's case list, and links
 *  pasted into tickets before the rename still land there. */
export const NAV_GROUPS = [
  {
    label: 'Monitor',
    items: [
      { route: 'dashboard', label: 'Overview' },
      { route: 'upload', label: 'Upload' },
      { route: 'findings', label: 'Findings' },
      { route: 'timeline', label: 'Timeline' },
    ],
  },
  {
    label: 'Investigate',
    items: [
      { route: 'customers', label: 'Customers' },
      { route: 'attack-graph', label: 'Attack Graph' },
      { route: 'attack-map', label: 'ATT&CK Map', ready: false },
    ],
  },
  {
    label: 'Manage',
    items: [
      { route: 'reports', label: 'Reports' },
      { route: 'settings', label: 'Settings', ready: false },
    ],
  },
]

/** `counts` maps a route to a number shown beside it (FR-0.2). A route with
 *  no number - null or absent - shows no badge at all, rather than a 0 that
 *  would claim nothing is open. */
export default function Sidebar({ active, counts = {}, user, onLogout }) {
  return (
    <aside className="sidebar">
      <div className="sidebar-brand">
        <div className="brand-mark" aria-hidden="true">S</div>
        <div>
          <div className="brand-name">SENTRY-IR</div>
          <div className="brand-sub">Finding Response Console</div>
        </div>
      </div>

      <nav className="sidebar-nav">
        {NAV_GROUPS.map((g) => (
          <div className="sidebar-group" key={g.label}>
            <div className="sidebar-group-label">{g.label}</div>
            {g.items.map((it) => (
              <a
                key={it.route}
                href={`#/${it.route}`}
                className={[
                  it.route === active ? 'active' : '',
                  it.ready === false ? 'pending' : '',
                ].join(' ').trim()}
                title={it.ready === false ? 'Not available yet' : undefined}
              >
                <span className="sidebar-label">{it.label}</span>
                {counts[it.route] != null && (
                  <span className="sidebar-count">{counts[it.route]}</span>
                )}
              </a>
            ))}
          </div>
        ))}
      </nav>

      {/* FR-0.3. The role is a stored label only - what each role may do is
          undefined until IAI-14, so nothing is enforced from it yet. */}
      <div className="sidebar-user">
        <div className="avatar" aria-hidden="true">{initials(user.name)}</div>
        <div>
          <div className="sidebar-user-name" title={user.email}>{user.name}</div>
          <div className="sidebar-user-role">{user.role}</div>
          <button type="button" className="link-button" onClick={onLogout}>
            Log out
          </button>
        </div>
      </div>
    </aside>
  )
}

/** "Kristichai Raksanit" -> "KR"; a one-word name or an email gives one letter.
 *  Thai leading vowels (เ แ โ ใ ไ) are skipped, so "เอก" gives "อ", not "เ". */
function initials(name) {
  const words = (name || '').replace(/@.*/, '').split(/\s+/).filter(Boolean)
  const first = (w) => ([...w].find((c) => !'เแโใไ'.includes(c)) || w[0]).toUpperCase()
  return words.slice(0, 2).map(first).join('') || '?'
}
