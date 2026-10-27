import { useState } from 'react'
import { ROLE_NAMES } from '../permissions.js'
import { saveTheme, storedTheme } from '../theme.js'

/** Menu groups from FR-0.1. `route` is the hash page; `ready: false` marks a
 *  page that is still a placeholder, so the menu says so instead of the
 *  analyst finding out by clicking.
 *
 *  Overview keeps the #/dashboard URL: it is today's case list, and links
 *  pasted into tickets before the rename still land there. */
export const NAV_GROUPS = [
  // In the order of the work (specs/case_flow_design.md, D4): Timeline, Attack
  // Graph, ATT&CK Map and Reports are steps of a case now, not menu pages.
  {
    label: 'Work',
    tone: 'accent',
    items: [
      { route: 'dashboard', label: 'Overview' },
      { route: 'upload', label: 'Upload' },
      { route: 'cases', label: 'Cases' },
      { route: 'findings', label: 'Findings' },
    ],
  },
  {
    label: 'Manage',
    tone: 'info',
    items: [
      { route: 'customers', label: 'Customers' },
      { route: 'settings', label: 'Settings' },
    ],
  },
]

/** One stroke icon per menu route (24-unit paths, drawn in currentColor). */
const ICONS = {
  dashboard: 'M3 3h7v7H3zM14 3h7v7h-7zM3 14h7v7H3zM14 14h7v7h-7z',
  upload: 'M12 16V4M7 9l5-5 5 5M4 20h16',
  cases: 'M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z',
  findings: 'M5 21V4M5 4h11l-2 4 2 4H5',
  customers: 'M4 21V5l8-3 8 3v16M9 21v-4h6v4M8 9h.01M12 9h.01M16 9h.01M8 13h.01M12 13h.01M16 13h.01',
  settings: 'M12 9a3 3 0 1 0 0 6 3 3 0 0 0 0-6zM12 2v3M12 19v3M2 12h3M19 12h3M4.9 4.9 7 7M17 17l2.1 2.1M4.9 19.1 7 17M17 7l2.1-2.1',
}
const SUN = 'M12 17a5 5 0 1 0 0-10 5 5 0 0 0 0 10zM12 1v2M12 21v2M4.2 4.2l1.4 1.4M18.4 18.4l1.4 1.4M1 12h2M21 12h2M4.2 19.8l1.4-1.4M18.4 5.6l1.4-1.4'
const MOON = 'M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z'

function Icon({ d }) {
  return (
    <svg className="icon" aria-hidden="true" viewBox="0 0 24 24" fill="none" stroke="currentColor"
         strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <path d={d} />
    </svg>
  )
}

/** `counts` maps a route to a number shown beside it (FR-0.2). A route with
 *  no number - null or absent - shows no badge at all, rather than a 0 that
 *  would claim nothing is open. */
export default function Sidebar({ active, counts = {}, user, onLogout }) {
  const [theme, setTheme] = useState(storedTheme)
  const next = theme === 'dark' ? 'light' : 'dark'
  const toggle = () => {
    saveTheme(next)
    setTheme(next)
  }

  return (
    <aside className="sidebar">
      <div className="sidebar-brand">
        <div className="brand-mark" aria-hidden="true">S</div>
        <div className="sidebar-brand-text">
          <div className="brand-name">SENTRY-IR</div>
          <div className="brand-sub">Finding Response Console</div>
        </div>
        <button type="button" className="theme-toggle" onClick={toggle}
                aria-label={`Switch to ${next} theme`} title={`Switch to ${next} theme`}>
          <Icon d={theme === 'dark' ? SUN : MOON} />
        </button>
      </div>

      <nav className="sidebar-nav">
        {NAV_GROUPS.map((g) => (
          <div className="sidebar-group" key={g.label}>
            <div className={`sidebar-group-label tone-${g.tone}`}>{g.label}</div>
            {g.items.map((it) => (
              <a
                key={it.route}
                href={`#/${it.route}`}
                className={[
                  it.route === active ? 'active' : '',
                  it.ready === false ? 'pending' : '',
                ].join(' ').trim()}
                aria-current={it.route === active ? 'page' : undefined}
                title={it.ready === false ? 'Not available yet' : undefined}
              >
                {ICONS[it.route] && <Icon d={ICONS[it.route]} />}
                <span className="sidebar-label">{it.label}</span>
                {counts[it.route] != null && (
                  <span className="sidebar-count">{counts[it.route]}</span>
                )}
              </a>
            ))}
          </div>
        ))}
      </nav>

      {/* FR-0.3. The role decides what the account may do (IAI-14,
          app/services/authz.py). */}
      <div className="sidebar-user">
        <div className="avatar" aria-hidden="true">{initials(user.name)}</div>
        <div>
          <div className="sidebar-user-name" title={user.email}>{user.name}</div>
          <div className="sidebar-user-role">{ROLE_NAMES[user.role] || user.role}</div>
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
