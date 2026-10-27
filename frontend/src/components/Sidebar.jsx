import { useState } from 'react'
import { ROLE_NAMES } from '../permissions.js'
import { saveTheme, storedTheme } from '../theme.js'
import Icon from './icons.jsx'

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
          <Icon name={theme === 'dark' ? 'sun' : 'moon'} />
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
                <Icon name={it.route} />
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
