import { useCallback, useEffect, useState } from 'react'
import { createUser, getAccountAudit, listUsers, removeUser, resetUserPassword, updateUser } from '../api.js'
import { fmtTime } from '../format.js'
import { ROLE_NAMES, useAccess } from '../permissions.js'

/** Settings - Users (IAI-14, Q59): accounts and their roles, for an
 *  administrator. Every change is checked by the server (the last enabled
 *  administrator stays one; nobody changes their own role or disables
 *  themself) and written to the hash-chained account log shown below
 *  (NIST SP 800-53 AC-2(7), AC-6(9)). */
const ROLE_DOES = {
  admin: 'manages accounts; reads everything; takes no case action',
  manager: 'all case work; creates customers and projects; assigns; the only role that resolves or reopens',
  analyst: 'uploads, reviews, works the findings assigned to them; no new customers, no closing',
}

export default function Users() {
  const { user, can, why } = useAccess()
  const [data, setData] = useState(null)
  const [audit, setAudit] = useState(null)
  const [error, setError] = useState('')
  const [draft, setDraft] = useState({ email: '', name: '', role: 'analyst', password: '' })
  const [busy, setBusy] = useState('')
  const [resetting, setResetting] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [removing, setRemoving] = useState('')

  const load = useCallback(async () => {
    try {
      const [u, a] = await Promise.all([listUsers(), getAccountAudit()])
      setData(u)
      setAudit(a)
      setError('')
    } catch (err) {
      setError(err.message)
    }
  }, [])

  const isAdmin = can('account:manage')
  useEffect(() => {
    if (isAdmin) load()
  }, [isAdmin, load])

  async function act(key, fn) {
    setBusy(key)
    setError('')
    try {
      await fn()
      await load()
      return true
    } catch (err) {
      setError(err.message)
      return false
    } finally {
      setBusy('')
    }
  }

  if (!isAdmin) {
    return (
      <section className="page">
        <div className="top-bar">
          <div>
            <h1>Settings</h1>
            <div className="subtitle">Accounts and roles</div>
          </div>
        </div>
        <div className="panel empty">
          {why('account:manage')}. Signed in as {user?.email} ({ROLE_NAMES[user?.role] || 'no role'}).
        </div>
      </section>
    )
  }
  if (!data) return <div className="empty">{error ? `Could not load the accounts: ${error}` : 'Loading...'}</div>

  return (
    <section className="page ov">
      <div className="top-bar">
        <div>
          <h1>Users</h1>
          <div className="subtitle">
            {data.users.length} {data.users.length === 1 ? 'account' : 'accounts'} - who may use this tool, and as what
          </div>
        </div>
      </div>
      {error && <div className="status-line err">{error}</div>}

      <div className="panel">
        <h2>Accounts</h2>
        <div className="table-scroll">
          <table className="ov-table">
            <thead>
              <tr>
                <th>Account</th>
                <th>Role</th>
                <th>Status</th>
                <th>Created</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {data.users.map((u) => {
                const self = u.email === user.email
                return (
                  <tr key={u.email}>
                    <td>
                      <div>{u.name}</div>
                      <div className="cell-sub mono">{u.email}</div>
                    </td>
                    <td>
                      <select
                        value={u.role}
                        aria-label={`Role of ${u.email}`}
                        disabled={!!busy || self}
                        title={self ? 'Another administrator changes your role' : ''}
                        onChange={(e) => act(u.email, () => updateUser(u.email, { role: e.target.value }))}
                      >
                        {data.roles.map((r) => (
                          <option key={r} value={r}>
                            {ROLE_NAMES[r]}
                          </option>
                        ))}
                      </select>
                    </td>
                    <td>{u.disabled ? <span className="ev-bad">Disabled</span> : 'Active'}</td>
                    <td className="cell-sub">
                      {u.created_at ? fmtTime(u.created_at) : '-'}
                      {u.created_by ? ` by ${u.created_by}` : ''}
                    </td>
                    <td>
                      <div className="lc-actions">
                        <button
                          type="button"
                          className="secondary"
                          disabled={!!busy || self}
                          title={self ? 'Another administrator disables your account' : ''}
                          onClick={() => act(u.email, () => updateUser(u.email, { disabled: !u.disabled }))}
                        >
                          {u.disabled ? 'Enable' : 'Disable'}
                        </button>
                        <button
                          type="button"
                          className="secondary"
                          disabled={!!busy}
                          onClick={() => {
                            setResetting(resetting === u.email ? '' : u.email)
                            setNewPassword('')
                          }}
                        >
                          Reset password
                        </button>
                        <button
                          type="button"
                          className="secondary"
                          disabled={!!busy || self}
                          title={self ? 'Another administrator removes your account' : ''}
                          onClick={() => setRemoving(removing === u.email ? '' : u.email)}
                        >
                          Remove
                        </button>
                      </div>
                      {resetting === u.email && (
                        <form
                          className="lc-form"
                          onSubmit={async (e) => {
                            e.preventDefault()
                            if (await act(u.email, () => resetUserPassword(u.email, newPassword))) setResetting('')
                          }}
                        >
                          <label htmlFor={`pw-${u.email}`}>
                            New password (at least {data.min_password} characters) - their sessions end
                          </label>
                          <input
                            id={`pw-${u.email}`}
                            type="password"
                            autoComplete="new-password"
                            value={newPassword}
                            onChange={(e) => setNewPassword(e.target.value)}
                          />
                          <button className="rv-btn" type="submit" disabled={!!busy || newPassword.length < data.min_password}>
                            Set password
                          </button>
                        </form>
                      )}
                      {removing === u.email && (
                        <div className="lc-form">
                          <span>Remove {u.email}? Their sessions end; the decisions they recorded stay.</span>
                          <button
                            className="rv-btn rv-reject"
                            type="button"
                            disabled={!!busy}
                            onClick={async () => {
                              if (await act(u.email, () => removeUser(u.email))) setRemoving('')
                            }}
                          >
                            Remove the account
                          </button>
                        </div>
                      )}
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      </div>

      <div className="panel">
        <h2>Add an account</h2>
        <form
          className="lc-form ing-form"
          onSubmit={async (e) => {
            e.preventDefault()
            if (await act('create', () => createUser(draft))) {
              setDraft({ email: '', name: '', role: 'analyst', password: '' })
            }
          }}
        >
          <div>
            <label htmlFor="nu-email">Account ID (email)</label>
            <input id="nu-email" type="email" required value={draft.email}
                   onChange={(e) => setDraft({ ...draft, email: e.target.value })} />
          </div>
          <div>
            <label htmlFor="nu-name">Name</label>
            <input id="nu-name" type="text" value={draft.name}
                   onChange={(e) => setDraft({ ...draft, name: e.target.value })} />
          </div>
          <div>
            <label htmlFor="nu-role">Role</label>
            <select id="nu-role" value={draft.role} onChange={(e) => setDraft({ ...draft, role: e.target.value })}>
              {data.roles.map((r) => (
                <option key={r} value={r}>
                  {ROLE_NAMES[r]}
                </option>
              ))}
            </select>
            <div className="cell-sub">{ROLE_DOES[draft.role]}</div>
          </div>
          <div>
            <label htmlFor="nu-pw">Password (at least {data.min_password} characters - give it to them yourself)</label>
            <input id="nu-pw" type="password" autoComplete="new-password" required value={draft.password}
                   onChange={(e) => setDraft({ ...draft, password: e.target.value })} />
          </div>
          <div className="lc-actions">
            <button className="rv-btn" type="submit" disabled={!!busy || draft.password.length < data.min_password}>
              {busy === 'create' ? 'Creating...' : 'Create the account'}
            </button>
          </div>
        </form>
      </div>

      <div className="panel">
        <h2>
          Roles <span className="muted cust-count">what each may do (enforced by the server)</span>
        </h2>
        <table className="profile-facts">
          <tbody>
            {data.roles.map((r) => (
              <tr key={r}>
                <td>{ROLE_NAMES[r]}</td>
                <td>{ROLE_DOES[r]}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="panel">
        <h2>
          Account history{' '}
          <span className={`cust-count ${audit?.chain?.intact ? 'muted' : 'ev-bad'}`}>
            {audit?.chain?.intact ? 'hash chain intact' : `hash chain broken: ${audit?.chain?.problem}`}
          </span>
        </h2>
        <div className="table-scroll">
          <table className="ov-table">
            <thead>
              <tr>
                <th>When</th>
                <th>Who</th>
                <th>What</th>
                <th>Account</th>
                <th>Change</th>
              </tr>
            </thead>
            <tbody>
              {!(audit?.entries || []).length && (
                <tr>
                  <td colSpan={5} className="empty">No account changes recorded yet</td>
                </tr>
              )}
              {(audit?.entries || []).map((e) => (
                <tr key={e.seq}>
                  <td className="cell-sub">{fmtTime(e.ts)}</td>
                  <td className="mono">{e.actor}</td>
                  <td>{e.event.replace('account_', '').replace('_', ' ')}</td>
                  <td className="mono">{e.account}</td>
                  <td className="cell-sub">
                    {e.changes
                      ? Object.entries(e.changes)
                          .map(([k, [a, b]]) => `${k}: ${String(a)} → ${String(b)}`)
                          .join(' · ')
                      : e.role || ''}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </section>
  )
}
