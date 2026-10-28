import { Fragment, useCallback, useEffect, useState } from 'react'
import { getCustomerSummary } from '../api.js'
import { ago, fmtNum } from '../format.js'
import { StatTile } from '../components/cards.jsx'
import DeleteCustomer from '../components/DeleteCustomer.jsx'
import { useAccess } from '../permissions.js'

const SEV_EN = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', informational: 'Info' }

/** figma-export/Customers.svg: case load per customer (FR-6.1).
 *
 *  A customer is added only on the Upload page, where data enters the system
 *  (decided 2026-10-05), so this page has no "Add customer" button although the
 *  Figma shows one. Its one action is deleting a customer with every case it
 *  holds (admin, manager - specs/customer_delete.md), confirmed in a row under it.
 *
 *  "Open" follows the analyst's decisions since 2026-10-27 (it followed the
 *  status workflow, IAI-79, until nothing on screen could move a status): a case
 *  is open while a suggestion in it is not decided. The footnote states the rule,
 *  because a number that silently means something else is worse than one that
 *  is labelled. */
export default function Customers() {
  const { can, why } = useAccess()
  const [data, setData] = useState(null)
  const [error, setError] = useState('')
  const [deleting, setDeleting] = useState(null) // the company_id whose confirmation is open

  const load = useCallback(async () => {
    try {
      setData(await getCustomerSummary())
      setError('')
    } catch (err) {
      setError(err.message)
    }
  }, [])

  useEffect(() => {
    load()
  }, [load])

  if (error && !data) return <div className="panel empty">Could not load customers: {error}</div>
  if (!data) return <div className="empty">Loading...</div>
  // The same open / closed the table shows per customer, added up.
  const open = data.customers.reduce((n, c) => n + (c.open || 0), 0)
  const closed = data.customers.reduce((n, c) => n + (c.closed || 0), 0)

  return (
    <section className="page ov">
      <div className="top-bar">
        <div>
          <h1>Customers</h1>
          <div className="subtitle">
            <span className="live-dot" /> {data.accounts} customer {data.accounts === 1 ? 'account' : 'accounts'},
            case load per account
          </div>
        </div>
        <div className="actions">
          <button type="button" className="secondary" onClick={load}>
            Refresh
          </button>
        </div>
      </div>

      <div className="ui-stat-grid" aria-label="Case load">
        <StatTile icon="customers" tone="info" value={fmtNum(data.accounts)} label="Customers" />
        <StatTile icon="cases" tone="muted" value={fmtNum(data.total_cases)} label="Cases" />
        <StatTile icon="findings" tone={open ? 'danger' : 'ok'} value={fmtNum(open)} label="Open cases" />
        <StatTile icon="check" tone="ok" value={fmtNum(closed)} label="Closed cases" />
      </div>

      <div className="panel">
        <h2>
          Customers{' '}
          <span className="muted mono cust-count">
            {data.accounts} accounts, {data.total_cases} cases total
          </span>
        </h2>
        <div className="table-scroll">
          <table className="ov-table cust-table">
            <thead>
              <tr>
                <th>Customer</th>
                <th>Open cases</th>
                <th>Closed</th>
                <th>Highest open severity</th>
                <th>Last activity</th>
                <th aria-label="Actions" />
              </tr>
            </thead>
            <tbody>
              {!data.customers.length && (
                <tr>
                  <td colSpan={6} className="empty">
                    No customers yet - add one when you <a href="#/upload">upload</a> a log
                  </td>
                </tr>
              )}
              {data.customers.map((c) => (
                <Fragment key={c.company_id || 'none'}>
                  <tr>
                    <td className={c.company_id ? 'cust-name' : 'cust-name muted'}>
                      {c.company_id ? (
                        <a href={`#/customers/${c.company_id}`} title="Open this customer's details">
                          {c.name}
                        </a>
                      ) : (
                        c.name
                      )}
                    </td>
                    <td>
                      <span className={`cust-open${c.open ? ` tone-${c.open_severity || 'low'}` : ''}`}>{c.open}</span>{' '}
                      <span className="cell-sub">of {c.cases}</span>
                    </td>
                    <td className="mono muted">{c.closed}</td>
                    <td>
                      {c.open_severity ? (
                        <span className={`sev-tag sev-tag-${c.open_severity}`}>{SEV_EN[c.open_severity]}</span>
                      ) : (
                        <span className="muted">—</span>
                      )}
                    </td>
                    <td className="mono muted">{ago(c.last_activity)}</td>
                    <td className="cust-actions">
                      {/* The "No customer" row is cases from before a customer was required:
                          no store of its own to delete. */}
                      {c.company_id && (
                        <button type="button" className="secondary danger-outline" disabled={!can('customer:delete')}
                                title={why('customer:delete') || `Delete ${c.name} and every case it holds`}
                                aria-expanded={deleting === c.company_id}
                                onClick={() => setDeleting(deleting === c.company_id ? null : c.company_id)}>
                          Delete
                        </button>
                      )}
                    </td>
                  </tr>
                  {deleting === c.company_id && (
                    <DeleteCustomer companyId={c.company_id} colSpan={6}
                                    onDone={(deleted) => { setDeleting(null); if (deleted) load() }} />
                  )}
                </Fragment>
              ))}
            </tbody>
          </table>
        </div>
        <div className="field-hint cust-note">
          A case is open while any suggestion in it is not decided yet, and closed once the analyst has
          decided every one - when its report can be issued. Highest open severity is the worst suggestion
          not decided. Cases still processing or failed count only towards the total. Last activity is the latest upload or review decision.
        </div>
      </div>
    </section>
  )
}
