import { useCallback, useEffect, useState } from 'react'
import { getCustomerSummary } from '../api.js'
import { ago } from '../format.js'

const SEV_EN = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', informational: 'Info' }

/** figma-export/Customers.svg: case load per customer (FR-6.1).
 *
 *  Read-only on purpose: a customer is added only on the Upload page, where
 *  data enters the system (decided 2026-10-05), so this page has no "Add
 *  customer" button although the Figma shows one.
 *
 *  "Open" is interim. FR-6.1 counts a case as open while it has a finding
 *  that is not closed, and the finding status workflow arrives in Sprint 3
 *  (IAI-79); until then a case is open while any of its findings is
 *  unreviewed. The footnote says
 *  so, because a number that silently means something else is worse than one
 *  that is labelled. */
export default function Customers() {
  const [data, setData] = useState(null)
  const [error, setError] = useState('')

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
              </tr>
            </thead>
            <tbody>
              {!data.customers.length && (
                <tr>
                  <td colSpan={5} className="empty">
                    No customers yet - add one when you <a href="#/upload">upload</a> a log
                  </td>
                </tr>
              )}
              {data.customers.map((c) => (
                <tr key={c.company_id || 'none'}>
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
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div className="field-hint cust-note">
          A case is open while any of its findings is unreviewed, closed once every finding has a decision.
          Cases still processing or failed count only towards the total. Last activity is the latest upload
          or review decision.
        </div>
      </div>
    </section>
  )
}
