import { useEffect, useState } from 'react'
import { getFlow, listCases, listCompanies } from '../api.js'
import { fmtTime } from '../format.js'
import { Empty, StatusBadge } from '../components/common.jsx'
import { stepHref } from '../components/StepBar.jsx'

// Steps are asked per case, a few at a time, newest first: each answer reads
// the case's findings, so a long list is filled in as it arrives.
const FLOW_BATCH = 4

/** Cases - the working list: every case of the chosen customer with the step
 *  it is on (case_flow.py). The customer profile keeps its own history view. */
export default function Cases() {
  const [companies, setCompanies] = useState([])
  const [companyId, setCompanyId] = useState('')
  const [cases, setCases] = useState(null)
  const [steps, setSteps] = useState({})
  const [error, setError] = useState('')

  useEffect(() => {
    listCompanies().then(setCompanies).catch(() => {})
  }, [])

  useEffect(() => {
    let alive = true
    setCases(null)
    setSteps({})
    listCases(companyId || null)
      .then(async (list) => {
        if (!alive) return
        const sorted = list.slice().sort((a, b) => String(b.uploaded_at).localeCompare(String(a.uploaded_at)))
        setCases(sorted)
        for (let i = 0; i < sorted.length && alive; i += FLOW_BATCH) {
          const batch = sorted.slice(i, i + FLOW_BATCH)
          const got = await Promise.all(batch.map((m) => getFlow(m.case_id).catch(() => null)))
          if (!alive) return
          setSteps((prev) => {
            const next = { ...prev }
            batch.forEach((m, j) => {
              next[m.case_id] = got[j]
            })
            return next
          })
        }
      })
      .catch((err) => alive && setError(err.message))
    return () => {
      alive = false
    }
  }, [companyId])

  return (
    <section className="page">
      <div className="top-bar">
        <div>
          <h1>Cases</h1>
          <div className="subtitle">
            Every case and the step it is on: Ingest, Timeline, Attack events, Attack timeline, Attack path,
            Report.
          </div>
        </div>
        <a className="btn-primary" href="#/upload">Upload a log</a>
      </div>

      <div className="panel">
        <div className="filter-bar">
          <label htmlFor="cases-customer">Customer</label>{' '}
          <select id="cases-customer" value={companyId} onChange={(e) => setCompanyId(e.target.value)}>
            <option value="">Every customer</option>
            {companies.map((c) => (
              <option key={c.company_id} value={c.company_id}>{c.name}</option>
            ))}
          </select>
        </div>
        {error && <Empty>{error}</Empty>}
        {!error && !cases && <Empty>Loading...</Empty>}
        {cases && !cases.length && <Empty>No cases yet. <a href="#/upload">Upload a log</a> to open one.</Empty>}
        {cases && cases.length > 0 && (
          <div className="table-scroll">
            <table className="ov-table">
              <thead>
                <tr>
                  <th>File</th>
                  <th>Customer · project</th>
                  <th>Uploaded</th>
                  <th>Status</th>
                  <th>Current step</th>
                </tr>
              </thead>
              <tbody>
                {cases.map((m) => {
                  const fl = steps[m.case_id]
                  const cur = fl?.steps.find((s) => s.id === fl.recommended)
                  return (
                    <tr key={m.case_id}>
                      <td>
                        <a className="table-link" href={stepHref(m.case_id, fl?.recommended || 'ingest')}>
                          {m.original_filename}
                        </a>
                        <div className="cell-sub mono">{m.case_id}</div>
                      </td>
                      <td>
                        {m.company_name || <span className="muted">No customer</span>}
                        {m.project_name && <div className="cell-sub">{m.project_name}</div>}
                      </td>
                      <td>{fmtTime(m.uploaded_at)}</td>
                      <td><StatusBadge status={m.status} error={m.error} /></td>
                      <td>
                        {cur ? (
                          <>
                            {cur.title}
                            <div className="cell-sub">{cur.reason}</div>
                          </>
                        ) : (
                          <span className="muted">{fl === null ? '-' : '...'}</span>
                        )}
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </section>
  )
}
