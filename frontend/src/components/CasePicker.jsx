import { useEffect, useState } from 'react'
import { listCases } from '../api.js'
import { fmtTime } from '../format.js'
import { Empty } from './common.jsx'

/** What a case-level page (Reports, Attack Graph, Timeline) shows when it is
 *  opened from the menu with no case: the ready cases, newest first, each
 *  linking to the same page for that case. */
export default function CasePicker({ route, title }) {
  const [cases, setCases] = useState(null)
  const [error, setError] = useState('')

  useEffect(() => {
    let alive = true
    listCases()
      .then((all) => alive && setCases(all.filter((m) => m.status === 'ready')))
      .catch((err) => alive && setError(err.message))
    return () => {
      alive = false
    }
  }, [])

  return (
    <section className="page">
      <div className="top-bar">
        <div>
          <h1>{title}</h1>
          <div className="subtitle">Choose a case</div>
        </div>
      </div>
      <div className="panel">
        {error && <Empty>Could not load the cases: {error}</Empty>}
        {!error && !cases && <Empty>Loading...</Empty>}
        {cases && !cases.length && <Empty>No case is ready yet - upload a log first.</Empty>}
        {cases && cases.length > 0 && (
          <table>
            <thead>
              <tr>
                <th>File</th>
                <th>Customer</th>
                <th>Uploaded</th>
              </tr>
            </thead>
            <tbody>
              {cases.map((m) => (
                <tr key={m.case_id}>
                  <td>
                    <a className="table-link" href={`#/${route}/${m.case_id}`}>
                      {m.original_filename}
                    </a>
                  </td>
                  <td>{m.company_name || '—'}</td>
                  <td>{fmtTime(m.uploaded_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </section>
  )
}
