import { useEffect, useState } from 'react'
import { listReports, reportFileUrl } from '../api.js'
import { fmtBytes, fmtTime } from '../format.js'
import { Empty } from '../components/common.jsx'

/** Reports - every draft the system made and every final an analyst uploaded, across every
 *  customer's projects, newest first, each a download (GET /api/reports). Drafts are made and
 *  finals uploaded on the project's own page (ReportPanel); this page only hands the files out. */
export default function Reports() {
  const [files, setFiles] = useState(null)
  const [error, setError] = useState('')

  useEffect(() => {
    listReports()
      .then((r) => setFiles(r.files))
      .catch((err) => setError(err.message))
  }, [])

  return (
    <section className="page ov">
      <div className="top-bar">
        <div>
          <h1>Reports</h1>
          <div className="subtitle">
            Every report draft and final of every project, newest first. A draft is made on its
            project's page.
          </div>
        </div>
      </div>

      <div className="panel">
        {error && <Empty>{error}</Empty>}
        {!error && !files && <Empty>Loading...</Empty>}
        {files && !files.length && (
          <Empty>No reports yet. Open a project from <a href="#/customers">Customers</a> to make a draft.</Empty>
        )}
        {files && files.length > 0 && (
          <div className="table-scroll">
            <table className="ov-table">
              <thead>
                <tr>
                  <th>Customer · project</th>
                  <th>Version</th>
                  <th>Kind</th>
                  <th>Made</th>
                  <th>By</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {files.map((f) => (
                  <tr key={`${f.company_id}/${f.project_id}/${f.file}`}>
                    <td>
                      {f.company_name || <span className="muted">{f.company_id}</span>}
                      <div className="cell-sub">
                        <a className="table-link" href={`#/customers/${f.company_id}/projects/${f.project_id}`}
                           title="Open this project">
                          {f.project_name || f.project_id}
                        </a>
                      </div>
                    </td>
                    <td className="mono">{f.version}</td>
                    <td>
                      {f.kind === 'final' ? 'Final' : 'Draft'}
                      {f.kind === 'final' && f.original_name && <div className="cell-sub">{f.original_name}</div>}
                    </td>
                    <td>{fmtTime(f.ts)}</td>
                    <td>{f.actor_name || f.actor}</td>
                    <td>
                      <a href={reportFileUrl(f.company_id, f.project_id, f.file)} download
                         title={`${f.file} · ${fmtBytes(f.bytes)} · SHA-256 ${f.sha256}`}>
                        Download
                      </a>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </section>
  )
}
