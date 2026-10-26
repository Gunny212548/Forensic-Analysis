import { useCallback, useEffect, useRef, useState } from 'react'
import { checkUpload, listCases, listCompanies, listProjects, uploadFile } from '../api.js'
import { useAccess } from '../permissions.js'
import { fmtBytes, fmtTime } from '../format.js'
import { SeverityPill, StatusBadge } from '../components/common.jsx'

const RECENT_LIMIT = 10
const POLL_MS = 5000
const FAST_POLL_MS = 1500

/** "Processing 42%" for a manifest, "~42%" when the pipeline says it is an
 *  estimate (the CSV fast path, see pipeline.Progress). */
function processingText(m) {
  if (!m) return ''
  if (m.status === 'queued') return 'Queued'
  if (m.status === 'failed') return 'Failed'
  if (m.status === 'ready') return `Done${aiText(m)}`
  const p = m.progress
  if (!p) return 'Processing...'
  return `Processing ${p.estimated ? '~' : ''}${p.pct}%`
}

/** " · AI reviewing 15 of 526 (qwen3.5:9b)" - the AI reviews every suggestion after the case
 *  is ready (triage.py, specs/ai_review_coverage.md), so a ready case can still be moving.
 *  Empty when there is nothing to say. */
function aiText(m) {
  const a = m?.ai_review
  if (!a) return ''
  const failed = a.failed ? ` · ${a.failed} failed` : ''
  if (a.status === 'queued') return ' · AI review queued'
  if (a.status === 'running')
    return ` · AI reviewing ${a.done ?? 0} of ${a.total ?? '?'}${a.model ? ` (${a.model})` : ''}${failed}`
  if (a.status === 'failed') return ` · AI review stopped${a.error ? `: ${a.error}` : ''}`
  if (a.status === 'done' && a.failed) return ` · AI reviewed ${a.done} of ${a.total}${failed}`
  return ''
}

function processingPct(m) {
  if (!m) return 0
  if (m.status === 'ready') return 100
  return m.progress?.pct || 0
}

// FR-2.6: the formats the decoder has actually been run against real exports
// of (CLAUDE.md, "Formats exercised against real data"). Anything else is
// still accepted and decoded heuristically - this list is what is known to
// work, not a whitelist.
const SUPPORTED_FORMATS = [
  'VMware ESXi auth.log / shell.log',
  'Linux syslog / auth.log (RFC 5424 / 3164)',
  'Palo Alto CSV export',
  'Check Point SmartConsole CSV',
  'FortiGate traffic log',
  'Microsoft Entra ID sign-in CSV / JSON',
  'Exchange Online message trace CSV',
  'Other CSV / JSON (columns guessed)',
  // FR-2.3: any of the above, compressed. A multi-file .zip becomes one case.
  '.gz (streamed)',
  '.zip (multi-file → one case)',
]

/** FR-2.7: "my" uploads are the cases whose evidence this account acquired
 *  (custody's `recorded_by`), so the list follows the analyst, not the
 *  browser. Newest first - list_manifests already sorts by uploaded_at. */
function myRecent(cases, email) {
  return cases.filter((m) => m.evidence?.recorded_by === email).slice(0, RECENT_LIMIT)
}

/** Laid out as figma-export/Upload.svg: customer first (FR-2.1), then the
 *  drop area (FR-2.2) and the supported formats (FR-2.6). */
export default function Upload({ user }) {
  const fileRef = useRef(null)
  // Uploading is an analyst's or a manager's; a new customer or project a
  // manager's (IAI-14). The server refuses the same.
  const { can, why } = useAccess()
  const mayUpload = can('case:upload')
  const mayCreate = can('customer:manage')
  const [file, setFile] = useState(null)
  const [dragging, setDragging] = useState(false)
  const [companies, setCompanies] = useState([])
  const [companyId, setCompanyId] = useState('')
  const [newCompany, setNewCompany] = useState('')
  const [projects, setProjects] = useState([])
  const [projectId, setProjectId] = useState('')
  const [newProject, setNewProject] = useState('')
  const [note, setNote] = useState('')
  const [busy, setBusy] = useState(false)
  const [status, setStatus] = useState({ msg: '', cls: '' })
  const [limits, setLimits] = useState(null)
  const [recent, setRecent] = useState([])
  // FR-2.5: two separate percentages - the upload (measured by the browser)
  // and the processing of the case it created (reported on its manifest).
  const [uploadPct, setUploadPct] = useState(null)
  const [activeCase, setActiveCase] = useState(null)

  const loadCompanies = useCallback(async () => {
    try {
      setCompanies(await listCompanies())
    } catch {
      // the "add new customer" option still works without the list
    }
  }, [])

  // The project list is the chosen customer's; a new customer has none yet.
  const loadProjects = useCallback(async (id) => {
    if (!id || id === '__new__') return setProjects([])
    try {
      setProjects(await listProjects(id))
    } catch {
      setProjects([])
    }
  }, [])

  useEffect(() => {
    loadProjects(companyId)
  }, [companyId, loadProjects])

  useEffect(() => {
    loadCompanies()
    checkUpload()
      .then(setLimits)
      .catch(() => {})
  }, [loadCompanies])

  // Polls this account's uploads so the analyst can watch
  // queued -> processing -> ready without leaving the page.
  const refreshManifests = useCallback(async () => {
    try {
      setRecent(myRecent(await listCases(), user.email))
    } catch {
      // keep the last list; the next poll tries again
    }
  }, [user.email])
  const manifests = Object.fromEntries(recent.map((m) => [m.case_id, m]))

  // Poll quickly only while something is moving, so a progress bar moves
  // and an idle page stays quiet.
  const moving = busy || recent.some((m) => ['queued', 'processing'].includes(m.status))
  useEffect(() => {
    refreshManifests()
    const t = setInterval(refreshManifests, moving ? FAST_POLL_MS : POLL_MS)
    return () => clearInterval(t)
  }, [refreshManifests, moving])

  // FR-2.1: no upload without a customer. The server refuses one too; this
  // just says so before the analyst waits for a large file to go up.
  const hasCustomer = companyId === '__new__' ? !!newCompany.trim() : !!companyId
  const tooBig = !!(file && limits && file.size > limits.max_bytes)

  function pick(files) {
    if (!files || !files.length) return
    const f = files[0]
    setFile(f)
    setStatus(
      limits && f.size > limits.max_bytes
        ? { msg: `${f.name} is ${fmtBytes(f.size)} - the limit is ${fmtBytes(limits.max_bytes)} per file`, cls: 'err' }
        : { msg: '', cls: '' },
    )
  }

  function clearFile() {
    setFile(null)
    setStatus({ msg: '', cls: '' })
    if (fileRef.current) fileRef.current.value = ''
  }

  async function onSubmit(e) {
    e.preventDefault()
    if (!hasCustomer) {
      setStatus({ msg: 'Select a customer first', cls: 'err' })
      return
    }
    if (projectId === '__new__' && !newProject.trim()) {
      setStatus({ msg: 'Name the new project, or choose No project', cls: 'err' })
      return
    }
    if (!file) {
      setStatus({ msg: 'Choose a file first', cls: 'err' })
      return
    }
    setBusy(true)
    try {
      // FR-2.2: size limit and free disk space are checked before sending,
      // so a 10 GB file is refused in a second, not after it has gone up.
      setStatus({ msg: 'Checking size and disk space...', cls: '' })
      await checkUpload(file.size)
      setStatus({ msg: `Uploading ${file.name}...`, cls: '' })
      setActiveCase(null)
      setUploadPct(0)
      const data = await uploadFile({
        file,
        note,
        companyId: companyId === '__new__' ? '' : companyId,
        companyName: companyId === '__new__' ? newCompany.trim() : '',
        projectId: projectId === '__new__' ? '' : projectId,
        projectName: projectId === '__new__' ? newProject.trim() : '',
        onProgress: setUploadPct,
      })
      setUploadPct(1)
      setActiveCase(data.case_id)
      setStatus({ msg: `Uploaded - case ${data.case_id} (${data.file_kind})`, cls: 'ok' })
      setFile(null)
      setNote('')
      setNewCompany('')
      setNewProject('')
      // Keep the customer and project for the next file of the same
      // investigation - as the records just created, if they were new.
      if (companyId === '__new__') setCompanyId(data.company_id)
      if (projectId === '__new__') setProjectId(data.project_id || '')
      loadProjects(data.company_id)
      if (fileRef.current) fileRef.current.value = ''
      loadCompanies()
      refreshManifests()
    } catch (err) {
      setUploadPct(null)
      setStatus({ msg: err.message, cls: 'err' })
    } finally {
      setBusy(false)
    }
  }

  return (
    <section className="page upload-page">
      <div className="top-bar">
        <div>
          <h1>Upload Log File</h1>
          <div className="subtitle">
            Start a new case by uploading any syslog, CSV or JSON log export
          </div>
        </div>
        <a className="btn-secondary" href="#/dashboard">
          View cases
        </a>
      </div>

      {!mayUpload && <div className="status-line err">{why('case:upload')} to upload evidence.</div>}
      <form className="upload-form" onSubmit={onSubmit}>
        <div>
          <label htmlFor="company-select">Customer</label>
          <div className="customer-row">
            <select
              id="company-select"
              required
              value={companyId}
              onChange={(e) => {
                setCompanyId(e.target.value)
                setProjectId('')
              }}
            >
              <option value="" disabled>
                Select a customer
              </option>
              {companies.map((c) => (
                <option value={c.company_id} key={c.company_id}>
                  {c.name}
                </option>
              ))}
              <option value="__new__" disabled={!mayCreate}>
                + Add new customer...{mayCreate ? '' : ' (Manager)'}
              </option>
            </select>
            <span className="field-hint">required — every case belongs to exactly one customer</span>
          </div>
          {companyId === '__new__' && (
            <input
              type="text"
              placeholder="New customer name"
              aria-label="New customer name"
              style={{ marginTop: 8, maxWidth: 420 }}
              value={newCompany}
              onChange={(e) => setNewCompany(e.target.value)}
            />
          )}
        </div>

        <div>
          <label htmlFor="project-select">Project</label>
          <div className="customer-row">
            <select
              id="project-select"
              value={projectId}
              disabled={!companyId}
              onChange={(e) => setProjectId(e.target.value)}
            >
              <option value="">No project</option>
              {projects.map((p) => (
                <option value={p.project_id} key={p.project_id}>
                  {p.name}
                </option>
              ))}
              <option value="__new__" disabled={!mayCreate}>
                + Add new project...{mayCreate ? '' : ' (Manager)'}
              </option>
            </select>
            <span className="field-hint">optional — one investigation of this customer</span>
          </div>
          {projectId === '__new__' && (
            <input
              type="text"
              placeholder="New project name"
              aria-label="New project name"
              style={{ marginTop: 8, maxWidth: 420 }}
              value={newProject}
              onChange={(e) => setNewProject(e.target.value)}
            />
          )}
        </div>

        <div className="panel dropzone-panel">
          <div
            className={`dropzone${dragging ? ' drag' : ''}`}
            onClick={() => !file && fileRef.current?.click()}
            onDragEnter={(e) => {
              e.preventDefault()
              setDragging(true)
            }}
            onDragOver={(e) => {
              e.preventDefault()
              setDragging(true)
            }}
            onDragLeave={(e) => {
              e.preventDefault()
              setDragging(false)
            }}
            onDrop={(e) => {
              e.preventDefault()
              setDragging(false)
              pick(e.dataTransfer.files)
            }}
          >
            <div className="drop-icon" aria-hidden="true">↑</div>
            {file ? (
              <>
                <div className="drop-title">{file.name}</div>
                <div className="drop-sub">{fmtBytes(file.size)}</div>
                <div className="drop-actions">
                  <button type="submit" disabled={busy || !hasCustomer || tooBig || !mayUpload}
                          title={why('case:upload')}>
                    {busy ? 'Uploading...' : 'Upload'}
                  </button>
                  <button type="button" className="secondary" disabled={busy} onClick={clearFile}>
                    Choose another
                  </button>
                </div>
                {!hasCustomer && <div className="drop-sub">Select a customer above to upload</div>}
              </>
            ) : (
              <>
                <div className="drop-title">Drag and drop a log file here</div>
                <div className="drop-sub">or click to browse from your computer</div>
                <div className="drop-actions">
                  <button type="button">Browse files</button>
                </div>
              </>
            )}
            <div className="drop-hint">
              syslog / auth.log · CSV firewall exports · JSON · .gz · .zip — max{' '}
              {limits ? fmtBytes(limits.max_bytes) : '10 GB'} per file, uncompressed
            </div>
            <input type="file" ref={fileRef} onChange={(e) => pick(e.target.files)} />
          </div>
          <div className={`status-line${status.cls ? ' ' + status.cls : ''}`} role="status">
            {status.msg}
          </div>
          {uploadPct !== null && (
            <div className="progress-pair">
              <ProgressRow label="Upload" pct={Math.round(uploadPct * 100)} text={`${Math.round(uploadPct * 100)}%`} />
              <ProgressRow
                label="Processing"
                pct={activeCase ? processingPct(manifests[activeCase]) : 0}
                text={activeCase ? processingText(manifests[activeCase]) : 'Waiting for upload'}
                tone={manifests[activeCase]?.status === 'failed' ? 'err' : ''}
                link={manifests[activeCase]?.status === 'ready' ? `#/case/${activeCase}` : null}
              />
            </div>
          )}
        </div>

        <div>
          <label htmlFor="note">Note (optional)</label>
          <textarea
            id="note"
            placeholder="e.g. where the log came from, related tickets"
            value={note}
            onChange={(e) => setNote(e.target.value)}
          />
        </div>
      </form>

      <div>
        <div className="section-label">Supported formats</div>
        <div className="format-chips">
          {SUPPORTED_FORMATS.map((f) => (
            <span className="chip" key={f}>
              {f}
            </span>
          ))}
        </div>
      </div>

      <div className="panel">
        <div className="top-bar">
          <h2>My recent uploads</h2>
          {/* FR-11.1's case list lives on the Overview for now. */}
          <a className="table-link" href="#/dashboard">
            View all cases →
          </a>
        </div>
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>Uploaded</th>
                <th>Case ID</th>
                <th>File</th>
                <th>Customer</th>
                <th>Size</th>
                <th>Status</th>
                <th>Severity</th>
              </tr>
            </thead>
            <tbody>
              {!recent.length && (
                <tr>
                  <td colSpan={7} className="empty">
                    No uploads from {user.email} yet
                  </td>
                </tr>
              )}
              {recent.map((m) => {
                const ready = m.status === 'ready'
                return (
                  <tr key={m.case_id}>
                    <td>{fmtTime(m.uploaded_at)}</td>
                    <td>
                      <code>{m.case_id}</code>
                    </td>
                    <td>
                      {/* The file name opens the case once it can be read. */}
                      {ready ? (
                        <a className="table-link" href={`#/case/${m.case_id}`}>
                          {m.original_filename}
                        </a>
                      ) : (
                        m.original_filename
                      )}
                    </td>
                    <td>
                      {m.company_name || '—'}
                      {m.project_name && <div className="cell-sub">{m.project_name}</div>}
                    </td>
                    <td>
                      {fmtBytes(m.size_bytes)}
                      {/* FR-2.2's limit is on this size, not the upload's. */}
                      {m.compression && m.uncompressed_bytes != null && (
                        <div className="cell-sub">{fmtBytes(m.uncompressed_bytes)} uncompressed</div>
                      )}
                    </td>
                    <td>
                      <StatusBadge status={m.status} error={m.error} />
                      {m.status === 'processing' && m.progress && (
                        <div className="cell-sub">
                          {m.progress.estimated ? '~' : ''}
                          {m.progress.pct}%
                        </div>
                      )}
                      {m.status === 'ready' && aiText(m) && <div className="cell-sub">{aiText(m).slice(3)}</div>}
                    </td>
                    <td>{ready ? <SeverityPill severity={m.severity} /> : '—'}</td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      </div>
    </section>
  )
}

function ProgressRow({ label, pct, text, tone, link }) {
  return (
    <div className={`progress-row${tone ? ' ' + tone : ''}`}>
      <span className="progress-label">{label}</span>
      <span className="progress-track" role="progressbar" aria-label={label} aria-valuenow={pct} aria-valuemin={0} aria-valuemax={100}>
        <span className="progress-fill" style={{ width: `${pct}%` }} />
      </span>
      <span className="progress-text">{link ? <a href={link}>Open case</a> : text}</span>
    </div>
  )
}
