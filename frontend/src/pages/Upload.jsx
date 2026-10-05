import { useCallback, useEffect, useRef, useState } from 'react'
import { checkUpload, getCase, listCompanies, uploadFile } from '../api.js'
import { fmtBytes, fmtTime } from '../format.js'
import { ResultLink, SeverityPill, StatusBadge } from '../components/common.jsx'

const RECENT_KEY = 'fa_recent_uploads'
const POLL_MS = 5000
const FAST_POLL_MS = 1500

/** "Processing 42%" for a manifest, "~42%" when the pipeline says it is an
 *  estimate (the CSV fast path, see pipeline.Progress). */
function processingText(m) {
  if (!m) return ''
  if (m.status === 'queued') return 'Queued'
  if (m.status === 'failed') return 'Failed'
  if (m.status === 'ready') return 'Done'
  const p = m.progress
  if (!p) return 'Processing...'
  return `Processing ${p.estimated ? '~' : ''}${p.pct}%`
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
  'VMware ESXi auth.log',
  'Linux syslog / auth.log',
  'Palo Alto CSV export',
  'Check Point SmartLog CSV',
  'Azure AD sign-in CSV',
  'Generic JSON',
  // FR-2.3: any of the above, compressed. A multi-file .zip becomes one case.
  '.gz (streamed)',
  '.zip (multi-file → one case)',
]

// Per-browser convenience only - the server is the record of what exists.
// Wrapped because storage throws in a private window or with site data
// blocked, and the page has to render anyway.
function getRecent() {
  try {
    return JSON.parse(localStorage.getItem(RECENT_KEY) || '[]')
  } catch {
    return []
  }
}

function addRecent(item) {
  const list = getRecent().filter((i) => i.case_id !== item.case_id)
  list.unshift(item)
  try {
    localStorage.setItem(RECENT_KEY, JSON.stringify(list.slice(0, 10)))
  } catch {
    // nothing to do - the upload still happened, only the local list is lost
  }
}

/** Laid out as figma-export/Upload.svg: customer first (FR-2.1), then the
 *  drop area (FR-2.2) and the supported formats (FR-2.6). */
export default function Upload() {
  const fileRef = useRef(null)
  const [file, setFile] = useState(null)
  const [dragging, setDragging] = useState(false)
  const [companies, setCompanies] = useState([])
  const [companyId, setCompanyId] = useState('')
  const [newCompany, setNewCompany] = useState('')
  const [note, setNote] = useState('')
  const [busy, setBusy] = useState(false)
  const [status, setStatus] = useState({ msg: '', cls: '' })
  const [limits, setLimits] = useState(null)
  const [recent, setRecent] = useState(getRecent)
  const [manifests, setManifests] = useState({})
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

  useEffect(() => {
    loadCompanies()
    checkUpload()
      .then(setLimits)
      .catch(() => {})
  }, [loadCompanies])

  // Polls the manifest of every upload made from this browser so the analyst
  // can watch queued -> processing -> ready without leaving the page.
  const refreshManifests = useCallback(async () => {
    const list = getRecent()
    setRecent(list)
    const entries = await Promise.all(
      list.map(async (item) => {
        try {
          return [item.case_id, await getCase(item.case_id)]
        } catch {
          return [item.case_id, null]
        }
      }),
    )
    setManifests(Object.fromEntries(entries))
  }, [])

  // Poll quickly only while something is moving, so a progress bar moves
  // and an idle page stays quiet.
  const moving = busy || Object.values(manifests).some((m) => m && ['queued', 'processing'].includes(m.status))
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
        onProgress: setUploadPct,
      })
      setUploadPct(1)
      setActiveCase(data.case_id)
      setStatus({ msg: `Uploaded - case ${data.case_id} (${data.file_kind})`, cls: 'ok' })
      addRecent({
        case_id: data.case_id,
        filename: file.name,
        uploaded_at: new Date().toISOString(),
      })
      setFile(null)
      setNote('')
      setNewCompany('')
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

      <form className="upload-form" onSubmit={onSubmit}>
        <div>
          <label htmlFor="company-select">Customer</label>
          <div className="customer-row">
            <select
              id="company-select"
              required
              value={companyId}
              onChange={(e) => setCompanyId(e.target.value)}
            >
              <option value="" disabled>
                Select a customer
              </option>
              {companies.map((c) => (
                <option value={c.company_id} key={c.company_id}>
                  {c.name}
                </option>
              ))}
              <option value="__new__">+ Add new customer...</option>
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
                  <button type="submit" disabled={busy || !hasCustomer || tooBig}>
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
                link={manifests[activeCase]?.status === 'ready' ? `#/result/${activeCase}` : null}
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
          <h2>สถานะการอัปโหลดล่าสุด</h2>
        </div>
        <table>
          <thead>
            <tr>
              <th>เวลาอัปโหลด</th>
              <th>ไฟล์</th>
              <th>บริษัท</th>
              <th>สถานะ</th>
              <th>ความเสี่ยง</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {!recent.length && (
              <tr>
                <td colSpan={6} className="empty">
                  ยังไม่มีการอัปโหลดจากหน้านี้ในเบราว์เซอร์นี้
                </td>
              </tr>
            )}
            {recent.map((item) => {
              const m = manifests[item.case_id]
              if (!m) {
                return (
                  <tr key={item.case_id}>
                    <td>{fmtTime(item.uploaded_at)}</td>
                    <td>
                      {item.filename}
                      <br />
                      <code>{item.case_id}</code>
                    </td>
                    <td colSpan={4} className="empty">
                      ไม่พบเคสนี้แล้ว
                    </td>
                  </tr>
                )
              }
              const ready = m.status === 'ready'
              return (
                <tr key={item.case_id}>
                  <td>{fmtTime(m.uploaded_at)}</td>
                  <td>
                    {m.original_filename}
                    <br />
                    <code>{m.case_id}</code>
                  </td>
                  <td>{m.company_name || '—'}</td>
                  <td>
                    <StatusBadge status={m.status} error={m.error} />
                    {m.status === 'processing' && m.progress && (
                      <div className="cell-sub">
                        {m.progress.estimated ? '~' : ''}
                        {m.progress.pct}%
                      </div>
                    )}
                  </td>
                  <td>{ready ? <SeverityPill severity={m.severity} /> : '—'}</td>
                  <td>
                    <ResultLink caseId={m.case_id} ready={ready}>
                      ดูผลลัพธ์
                    </ResultLink>
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
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
