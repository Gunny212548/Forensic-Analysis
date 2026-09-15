import { useCallback, useEffect, useRef, useState } from 'react'
import { getCase, listCompanies, uploadFile } from '../api.js'
import { fmtTime } from '../format.js'
import { ResultLink, SeverityPill, StatusBadge } from '../components/common.jsx'

const RECENT_KEY = 'fa_recent_uploads'
const POLL_MS = 5000

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
  const [recent, setRecent] = useState(getRecent)
  const [manifests, setManifests] = useState({})

  const loadCompanies = useCallback(async () => {
    try {
      setCompanies(await listCompanies())
    } catch {
      // a missing company list must not block an upload
    }
  }, [])

  useEffect(() => {
    loadCompanies()
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

  useEffect(() => {
    refreshManifests()
    const t = setInterval(refreshManifests, POLL_MS)
    return () => clearInterval(t)
  }, [refreshManifests])

  function pick(files) {
    if (files && files.length) setFile(files[0])
  }

  async function onSubmit(e) {
    e.preventDefault()
    if (!file) {
      setStatus({ msg: 'กรุณาเลือกไฟล์ก่อน', cls: 'err' })
      return
    }
    setBusy(true)
    setStatus({ msg: 'กำลังอัปโหลดและประมวลผล...', cls: '' })
    try {
      const data = await uploadFile({
        file,
        note,
        companyId: companyId === '__new__' ? '' : companyId,
        companyName: companyId === '__new__' ? newCompany.trim() : '',
      })
      setStatus({ msg: `สำเร็จ: ${data.case_id} (${data.file_kind})`, cls: 'ok' })
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
      setStatus({ msg: err.message, cls: 'err' })
    } finally {
      setBusy(false)
    }
  }

  return (
    <section className="page">
      <div className="top-bar">
        <div>
          <h1>Upload</h1>
          <div className="subtitle">
            อัปโหลด log (syslog/CSV/JSON ใดก็ได้) แล้วติดตามสถานะการประมวลผลได้ที่นี่
          </div>
        </div>
      </div>

      <div className="panel">
        <h2>อัปโหลดไฟล์ log</h2>
        <form onSubmit={onSubmit}>
          <div
            className={`dropzone${dragging ? ' drag' : ''}`}
            onClick={() => fileRef.current?.click()}
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
            <div>ลากไฟล์มาวาง หรือคลิกเพื่อเลือกไฟล์</div>
            <div className="hint">
              รองรับ .log / .txt (syslog, auth.log ฯลฯ), .csv (firewall export), .json —
              ตรวจชนิดไฟล์อัตโนมัติจากนามสกุล
            </div>
            <div className="filename">{file ? file.name : ''}</div>
            <input type="file" ref={fileRef} onChange={(e) => pick(e.target.files)} />
          </div>

          <div>
            <label htmlFor="company-select">บริษัท/ลูกค้า (ไม่บังคับ)</label>
            <select
              id="company-select"
              value={companyId}
              onChange={(e) => setCompanyId(e.target.value)}
            >
              <option value="">— ไม่ระบุบริษัท —</option>
              {companies.map((c) => (
                <option value={c.company_id} key={c.company_id}>
                  {c.name}
                </option>
              ))}
              <option value="__new__">+ เพิ่มบริษัทใหม่...</option>
            </select>
            {companyId === '__new__' && (
              <input
                type="text"
                placeholder="ชื่อบริษัทใหม่"
                style={{ marginTop: 8 }}
                value={newCompany}
                onChange={(e) => setNewCompany(e.target.value)}
              />
            )}
          </div>

          <div>
            <label htmlFor="note">หมายเหตุ (ไม่บังคับ)</label>
            <textarea
              id="note"
              placeholder="เช่น ที่มาของ log, เคสที่เกี่ยวข้อง"
              value={note}
              onChange={(e) => setNote(e.target.value)}
            />
          </div>

          <button type="submit" disabled={busy}>
            อัปโหลด
          </button>
          <div className={`status-line${status.cls ? ' ' + status.cls : ''}`}>{status.msg}</div>
        </form>
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
