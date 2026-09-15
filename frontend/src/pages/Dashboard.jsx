import { useCallback, useEffect, useMemo, useState } from 'react'
import { listCases } from '../api.js'
import { fmtBytes, fmtNum, fmtTime } from '../format.js'
import { Empty, ResultLink, SeverityPill, StatusBadge } from '../components/common.jsx'

const POLL_MS = 15000

export default function Dashboard() {
  const [cases, setCases] = useState(null)
  const [error, setError] = useState('')
  const [filter, setFilter] = useState('')

  const load = useCallback(async () => {
    try {
      setCases(await listCases())
      setError('')
    } catch (err) {
      setError(err.message)
    }
  }, [])

  useEffect(() => {
    load()
    const t = setInterval(load, POLL_MS)
    return () => clearInterval(t)
  }, [load])

  // Filter options are built from the cases actually present, not the full
  // company registry - a company with no uploads yet doesn't clutter the list.
  const companies = useMemo(() => {
    const map = new Map()
    let hasNone = false
    for (const c of cases || []) {
      if (c.company_id) map.set(c.company_id, c.company_name || c.company_id)
      else hasNone = true
    }
    return {
      sorted: [...map.entries()].sort((a, b) => a[1].localeCompare(b[1])),
      hasNone,
    }
  }, [cases])

  const shown = useMemo(() => {
    const list = cases || []
    if (!filter) return list
    if (filter === '__none__') return list.filter((c) => !c.company_id)
    return list.filter((c) => c.company_id === filter)
  }, [cases, filter])

  return (
    <section className="page">
      <div className="top-bar">
        <div>
          <h1>Dashboard</h1>
          <div className="subtitle">ภาพรวมทุกเคสที่อัปโหลด พร้อมระดับความเสี่ยงแบบเห็นได้ทันที</div>
        </div>
        <div className="filter-bar" style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          <select value={filter} onChange={(e) => setFilter(e.target.value)}>
            <option value="">ทุกบริษัท</option>
            {companies.sorted.map(([id, name]) => (
              <option value={id} key={id}>
                {name}
              </option>
            ))}
            {companies.hasNone && <option value="__none__">ไม่ระบุบริษัท</option>}
          </select>
          <button className="secondary" onClick={load}>
            รีเฟรช
          </button>
        </div>
      </div>

      <div className="panel">
        <table>
          <thead>
            <tr>
              <th>เวลาอัปโหลด</th>
              <th>ไฟล์</th>
              <th>บริษัท</th>
              <th>ชนิด</th>
              <th>ขนาด</th>
              <th>สถานะ</th>
              <th>ความเสี่ยง</th>
              <th>Findings / แถวทั้งหมด</th>
              <th>หมายเหตุ</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {error && (
              <tr>
                <td colSpan={10} className="empty">
                  โหลดไม่สำเร็จ: {error}
                </td>
              </tr>
            )}
            {!error && cases === null && (
              <tr>
                <td colSpan={10} className="empty">
                  กำลังโหลด...
                </td>
              </tr>
            )}
            {!error && cases !== null && !shown.length && (
              <tr>
                <td colSpan={10} className="empty">
                  {cases.length ? 'ไม่มีเคสของบริษัทที่เลือก' : 'ยังไม่มีเคสที่อัปโหลด'}
                </td>
              </tr>
            )}
            {!error &&
              shown.map((c) => {
                const ready = c.status === 'ready'
                const sev = c.severity || {}
                const rowCls =
                  ready && sev.critical > 0
                    ? 'sev-row-critical'
                    : ready && sev.high > 0
                      ? 'sev-row-high'
                      : ''
                return (
                  <tr className={rowCls} key={c.case_id}>
                    <td>{fmtTime(c.uploaded_at)}</td>
                    <td>
                      {c.original_filename}
                      <br />
                      <code>{c.case_id}</code>
                    </td>
                    <td>{c.company_name || '—'}</td>
                    <td>{c.file_kind}</td>
                    <td>{fmtBytes(c.size_bytes)}</td>
                    <td>
                      <StatusBadge status={c.status} error={c.error} />
                    </td>
                    <td>{ready ? <SeverityPill severity={c.severity} /> : '—'}</td>
                    <td>
                      {ready ? (
                        <>
                          <span className={`badge ${c.flagged_count > 0 ? 'count-n' : 'count-0'}`}>
                            {fmtNum(c.flagged_count)}
                          </span>{' '}
                          / {fmtNum(c.total_rows)}
                        </>
                      ) : (
                        '—'
                      )}
                    </td>
                    <td>{c.note || ''}</td>
                    <td className="actions">
                      <ResultLink caseId={c.case_id} ready={ready}>
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
