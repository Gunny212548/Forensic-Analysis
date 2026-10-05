import { useCallback, useEffect, useState } from 'react'
import { getFindings, postReview } from '../api.js'
import { REVIEW_CLASS, fmtNum, shortTs } from '../format.js'
import { Empty, MitreTags } from './common.jsx'

// Unreviewed first, whatever its confidence: a high-confidence finding
// nobody has looked at must never sit above a reviewed one (NFR-9).
const ORDER = { Unreviewed: 0, Modified: 1, Accepted: 2, Rejected: 3 }

/** The review unit is the collapsed finding (rid|srcip|username), not the
 *  row - one case has 20,063 finding rows and 4 reviewable findings, and
 *  reviewing rows one at a time is a requirement that cannot be met
 *  (CLAUDE.md gotcha #19). Decisions are append-only server-side. */
export default function ReviewPanel({ caseId }) {
  const [data, setData] = useState(null)
  const [error, setError] = useState('')
  const [rejecting, setRejecting] = useState(null) // finding key awaiting a reason
  const [reasonCode, setReasonCode] = useState('')
  const [reasonNote, setReasonNote] = useState('')
  const [busyKey, setBusyKey] = useState('')

  const load = useCallback(async () => {
    setError('')
    try {
      setData(await getFindings(caseId))
    } catch (err) {
      setError(err.message)
    }
  }, [caseId])

  useEffect(() => {
    load()
  }, [load])

  async function submit(key, action, extra = {}) {
    setBusyKey(key)
    try {
      await postReview(caseId, { finding_key: key, action, ...extra })
      setRejecting(null)
      setReasonCode('')
      setReasonNote('')
      await load()
    } catch (err) {
      setError(err.message)
    } finally {
      setBusyKey('')
    }
  }

  if (error && !data) return <Empty>{error}</Empty>
  if (!data) return <Empty>กำลังโหลด...</Empty>

  const s = data.review_summary || {}
  const unreviewed = s.Unreviewed || 0
  const findings = (data.findings || []).slice().sort((a, b) => {
    const d = ORDER[a.review.status] - ORDER[b.review.status]
    return d !== 0 ? d : b.lvl - a.lvl || b.cnt - a.cnt
  })
  const reasonCodes = data.reason_codes || {}

  return (
    <>
      {/* The export gate is stated up front, not discovered at export time:
          under a deadline an analyst needs to know what is still blocking. */}
      <div className={`rv-gate ${data.ready_for_report ? 'ok' : 'blocked'}`}>
        {data.ready_for_report
          ? 'ตรวจสอบครบทุก finding แล้ว — พร้อมออกรายงานฉบับสมบูรณ์'
          : `ยังเหลือ ${unreviewed} finding ที่ยังไม่ได้ตรวจสอบ — ยังออกรายงานฉบับสมบูรณ์ไม่ได้`}
        <span className="rv-counts">
          Accepted {s.Accepted || 0} · Modified {s.Modified || 0} · Rejected {s.Rejected || 0} ·
          Unreviewed {unreviewed}
        </span>
      </div>

      {error && <Empty>{error}</Empty>}

      {findings.map((f) => {
        const st = f.review.status
        const busy = busyKey === f.key
        return (
          <div className={`rv-item ${REVIEW_CLASS[st] || ''}`} key={f.key}>
            <div className="rv-head">
              <span className="rv-status">{st}</span>
              <span className={`rv-conf rv-conf-${f.confidence}`}>confidence: {f.confidence}</span>
              {(f.flags || []).map((x) => (
                <span className="rv-flag" key={x}>
                  {x}
                </span>
              ))}
              <span className="rv-rid">{f.rid}</span>
              <span className="rv-n">{fmtNum(f.cnt)} events</span>
            </div>
            <div className="rv-desc">
              {f.descr || ''} <MitreTags list={f.mitre} />
            </div>
            <div className="rv-meta">
              {f.ts_first || ''}
              {f.ts_last && f.ts_last !== f.ts_first ? ` → ${f.ts_last}` : ''}
            </div>
            {f.review.actor && (
              <div className="rv-who">
                {f.review.actor} · {shortTs(f.review.ts)}
                {f.review.reason_code ? ` · ${f.review.reason_code}` : ''}
              </div>
            )}

            {rejecting === f.key ? (
              // FR-4.6: a rejection carries a structured reason, so mapping
              // quality can be measured later instead of guessed at. The API
              // returns 400 without one, so it is collected here rather than
              // discovered at submit time.
              <form
                onSubmit={(e) => {
                  e.preventDefault()
                  if (!reasonCode) return
                  submit(f.key, 'reject', { reason_code: reasonCode, note: reasonNote })
                }}
              >
                <label htmlFor={`reason-${f.key}`}>เหตุผลที่ปฏิเสธ (บังคับ)</label>
                <select
                  id={`reason-${f.key}`}
                  value={reasonCode}
                  onChange={(e) => setReasonCode(e.target.value)}
                >
                  <option value="">— เลือกเหตุผล —</option>
                  {Object.entries(reasonCodes).map(([code, label]) => (
                    <option value={code} key={code}>
                      {label} ({code})
                    </option>
                  ))}
                </select>
                <textarea
                  placeholder="บันทึกเพิ่มเติม (ไม่บังคับ)"
                  value={reasonNote}
                  onChange={(e) => setReasonNote(e.target.value)}
                />
                <div className="rv-actions">
                  <button className="rv-btn rv-reject" type="submit" disabled={!reasonCode || busy}>
                    ยืนยันการปฏิเสธ
                  </button>
                  <button
                    className="rv-btn"
                    type="button"
                    onClick={() => {
                      setRejecting(null)
                      setReasonCode('')
                      setReasonNote('')
                    }}
                  >
                    ยกเลิก
                  </button>
                </div>
              </form>
            ) : (
              <div className="rv-actions">
                <button
                  className="rv-btn rv-accept"
                  disabled={busy}
                  onClick={() => submit(f.key, 'accept')}
                >
                  Accept
                </button>
                <button
                  className="rv-btn rv-modify"
                  disabled={busy}
                  onClick={() => submit(f.key, 'modify')}
                >
                  Modified
                </button>
                <button className="rv-btn rv-reject" disabled={busy} onClick={() => setRejecting(f.key)}>
                  Reject
                </button>
                {st !== 'Unreviewed' && (
                  <button
                    className="rv-btn rv-undo"
                    disabled={busy}
                    onClick={() => submit(f.key, 'unreview')}
                  >
                    Undo
                  </button>
                )}
              </div>
            )}
          </div>
        )
      })}
    </>
  )
}
