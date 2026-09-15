import { useCallback, useEffect, useState } from 'react'
import { getEvents } from '../api.js'
import { fmtNum } from '../format.js'
import { Empty, MitreTags } from './common.jsx'

const PAGE_SIZE = 100

/** Paginated, server-side. A case can hold 65k+ rows and 25k findings, so
 *  the client never pulls the whole table - the offset lives here and every
 *  page is its own query. */
export default function EventsTable({ caseId }) {
  const [offset, setOffset] = useState(0)
  const [data, setData] = useState(null)
  const [error, setError] = useState('')

  const load = useCallback(async () => {
    setError('')
    try {
      setData(await getEvents(caseId, { limit: PAGE_SIZE, offset }))
    } catch (err) {
      setError(err.message)
    }
  }, [caseId, offset])

  useEffect(() => {
    load()
  }, [load])

  if (error) return <Empty>โหลดไม่สำเร็จ: {error}</Empty>
  if (!data) return <Empty>กำลังโหลด...</Empty>
  if (!data.events.length) {
    return (
      <Empty>
        {offset === 0
          ? 'rule engine ไม่พบเหตุการณ์ที่น่าสนใจในไฟล์นี้'
          : 'ไม่มีข้อมูลเพิ่มเติม'}
      </Empty>
    )
  }

  const from = data.offset + 1
  const to = data.offset + data.count
  const hasPrev = data.offset > 0
  const hasNext = to < data.total

  return (
    <>
      <Empty style={{ paddingBottom: 8 }}>
        แสดง {fmtNum(from)}-{fmtNum(to)} จาก {fmtNum(data.total)} findings (ข้อมูลดิบทั้งหมด{' '}
        {fmtNum(data.total_rows)} แถว)
      </Empty>
      <table>
        <thead>
          <tr>
            <th>เวลา</th>
            <th>rule</th>
            <th>lvl</th>
            <th>description</th>
            <th>mitre</th>
          </tr>
        </thead>
        <tbody>
          {data.events.map((e, i) => (
            <tr key={`${e.row_id}-${e.rid}-${i}`}>
              {/* ts is the parsed GMT+7 event time; ts_raw is the source text,
                  shown only when nothing parsed (CLAUDE.md gotcha #21). */}
              <td>{e.ts || e.ts_raw || ''}</td>
              <td>{e.rid || ''}</td>
              <td>{e.lvl ?? ''}</td>
              <td>{e.descr || ''}</td>
              <td>
                <MitreTags list={e.mitre} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <div style={{ display: 'flex', gap: 8, marginTop: 14 }}>
        <button
          className="secondary"
          disabled={!hasPrev}
          onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}
        >
          &larr; ก่อนหน้า
        </button>
        <button
          className="secondary"
          disabled={!hasNext}
          onClick={() => setOffset(offset + PAGE_SIZE)}
        >
          ถัดไป &rarr;
        </button>
      </div>
    </>
  )
}
