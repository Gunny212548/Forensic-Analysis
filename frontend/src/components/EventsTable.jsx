import { useCallback, useEffect, useState } from 'react'
import { getEvents } from '../api.js'
import { LEVEL_EN, SEV_CLASS, fmtNum } from '../format.js'
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

  if (error) return <Empty>Could not load: {error}</Empty>
  if (!data) return <Empty>Loading...</Empty>
  if (!data.events.length) {
    return (
      <Empty>
        {offset === 0
          ? 'The rule engine flagged nothing in this file'
          : 'No more events'}
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
        Showing {fmtNum(from)}-{fmtNum(to)} of {fmtNum(data.total)} findings (raw rows in the file:{' '}
        {fmtNum(data.total_rows)})
      </Empty>
      <table>
        <thead>
          <tr>
            <th>time</th>
            <th>rule</th>
            <th>level</th>
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
              <td className={SEV_CLASS[e.level] || ''}>{LEVEL_EN[e.level] || ''}</td>
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
          &larr; Previous
        </button>
        <button
          className="secondary"
          disabled={!hasNext}
          onClick={() => setOffset(offset + PAGE_SIZE)}
        >
          Next &rarr;
        </button>
      </div>
    </>
  )
}
