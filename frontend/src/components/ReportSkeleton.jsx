import { useCallback, useEffect, useRef, useState } from 'react'
import { getReportSkeleton, uploadReportSkeleton } from '../api.js'
import { fmtBytes, fmtTime } from '../format.js'

/** Settings - the report skeleton (docs/specs/forensic_report.md R-D11): the provider's Word
 *  layout every report draft is filled into. An administrator downloads it, edits it in
 *  Word and uploads it again; every version is kept and the newest is used. The server
 *  refuses a skeleton that misses a tag, uses an unknown one or links anything outside
 *  the file, and says why. */
export default function ReportSkeleton() {
  const [data, setData] = useState(null)
  const [error, setError] = useState('')
  const [problems, setProblems] = useState([])
  const [busy, setBusy] = useState(false)
  const [done, setDone] = useState('')
  const [showTags, setShowTags] = useState(false)
  const formRef = useRef(null)

  const load = useCallback(async () => {
    try {
      setData(await getReportSkeleton())
      setError('')
    } catch (err) {
      setError(err.message)
    }
  }, [])
  useEffect(() => {
    load()
  }, [load])

  async function upload(e) {
    e.preventDefault()
    const file = formRef.current.elements.file.files[0]
    if (!file) {
      setError('Choose the skeleton (.docx)')
      return
    }
    setBusy(true)
    setError('')
    setProblems([])
    setDone('')
    try {
      const line = await uploadReportSkeleton(file)
      setDone(`${line.file} is the skeleton now`)
      formRef.current.elements.file.value = ''
      await load()
    } catch (err) {
      setError(err.message)
      setProblems(err.problems || [])
    } finally {
      setBusy(false)
    }
  }

  const cur = data?.current
  const href = (sha) => `/api/settings/report-skeleton/${sha}`
  return (
    <div className="panel">
      <h2>Report skeleton</h2>
      <p className="cell-sub">
        The Word layout every report draft is filled into - letterhead, headers, footers, the
        sections and their tags. Download it, change it in Word, upload it again; the newest is
        used and every earlier one is kept.
      </p>
      {cur ? (
        <dl className="cp-dl">
          <dt>In use</dt>
          <dd>
            <a href={href(cur.sha256)} download>{cur.file || 'skeleton.docx'}</a>{' '}
            <span className="cell-sub">{fmtBytes(cur.bytes)}</span>
          </dd>
          <dt>Uploaded</dt>
          <dd>{fmtTime(cur.ts)} by {cur.actor}</dd>
          <dt>SHA-256</dt>
          <dd className="mono cell-sub">{cur.sha256}</dd>
        </dl>
      ) : (
        <div className="rv-gate blocked">
          No skeleton uploaded - no report draft can be made until one is.
        </div>
      )}
      <form ref={formRef} className="lc-form report-form" onSubmit={upload}>
        <label>
          Upload a skeleton (.docx, at most {data ? fmtBytes(data.max_bytes) : '20 MB'})
          <input type="file" name="file" accept=".docx" />
        </label>
        <div className="lc-actions">
          <button type="submit" disabled={busy}>{busy ? 'Checking...' : 'Upload'}</button>
        </div>
      </form>
      {error && <div className="lc-error">{error}</div>}
      {problems.length > 0 && (
        <ul className="lc-error">
          {problems.map((p) => <li key={p}>{p}</li>)}
        </ul>
      )}
      {done && <div className="status-line ok">{done}</div>}

      {data && (
        <>
          <div className="section-label">
            Tags a skeleton may use{' '}
            <button type="button" className="secondary" onClick={() => setShowTags(!showTags)}>
              {showTags ? 'Hide' : `Show ${Object.keys(data.tags).length}`}
            </button>
          </div>
          {showTags && (
            <div className="table-scroll">
              <table className="ov-table">
                <thead>
                  <tr>
                    <th>Tag</th>
                    <th>Holds</th>
                    <th>Required</th>
                  </tr>
                </thead>
                <tbody>
                  {Object.entries(data.tags).map(([tag, what]) => (
                    <tr key={tag}>
                      <td className="mono">{`{{ ${tag} }}`}</td>
                      <td className="cell-sub">{what}</td>
                      <td>{data.required.includes(tag) ? 'required' : ''}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              <p className="cell-sub">
                A row tag repeats a table row: put <span className="mono">{'{%tr for e in evidence %}'}</span> in
                the row above and <span className="mono">{'{%tr endfor %}'}</span> in the row below. An item tag
                repeats a paragraph the same way with <span className="mono">{'{%p for x in limitations %}'}</span>.
              </p>
            </div>
          )}
          {data.history.length > 1 && (
            <>
              <div className="section-label">Earlier skeletons</div>
              <div className="table-scroll">
                <table className="ov-table">
                  <thead>
                    <tr>
                      <th>Uploaded</th>
                      <th>By</th>
                      <th>File</th>
                      <th>SHA-256</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.history.slice(1).map((e) => (
                      <tr key={e.seq ?? e.sha256 + e.ts}>
                        <td className="cell-sub">{fmtTime(e.ts)}</td>
                        <td className="mono">{e.actor}</td>
                        <td><a href={href(e.sha256)} download>{e.file || 'skeleton.docx'}</a></td>
                        <td className="mono cell-sub">{e.sha256.slice(0, 16)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          )}
        </>
      )}
    </div>
  )
}
