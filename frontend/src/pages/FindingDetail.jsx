import { useEffect, useState } from 'react'
import { getCase } from '../api.js'
import { fmtTime } from '../format.js'
import { Empty } from '../components/common.jsx'
import ReviewPanel from '../components/ReviewPanel.jsx'

/** One finding on its own page (#/finding/<case>/<finding key>): what the rule
 *  engine saw, the events behind it with their source files, the findings of the
 *  same attack chain, and the analyst's decision and workflow status - the part
 *  of the old case page (#/result) that belongs to a single finding. */
export default function FindingDetail({ caseId, findingKey }) {
  const [manifest, setManifest] = useState(null)
  const [error, setError] = useState('')

  useEffect(() => {
    let alive = true
    getCase(caseId)
      .then((m) => alive && setManifest(m))
      .catch((err) => alive && setError(err.message))
    return () => {
      alive = false
    }
  }, [caseId])

  return (
    <section className="page">
      <div className="top-bar">
        <div>
          <div className="back-link">
            <a href="#/findings">Findings</a>
            {manifest?.company_name && <> › {manifest.company_name}</>}
            {manifest?.original_filename && <> › {manifest.original_filename}</>}
          </div>
          <h1>Finding</h1>
          <div className="subtitle">
            {manifest && (
              <>
                <code>{manifest.case_id}</code> · uploaded {fmtTime(manifest.uploaded_at)}
              </>
            )}
          </div>
        </div>
      </div>

      <div className="panel">
        {error && <Empty>Could not load: {error}</Empty>}
        {!error && manifest && manifest.status !== 'ready' && (
          <Empty>This case is not ready - its findings are not available.</Empty>
        )}
        {!error && (!manifest || manifest.status === 'ready') && (
          <ReviewPanel
            caseId={caseId}
            onlyKey={findingKey}
            relatedHref={(key) => `#/finding/${caseId}/${encodeURIComponent(key)}`}
          />
        )}
      </div>
    </section>
  )
}
