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

  // Refused for integrity (case_views.integrity_refused): still listed, with a warning.
  const refused = manifest?.status === 'failed' && (manifest.error || '').startsWith('IntegrityError')

  return (
    <section className="page">
      <div className="top-bar">
        <div>
          <div className="back-link">
            <a href="#/findings">Findings</a>
            {manifest?.company_name && <> › {manifest.company_name}</>}
            {manifest?.original_filename && (
              // Back to the case, on the step a finding is worked in.
              <> › <a href={`#/case/${caseId}/investigate`}>{manifest.original_filename}</a></>
            )}
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
        {!error && manifest && manifest.status !== 'ready' && !refused && (
          <Empty>This case is not ready - its findings are not available.</Empty>
        )}
        {refused && (
          <div className="rv-chain ev-bad">
            The evidence file of this case no longer matches the digest recorded when it was acquired, and
            re-processing was refused. This finding is from the last run on the unaltered file; check the
            case&apos;s Evidence before acting on it.
          </div>
        )}
        {!error && (!manifest || manifest.status === 'ready' || refused) && (
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
