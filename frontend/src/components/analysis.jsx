import { SEV_CLASS, shortTs } from '../format.js'
import { Empty, MitreTags } from './common.jsx'

/** Horizontal stage flow, shown small on Overview and full on Attack Chain. */
export function ChainFlow({ chain }) {
  if (!chain || !chain.length) return null
  return (
    <>
      <div className="section-label">Attack Chain Flow</div>
      <div className="chain-flow-wrap">
        <div className="chain-flow">
          {chain.map((stage, i) => {
            const isStart = i === 0
            const isEnd = i === chain.length - 1
            const cls = isStart ? 'start' : isEnd ? 'end' : ''
            const rangeStart = (stage.timestamp_range || '').split(' - ')[0]
            return (
              <div style={{ display: 'contents' }} key={`${stage.stage}-${i}`}>
                <div className={`chain-node ${cls}`}>
                  {isStart && <span className="badge-endpoint">START</span>}
                  {!isStart && isEnd && <span className="badge-endpoint">END</span>}
                  <div className="n-stage">{stage.stage || '?'}</div>
                  <div className="n-ts">{shortTs(rangeStart)}</div>
                  <div className="n-conf">confidence: {stage.confidence || '-'}</div>
                </div>
                {!isEnd && <div className="chain-connector">&#8594;</div>}
              </div>
            )
          })}
        </div>
      </div>
    </>
  )
}

export function ChainStages({ chain }) {
  if (!chain || !chain.length) {
    return <Empty>No clear multi-stage attack pattern was found.</Empty>
  }
  return (
    <>
      {chain.map((stage, i) => (
        <div className="chain-stage" key={`${stage.stage}-${i}`}>
          <span className="stage-conf">confidence: {stage.confidence || '-'}</span>
          <div className="stage-name">{stage.stage || ''}</div>
          <div className="stage-desc">
            {stage.description || ''} <MitreTags list={stage.mitre} />
          </div>
          <div className="stage-meta">{stage.timestamp_range || ''}</div>
        </div>
      ))}
    </>
  )
}

export function Timeline({ items }) {
  if (!items || !items.length) return null
  return (
    <>
      {items.map((item, i) => (
        <div className="timeline-item" key={`${item.timestamp}-${i}`}>
          <div className="ts">{item.timestamp || ''}</div>
          <div>
            <span className={SEV_CLASS[(item.severity || '').toLowerCase()] || ''}>
              [{item.severity || '?'}]
            </span>{' '}
            {item.event || ''}
            {item.source_ip && (
              <>
                {' — '}
                <code>{item.source_ip}</code>
              </>
            )}
            {item.target && <> → {item.target}</>}
            <MitreTags list={item.mitre} />
          </div>
        </div>
      ))}
    </>
  )
}

/** Risk-based ranking: which entities carry the most accumulated finding
 *  severity. Answers "where do I look first" in a case with tens of
 *  thousands of findings, which a per-rule list never does. The score is
 *  computed in SQL with a log-dampened per-rule term (db.risk_scores), so a
 *  busy host does not outrank a quiet one implicated by several rules. */
export function RiskTables({ risk }) {
  if (!risk) return null
  const ROLES = [
    ['sources', 'Sources'],
    ['destinations', 'Destinations'],
    ['accounts', 'Accounts'],
  ]
  const blocks = ROLES.filter(([key]) => (risk[key] || []).length)
  if (!blocks.length) return null
  return (
    <div className="risk-wrap">
      {blocks.map(([key, label]) => (
        <div className="risk-block" key={key}>
          <div className="risk-role">{label}</div>
          <table className="risk-table">
            <tbody>
              <tr>
                <th>entity</th>
                <th>score</th>
                <th>findings</th>
                <th>rules</th>
              </tr>
              {risk[key].slice(0, 6).map((i) => (
                <tr key={i.entity}>
                  <td className="risk-entity">{i.entity}</td>
                  <td className="risk-score">{i.score}</td>
                  <td className="risk-n">{i.findings}</td>
                  <td className="risk-rules">
                    <MitreTags list={i.rules} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ))}
    </div>
  )
}

export function Recommendations({ items }) {
  if (!items || !items.length) return null
  return (
    <ul className="rec-list">
      {items.map((r, i) => (
        <li key={i}>{r}</li>
      ))}
    </ul>
  )
}

/** Progress of a queued map-reduce job (CLAUDE.md: a case with more distinct
 *  findings than one model call can hold is narrated in N batches plus one
 *  synthesis call, roughly a minute each). The analyst is watching a
 *  multi-minute job, so it says which call it is on rather than spinning:
 *  the numbers come straight from the server's job record and nothing here is
 *  animated, because a screenshot of this panel has to mean something.
 *
 *  `stale` is the case where an older finished analysis is still on screen
 *  below - then this is a non-blocking note, not a placeholder. */
export function AnalysisProgress({ job, stale, stalled }) {
  if (!job) return null
  const total = job.chunks_total || 0
  const done = job.chunks_done || 0
  // N map calls + 1 reduce. The server counts a map call as done only once it
  // returns, so during map step `done` is the number finished behind us.
  const calls = job.expected_groq_calls || total + 1
  const step = job.step || 'queued'
  const at = step === 'reduce' ? calls : Math.min(done + 1, calls)
  const label =
    step === 'reduce'
      ? `Combining the results (step ${calls} of ${calls})`
      : step === 'map'
        ? `Analysing in batches: batch ${Math.min(done + 1, total)} of ${total}`
        : 'Queued - waiting to start'
  const mins = job.estimated_seconds ? Math.max(1, Math.round(job.estimated_seconds / 60)) : 0

  return (
    <div className={`job-progress${stale ? ' stale' : ''}`}>
      <div className="job-head">
        {stale ? 'Re-analysing in the background - the previous analysis is shown below' : label}
      </div>
      {stale && <div className="job-note">{label}</div>}
      <div className="job-bar">
        <span style={{ width: `${Math.round((at / calls) * 100)}%` }} />
      </div>
      <div className="job-note">
        This case is too large for one analysis ({job.distinct_total} distinct findings), so it
        runs as {total} batches + 1 summary, {calls} calls in all
        {mins ? ` · about ${mins} min` : ''} · this page updates itself
      </div>
      {job.map_reduce_capped && (
        <div className="job-note">
          More findings than can be narrated - only the {job.pool_size} most severe are analysed
          (the attack graph and risk ranking still cover the whole case; they come from SQL)
        </div>
      )}
      {stalled && (
        <div className="job-note">
          The server has not reported progress for a while (the figures above are the last received) -
          the job may still be running, just slower. This page keeps asking.
        </div>
      )}
      {job.already_running && (
        <div className="job-note">An analysis is already running, so no second one was started.</div>
      )}
    </div>
  )
}

/** `_meta.truncated` is computed server-side from *missing top-level keys*,
 *  not from finish_reason - the model can spend its last tokens on trailing
 *  whitespace after a complete object (CLAUDE.md gotcha #5). So when this
 *  warning shows, something really is absent. */
export function AnalysisMeta({ meta }) {
  if (!meta) return null
  return (
    <>
      {meta.truncated && (
        <div className="meta-warn">
          The output was cut off (output token limit) - later parts such as the timeline may be
          incomplete. Re-run the analysis or lower MAX_EVENTS_FOR_ANALYSIS.
        </div>
      )}
      <Grounding grounding={meta.grounding} />
      <div className="meta-line">
        Analysed with {meta.provider}/{meta.model} · used {meta.events_analyzed}/{meta.events_total}{' '}
        events
        {meta.reproducibility && (
          <>
            {' '}
            · {meta.reproducibility.constrained ? 'schema-constrained' : 'not schema-constrained'}
            {meta.reproducibility.seed != null &&
              ` · temperature ${meta.reproducibility.temperature}, seed ${meta.reproducibility.seed}`}
            {meta.grounding && ` · ${meta.grounding.checked} cited values checked`}
          </>
        )}
      </div>
    </>
  )
}

const GROUNDING_KIND = { ip: 'address', technique: 'ATT&CK id', email: 'e-mail', date: 'date' }

/** grounding.check() on the server: values the narrative states that were
 *  not in the evidence it was given. Shown, not removed - the analyst decides
 *  whether "10.8.1.0/24" style generalisations are fair. */
function Grounding({ grounding }) {
  if (!grounding || grounding.ok) return null
  const seen = new Set()
  const items = grounding.unsupported.filter((u) => {
    const k = `${u.kind}|${u.value}`
    if (seen.has(k)) return false
    seen.add(k)
    return true
  })
  return (
    <div className="meta-warn">
      The narrative states {items.length} value{items.length === 1 ? '' : 's'} that the evidence it was
      given does not contain - check before quoting it:{' '}
      {items.map((u, i) => (
        <span key={i}>
          {i > 0 && ', '}
          {GROUNDING_KIND[u.kind] || u.kind} <code>{u.value}</code>
        </span>
      ))}
    </div>
  )
}
