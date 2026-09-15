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
    return <Empty>ไม่พบรูปแบบการโจมตีหลายขั้นตอนที่ชัดเจน</Empty>
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
          ผลลัพธ์ถูกตัดกลางคัน (output token limit) - ส่วนท้าย เช่น timeline อาจไม่ครบ
          ลองวิเคราะห์ใหม่หรือลด MAX_EVENTS_FOR_ANALYSIS
        </div>
      )}
      <div className="meta-line">
        วิเคราะห์ด้วย {meta.provider}/{meta.model} · ใช้ {meta.events_analyzed}/{meta.events_total}{' '}
        events
      </div>
    </>
  )
}
