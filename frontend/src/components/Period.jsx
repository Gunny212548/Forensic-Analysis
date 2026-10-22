import { fmtNum } from '../format.js'

const TYPE = { firewall: 'Firewall', os: 'OS' }

/** The period each evidence item covers (period.py, D15): first and last event,
 *  span, days with events, gaps and events per day. */
export function Periods({ periods }) {
  if (!periods) {
    return <div className="muted">Not recorded - this case was processed before periods were kept; re-process it.</div>
  }
  if (!periods.length) return <div className="muted">No evidence item produced events.</div>
  return (
    <div className="table-scroll">
      <table className="ov-table">
        <thead>
          <tr>
            <th>File</th>
            <th>First event</th>
            <th>Last event</th>
            <th className="num">Span (days)</th>
            <th className="num">Days with events</th>
            <th>Gaps (days with none)</th>
            <th className="num">Events per day (min / median / max)</th>
          </tr>
        </thead>
        <tbody>
          {periods.map((p) => (
            <tr key={p.item}>
              <td>{p.item || '(the file)'}</td>
              <td className="mono">{p.first ? `${p.first} +07:00` : '-'}</td>
              <td className="mono">{p.last ? `${p.last} +07:00` : '-'}</td>
              <td className="num">{fmtNum(p.span_days)}</td>
              <td className="num">{fmtNum(p.active_days)}</td>
              <td>
                {p.gap_count === 0
                  ? 'none'
                  : `${fmtNum(p.gap_count)} gaps, ${fmtNum(p.gap_days)} days`}
                {p.longest_gaps?.length > 0 && (
                  <div className="muted">
                    longest: {p.longest_gaps.slice(0, 3).map((g) =>
                      g.from === g.to ? `${g.from} (1 day)` : `${g.from} to ${g.to} (${g.days} days)`).join(' · ')}
                  </div>
                )}
              </td>
              <td className="num">
                {p.events_per_day
                  ? `${fmtNum(p.events_per_day.min)} / ${fmtNum(p.events_per_day.median)} / ${fmtNum(p.events_per_day.max)}`
                  : '-'}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

/** What each product's rules cover, area by area (products.py, D12): the rules
 *  that run, or "not applicable" with the reason, or "no rule yet". */
export function Detection({ detection }) {
  if (!detection) return null
  if (!detection.length) return <div className="muted">No evidence item was read as a known product.</div>
  const areas = detection[0].areas.map((a) => ({ id: a.area, name: a.name }))
  return (
    <div className="table-scroll">
      <table className="ov-table">
        <thead>
          <tr>
            <th>Product</th>
            {areas.map((a) => (
              <th key={a.id}>{a.name}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {detection.map((d) => (
            <tr key={d.product}>
              <td>
                {d.name}
                <div className="muted">{TYPE[d.type] || 'type not set'}</div>
              </td>
              {d.areas.map((c) => (
                <td key={c.area} title={c.reason || ''}>
                  {c.status === 'rules' && (
                    <>
                      <span className="mono">{c.rules.join(', ')}</span>
                      {c.generic?.length > 0 && <div className="muted">generic rules</div>}
                    </>
                  )}
                  {c.status === 'n/a' && (
                    <>
                      n/a<div className="muted">{c.reason}</div>
                    </>
                  )}
                  {c.status === 'none' && <span className="muted">no rule yet</span>}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
