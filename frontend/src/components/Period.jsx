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

/** Which SigmaHQ rule set ran on this evidence and what could not (specs/sigma_windows.md):
 *  a rule with no event of its log source here is not applicable, never a 0; one reading ETW
 *  or a channel the Sigma taxonomy does not name cannot be read; one pySigma could not convert
 *  is listed too (ADR-006 decision 3). High / critical rules are suggestions, the rest marks. */
export function Sigma({ sigma }) {
  if (!sigma) return null
  if (sigma.status !== 'ran') return <div className="muted">{sigma.reason || 'SigmaHQ rules did not run.'}</div>
  const p = sigma.provenance || {}
  const suggested = Object.values(sigma.suggestions || {}).reduce((a, b) => a + b, 0)
  const marked = Object.values(sigma.marks || {}).reduce((a, b) => a + b, 0)
  return (
    <div>
      <table className="ov-table">
        <tbody>
          <tr>
            <th>Rule set</th>
            <td>
              <a href={`${p.source}/tree/${p.commit}`} target="_blank" rel="noreferrer noopener" className="mono">
                SigmaHQ {(p.commit || '').slice(0, 7)}
              </a>{' '}
              · {fmtNum(sigma.rules)} Windows rules ·{' '}
              <a href={p.license_url} target="_blank" rel="noreferrer noopener">
                {p.license}
              </a>
              <div className="muted">
                converted by pySigma {p.pysigma} (SQLite backend {p.pysigma_backend_sqlite}, DuckDB dialect) ·{' '}
                {p.taxonomy} · file SHA-256 <span className="mono">{(sigma.sha256 || '').slice(0, 16)}</span>
              </div>
            </td>
          </tr>
          <tr>
            <th>Ran</th>
            <td>
              {fmtNum(sigma.ran)} rules had events of their log source
              <div className="muted">
                {fmtNum(sigma.not_applicable)} not applicable (no such events here) · {fmtNum(sigma.not_readable)} cannot
                be read (ETW, or a channel the taxonomy does not name) · {fmtNum(sigma.not_convertible)} not convertible
              </div>
            </td>
          </tr>
          <tr>
            <th>Matched</th>
            <td>
              {fmtNum(Object.keys(sigma.suggestions || {}).length)} high / critical rules on {fmtNum(suggested)} events
              (suggestions) · {fmtNum(Object.keys(sigma.marks || {}).length)} other rules on {fmtNum(marked)} events
              (marks on the timeline)
            </td>
          </tr>
          {sigma.errors?.length > 0 && (
            <tr>
              <th>Failed</th>
              <td>
                {sigma.errors.map((e) => (
                  <div key={e.rid} className="mono muted">
                    {e.rid}: {e.error}
                  </div>
                ))}
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  )
}

const METHOD_NAMES = {
  trw: 'TRW',
  'no-line': 'No line',
  cusum: 'CUSUM over the site',
  'fleet-wide': 'Fleet-wide timers left out',
}

/** How each line-drawing rule decided on this evidence (lines.py, D16): TRW's
 *  decisions, the line measured on the legitimate members, no line, the site's
 *  CUSUM (gotcha #68) or the beacons the whole fleet shares (W-D11). */
export function Lines({ lines }) {
  const rows = Object.entries(lines || {})
  if (!rows.length) return null
  return (
    <div className="table-scroll">
      <table className="ov-table">
        <thead>
          <tr>
            <th>Rule</th>
            <th>Method</th>
            <th>On this evidence</th>
          </tr>
        </thead>
        <tbody>
          {rows.map(([rid, r]) => (
            <tr key={rid}>
              <td className="mono">{rid}</td>
              <td>
                {METHOD_NAMES[r.method] || 'Line from the evidence'}
                <div className="muted">{r.source}</div>
              </td>
              <td>
                {r.method === 'trw' ? (
                  <>
                    {fmtNum(r.sources.scanner)} scanner · {fmtNum(r.sources.benign)} benign ·{' '}
                    {fmtNum(r.sources.pending)} undecided
                    <div className="muted">
                      benign sources succeeded{' '}
                      {r.measured_success_benign == null ? '-' : `${(r.measured_success_benign * 100).toFixed(1)}%`} of
                      first attempts (the paper assumes 80%)
                      {r.assumption_holds === false && ' - the assumption does not hold on this evidence'}
                    </div>
                  </>
                ) : (
                  <>
                    {r.note}
                    <div className="muted">{r.population}</div>
                  </>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
