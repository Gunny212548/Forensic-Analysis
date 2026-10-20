import { useEffect, useState } from 'react'
import { getSourceProfile } from '../api.js'
import { fmtNum } from '../format.js'
import { Empty } from './common.jsx'

/** A source address's behaviour profile (specs/behaviour_profiles.md): what
 *  it did, how fast and how widely, ranked against the other addresses of the
 *  same evidence. Facts, not a verdict - nothing here is a finding. */
export default function ProfilePanel({ caseId, ip, onClose }) {
  const [data, setData] = useState(null)
  const [error, setError] = useState('')
  useEffect(() => {
    let alive = true
    setData(null)
    setError('')
    getSourceProfile(caseId, ip)
      .then((d) => alive && setData(d))
      .catch((err) => alive && setError(err.message))
    return () => {
      alive = false
    }
  }, [caseId, ip])

  return (
    <div className="profile-panel">
      <div className="profile-head">
        <strong className="mono">{ip}</strong>
        <span className="muted"> · behaviour profile - facts counted from this evidence, not a verdict</span>
        <button className="secondary profile-close" onClick={onClose}>
          Close
        </button>
      </div>
      {error && <Empty>{error}</Empty>}
      {!error && !data && <Empty>Loading...</Empty>}
      {data && (
        <>
          <div className="meta-line" style={{ marginTop: 0 }}>
            {fmtNum(data.events)} events · {data.first_seen || '?'} → {data.last_seen || '?'} ·{' '}
            {data.days_active} day{data.days_active === 1 ? '' : 's'} · active hours (GMT+7):{' '}
            {data.hours_active.length ? data.hours_active.join(', ') : '-'}
          </div>
          <div className="profile-grid">
            <Facts
              title="Sign-ins"
              facts={data.sign_ins}
              rows={[
                ['Failed', (f) => f.auth_failed],
                ['Unknown account', (f) => f.invalid_user],
                ['Succeeded', (f) => f.auth_success],
                ['Accounts tried (failed)', (f) => f.accounts_failed, 'accounts_failed'],
                ['Most failures in 1 min', (f) => f.fail_max_1m, 'fail_max_1m'],
                ['in 10 min', (f) => f.fail_max_10m, 'fail_max_10m'],
                ['in 60 min', (f) => f.fail_max_60m, 'fail_max_60m'],
                [
                  'Succeeded after failing',
                  (f) =>
                    f.success_after_fail_ts
                      ? `${f.success_after_fail_ts} (${f.success_after_fail_gap_s} s after the first failure)`
                      : 'no',
                ],
              ]}
            />
            <Facts
              title="Traffic"
              facts={data.traffic}
              rows={[
                ['Refused', (f) => f.refused],
                ['Allowed', (f) => f.allowed],
                ['Destination hosts', (f) => f.dst_hosts, 'dst_hosts'],
                ['Refused ports', (f) => f.refused_ports, 'refused_ports'],
                ['Most refused in 1 min', (f) => f.refused_max_1m, 'refused_max_1m'],
                ['in 10 min', (f) => f.refused_max_10m, 'refused_max_10m'],
                ['in 60 min', (f) => f.refused_max_60m, 'refused_max_60m'],
                ['Bytes sent to public addresses', (f) => (f.bytes_public == null ? 'n/a' : fmtNum(f.bytes_public)), 'bytes_public'],
              ]}
            />
          </div>
        </>
      )}
    </div>
  )
}

/** One group of facts, or the n/a sentence when the address has no events
 *  of that kind. A rank is shown beside a fact only when the server gave one
 *  (enough addresses of the kind in this evidence to compare with). */
function Facts({ title, facts, rows }) {
  if (typeof facts === 'string') {
    return (
      <div>
        <div className="section-label">{title}</div>
        <div className="muted">{facts}</div>
      </div>
    )
  }
  const ranks = typeof facts.rank === 'object' ? facts.rank.percent_of_addresses_below : null
  return (
    <div>
      <div className="section-label">{title}</div>
      <table className="profile-facts">
        <tbody>
          {rows.map(([label, value, rankKey]) => (
            <tr key={label}>
              <td>{label}</td>
              <td className="mono">{value(facts)}</td>
              <td className="muted">
                {ranks && rankKey && ranks[rankKey] != null ? `more than ${ranks[rankKey]}% of addresses here` : ''}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <div className="cell-sub">
        {typeof facts.rank === 'object' ? `ranked among ${facts.rank.among} addresses` : facts.rank}
      </div>
    </div>
  )
}
