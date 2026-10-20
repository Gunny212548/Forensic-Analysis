import { useEffect, useState } from 'react'
import { getProfile } from '../api.js'
import { fmtNum } from '../format.js'
import { Empty } from './common.jsx'

/** The behaviour profile of a source address or an account
 *  (specs/behaviour_profiles.md): what it did, how fast and how widely,
 *  ranked against the others of its kind in the same evidence. Facts, not a
 *  verdict - nothing here is a finding. */
export default function ProfilePanel({ caseId, kind, value, onClose }) {
  const [data, setData] = useState(null)
  const [error, setError] = useState('')
  useEffect(() => {
    let alive = true
    setData(null)
    setError('')
    getProfile(caseId, kind, value)
      .then((d) => alive && setData(d))
      .catch((err) => alive && setError(err.message))
    return () => {
      alive = false
    }
  }, [caseId, kind, value])

  return (
    <div className="profile-panel">
      <div className="profile-head">
        <strong className="mono">{value}</strong>
        <span className="muted">
          {' '}
          · {kind === 'account' ? 'account' : 'address'} behaviour profile - facts counted from this evidence, not a
          verdict
        </span>
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
            {kind === 'account' && ` · hosts: ${data.hosts}`}
          </div>
          {kind === 'account' ? <AccountFacts data={data} /> : <SourceFacts data={data} />}
        </>
      )}
    </div>
  )
}

function SourceFacts({ data }) {
  return (
    <div className="profile-grid">
      <Facts
        title="Sign-ins"
        facts={data.sign_ins}
        rankKey="percent_of_addresses_below"
        noun="addresses"
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
        rankKey="percent_of_addresses_below"
        noun="addresses"
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
  )
}

function AccountFacts({ data }) {
  return (
    <div className="profile-grid">
      <Facts
        title="Sign-ins"
        facts={data.sign_ins}
        rankKey="percent_of_accounts_below"
        noun="accounts"
        rows={[
          ['Failed', (f) => f.auth_failed],
          ['As an unknown account', (f) => f.invalid_user],
          ['Succeeded', (f) => f.auth_success],
          ['Sources it failed from', (f) => f.sources_failed, 'sources_failed'],
          ['Sources it signed in from', (f) => f.sources_succeeded, 'sources_succeeded'],
          ['Most sources signing in within an hour', (f) => f.success_sources_max_60m, 'success_sources_max_60m'],
          ['Most sources failing within an hour', (f) => f.fail_sources_max_60m, 'fail_sources_max_60m'],
          ['Most failures in 1 min', (f) => f.fail_max_1m, 'fail_max_1m'],
          ['in 10 min', (f) => f.fail_max_10m, 'fail_max_10m'],
          ['in 60 min', (f) => f.fail_max_60m, 'fail_max_60m'],
        ]}
      />
    </div>
  )
}

/** One group of facts, or the n/a sentence when there are no events of that
 *  kind. A rank is shown beside a fact only when the server gave one (enough
 *  others of the kind in this evidence to compare with). */
function Facts({ title, facts, rows, rankKey, noun }) {
  if (typeof facts === 'string') {
    return (
      <div>
        <div className="section-label">{title}</div>
        <div className="muted">{facts}</div>
      </div>
    )
  }
  const ranks = typeof facts.rank === 'object' ? facts.rank[rankKey] : null
  return (
    <div>
      <div className="section-label">{title}</div>
      <table className="profile-facts">
        <tbody>
          {rows.map(([label, value, key]) => (
            <tr key={label}>
              <td>{label}</td>
              <td className="mono">{value(facts)}</td>
              <td className="muted">
                {ranks && key && ranks[key] != null ? `more than ${ranks[key]}% of ${noun} here` : ''}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <div className="cell-sub">
        {typeof facts.rank === 'object' ? `ranked among ${facts.rank.among} ${noun}` : facts.rank}
      </div>
    </div>
  )
}
