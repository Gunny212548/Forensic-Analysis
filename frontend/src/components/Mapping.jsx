/** How a file's columns were read (app/services/logsources.py): from the
 *  log source's own format documentation, guessed from column names, or not
 *  at all. "Log source" is the product that wrote the log (Sigma's
 *  `logsource`), never "vendor" - one company ships several log sources.
 *  A guessed mapping is the one thing here an analyst must check before
 *  trusting the findings, so it is stated as a warning, not a footnote. */

const FIELD_EN = {
  ts: 'time',
  srcip: 'source IP',
  dstip: 'destination IP',
  dstport: 'destination port',
  username: 'account',
  verdict: 'firewall action',
  app: 'application',
  risk: 'app risk',
  bytes_sent: 'bytes sent',
  category: 'category',
  auth_status: 'sign-in result',
}

function Docs({ docs }) {
  if (!docs?.length) return null
  return (
    <ul className="map-docs">
      {docs.map((d) => (
        <li key={d.url}>
          <a href={d.url} target="_blank" rel="noreferrer noopener">
            {d.title}
          </a>
        </li>
      ))}
    </ul>
  )
}

function fieldList(fields, only) {
  return Object.entries(fields || {})
    .filter(([f]) => !only || only.includes(f))
    .map(([f, v]) => `${FIELD_EN[f] || f} ← ${v.columns.join(' / ')}`)
    .join(' · ')
}

const JSON_LAYOUT = {
  lines: 'JSON-lines',
  array: 'a JSON array',
  object: 'one JSON document',
  concatenated: 'JSON documents one after another',
}

/** How a JSON file was read (parsers.iter_json): its layout, and - stated,
 *  never left out - every record that could not be read as one (IAI-35).
 *  Those rows are still in the case, decoded as plain text lines. */
function JsonNote({ stats, label }) {
  if (!stats) return null
  const bad = stats.unparseable || 0
  const at = stats.unparseable_at || []
  return (
    <div className={`map-note${bad || stats.broken_at_byte != null ? ' map-warn' : ''}`}>
      {label}Read as {JSON_LAYOUT[stats.layout] || 'JSON'}
      {stats.wrapper && <> (records inside its &quot;{stats.wrapper}&quot; array)</>}:{' '}
      {(stats.records || 0).toLocaleString()} records.
      {bad > 0 && (
        <>
          {' '}
          {bad.toLocaleString()} {bad === 1 ? 'entry was' : 'entries were'} not a readable JSON record (
          {at.join(', ')}
          {bad > at.length ? ', ...' : ''}) - kept in the case as text, where no column-based rule can fire on{' '}
          {bad === 1 ? 'it' : 'them'}.
        </>
      )}
      {stats.broken_at_byte != null && (
        <>
          {' '}
          <strong>The file breaks off at character {stats.broken_at_byte.toLocaleString()}</strong> - nothing
          after that point could be read.
        </>
      )}
    </div>
  )
}

/** What of the file was actually read (pipeline._coverage, IAI-31): rows in
 *  the case, rows the bulk load refused, timestamps that did not parse, and
 *  per mapped field how many rows carry a value - the "0 findings: schema
 *  mismatch or a boring log?" question (gotcha #7) answered on the page. */
function CoverageNote({ cov, label }) {
  if (!cov) return null
  const n = (v) => (v ?? 0).toLocaleString()
  const fields = Object.entries(cov.fields || {})
  const problem = cov.not_loaded > 0 || cov.time_unparsed > 0
  return (
    <div className={`map-note${problem ? ' map-warn' : ''}`}>
      {label}
      {n(cov.rows)} rows read.
      {cov.not_loaded > 0 && (
        <>
          {' '}
          <strong>{n(cov.not_loaded)} decoded rows could not be loaded</strong> and are not in the case.
        </>
      )}
      {cov.time_unparsed > 0 && <> {n(cov.time_unparsed)} rows have a timestamp that could not be read.</>}
      {fields.length > 0 && (
        <div className="map-sub">
          Rows with a value, per mapped field:{' '}
          {fields
            .map(([f, c]) => `${FIELD_EN[f] || f} ${n(c)}${c === 0 ? ' (empty in every row)' : ''}`)
            .join(' · ')}
        </div>
      )}
    </div>
  )
}

function One({ mapping, name }) {
  if (!mapping) return null
  const label = name ? <strong>{name}: </strong> : null
  const notes = (
    <>
      {mapping.json && <JsonNote stats={mapping.json} label={label} />}
      <CoverageNote cov={mapping.coverage} label={label} />
    </>
  )

  if (mapping.method === 'unrecognised') {
    return (
      <>
        <div className="map-note map-warn">
          {label}No documented log format was recognised in this file. Only timestamps and IP
          addresses were extracted, so no detection rule can fire on it.
        </div>
        {notes}
      </>
    )
  }

  if (mapping.line_profiles) {
    return (
      <>
      <div className="map-note">
        {label}Read with documented message formats:{' '}
        {mapping.line_profiles
          .map(
            (p) =>
              `${p.name} (${p.lines.toLocaleString()} lines` +
              // Seen in real logs, not published by the log source: read,
              // but not vouched for by any documentation.
              (p.observed ? ' - format observed in real logs, not documented by the vendor' : '') +
              ')',
          )
          .join(', ')}
        {mapping.unrecognised_lines
          ? `. ${mapping.unrecognised_lines.toLocaleString()} other lines matched no known format and carry no findings.`
          : '.'}
        <Docs docs={mapping.line_profiles.flatMap((p) => p.docs)} />
      </div>
      {notes}
      </>
    )
  }

  if (mapping.method === 'documented') {
    const guessed = mapping.heuristic_fields || []
    return (
      <>
        <div className={`map-note${guessed.length ? ' map-warn' : ''}`}>
          {label}Columns mapped from the log source's documentation: <strong>{mapping.name}</strong>.
          {guessed.length > 0 && (
            <>
              {' '}
              This export lacks the documented column for {guessed.map((f) => FIELD_EN[f] || f).join(', ')},
              so it was guessed from column names - verify: {fieldList(mapping.fields, guessed)}.
            </>
          )}
          {(mapping.notes || []).map((n) => (
            <div className="map-sub" key={n}>
              {n}
            </div>
          ))}
          <Docs docs={mapping.docs} />
        </div>
        {notes}
      </>
    )
  }

  return (
    <>
      <div className="map-note map-warn">
        {label}
        <strong>Column mapping not based on the log source's documentation.</strong>{' '}
        {mapping.json ? "This file's keys" : "This file's header"} matched no known log source, so its{' '}
        {mapping.json ? 'fields' : 'columns'} were guessed from their names. Verify the mapping before
        relying on the findings: {fieldList(mapping.fields) || 'no column was recognised'}.
      </div>
      {notes}
    </>
  )
}

export default function MappingNote({ manifest }) {
  if (manifest.members?.length) {
    const any = manifest.members.some((m) => m.mapping)
    if (!any) return null
    return (
      <>
        {manifest.members.map((m) => (
          <One key={`${m.name}-${m.row_id_first}`} mapping={m.mapping} name={m.name} />
        ))}
      </>
    )
  }
  return <One mapping={manifest.mapping} />
}
