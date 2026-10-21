/** What a file was identified as (app/services/identify.py) and how its
 *  columns were read (logsources.py): from the log source's own format
 *  documentation, or not at all - nothing is guessed since IAI-92; cases
 *  processed before it can still show a guessed mapping, as a warning.
 *  "Log source" is the product that wrote the log (Sigma's `logsource`),
 *  never "vendor" - one company ships several log sources. */

/** "category: firewall · custom product: paloalto_panos" - the Sigma
 *  logsource values, then the product the taxonomy has no value for. */
function logsourceLabel(found) {
  const sigma = Object.entries(found.sigma || {}).map(([k, v]) => `${k}: ${v}`)
  const parts = sigma.length ? [`Sigma logsource ${sigma.join(', ')}`] : ['no Sigma logsource value']
  if (found.custom) parts.push(`product ${found.custom}`)
  return parts.join(' · ')
}

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

/** How a Windows event log was read (pipeline._ingest_winevents): events
 *  per channel, and - stated, never left out - what could not be read: an
 *  event XML record that does not parse, or .evtx records a chunk header
 *  names that the reader did not return (gotcha #60). */
function WindowsNote({ win, label }) {
  if (!win) return null
  const n = (v) => (v ?? 0).toLocaleString()
  const channels = Object.entries(win.channels || {})
    .map(([c, k]) => `${c === '-' ? 'no channel' : c} ${n(k)}`)
    .join(' · ')
  const bad = win.unreadable || 0
  const chunks = win.unreadable_chunks || 0
  const errors = win.reader_errors || []
  return (
    <div className={`map-note${bad || chunks || errors.length ? ' map-warn' : ''}`}>
      {label}
      {n(win.events)} Windows events read{channels ? ` - ${channels}` : ''}.
      {bad > 0 && (
        <>
          {' '}
          <strong>{n(bad)} {bad === 1 ? 'record' : 'records'} could not be read</strong> - each damaged part is
          kept in the case as a text row that says where it is.
        </>
      )}
      {chunks > 0 && (
        <>
          {' '}
          <strong>{n(chunks)} damaged {chunks === 1 ? 'chunk' : 'chunks'}</strong> with no readable header - how
          many records {chunks === 1 ? 'it' : 'they'} held cannot be known.
        </>
      )}
      {errors.length > 0 && <div className="map-sub">Reader messages: {errors.join(' · ')}</div>}
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

/** The syslog header each line had (decode.decode_line, IAI-34): RFC 5424,
 *  RFC 3164 or an ISO / RFC 3339 timestamp, how many carried a <PRI>, and -
 *  said as a caveat, because it is a guess - how many RFC 3164 timestamps,
 *  which carry no year, were put in the year of the upload. */
function SyslogNote({ syslog, docs, label }) {
  if (!syslog) return null
  const n = (v) => (v ?? 0).toLocaleString()
  const parts = [
    syslog.rfc5424 && `RFC 5424 ${n(syslog.rfc5424)}`,
    syslog.rfc3164 && `RFC 3164 ${n(syslog.rfc3164)}`,
    syslog.iso && `ISO 8601 timestamp ${n(syslog.iso)}`,
  ].filter(Boolean)
  return (
    <div className={`map-note${syslog.year_inferred ? ' map-warn' : ''}`}>
      {label}Syslog header read on {parts.join(' · ')} lines
      {syslog.pri ? ` (${n(syslog.pri)} with a <PRI> priority)` : ''}.
      {syslog.year_inferred > 0 && (
        <>
          {' '}
          <strong>{n(syslog.year_inferred)} timestamps carry no year</strong> (RFC 3164) - the year was
          taken from the upload date, or the year before when that would put them in the future. Check
          the dates against another source before quoting them.
        </>
      )}
      <Docs docs={docs} />
    </div>
  )
}

function One({ mapping, name }) {
  if (!mapping) return null
  const label = name ? <strong>{name}: </strong> : null
  const notes = (
    <>
      {/* How the file itself was read (pipeline._file_notes, IAI-30). */}
      {(mapping.encoding || mapping.read_as) && (
        <div className="map-note">
          {label}
          {mapping.read_as && 'Read as a table: the file name does not say so, but its first line is the header of the log source below. '}
          {mapping.encoding && `Text encoding ${mapping.encoding.toUpperCase()} (from the file's byte order mark).`}
        </div>
      )}
      {mapping.json && <JsonNote stats={mapping.json} label={label} />}
      <WindowsNote win={mapping.windows} label={label} />
      <SyslogNote syslog={mapping.syslog} docs={mapping.syslog_docs} label={label} />
      <CoverageNote cov={mapping.coverage} label={label} />
    </>
  )

  // What the file was identified as before it was read (identify.py, IAI-92).
  const found = mapping.logsource
  const identity = found && found.status !== 'unrecognised' && (
    <div className="map-note">
      {label}Identified as <strong>{found.name}</strong> - {logsourceLabel(found)}.
      <div className="map-sub">
        {found.evidence}. {found.custom ? 'The Sigma logsource taxonomy has no product for this log source, so the product is named here and is not a Sigma value.' : ''}
      </div>
    </div>
  )

  if (mapping.method === 'no_reader') {
    return (
      <>
        {identity}
        <div className="map-note map-warn">
          {label}This tool has no reader for this log source yet. The file is kept as evidence - its
          digest and chain of custody are recorded - and was not analysed.
        </div>
      </>
    )
  }

  if (mapping.method === 'unrecognised') {
    return (
      <>
        <div className="map-note map-warn">
          {label}
          {found
            ? `Not a log format this tool can identify (${found.evidence}). The file is kept as evidence and was not analysed - nothing is guessed from it.`
            : 'No documented log format was recognised in this file. Only timestamps and IP addresses were extracted, so no detection rule can fire on it.'}
        </div>
        {notes}
      </>
    )
  }

  if (mapping.line_profiles) {
    return (
      <>
      {identity}
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
    // Cases processed before IAI-92 may still carry a guessed field.
    const guessed = mapping.heuristic_fields || []
    const missing = mapping.missing_fields || []
    return (
      <>
        {identity}
        <div className={`map-note${guessed.length || missing.length ? ' map-warn' : ''}`}>
          {label}Columns mapped from the log source's documentation: <strong>{mapping.name}</strong>.
          {missing.length > 0 && (
            <>
              {' '}
              This export lacks the documented column for {missing.map((f) => FIELD_EN[f] || f).join(', ')};
              {missing.length === 1 ? ' it is' : ' they are'} left empty - nothing is guessed - and rules that need{' '}
              {missing.length === 1 ? 'it' : 'them'} cannot fire on this file.
            </>
          )}
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
