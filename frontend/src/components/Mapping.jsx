/** How a file's columns were read (app/services/vendors.py): from the
 *  vendor's own documentation, guessed from column names, or not at all.
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

function One({ mapping, name }) {
  if (!mapping) return null
  const label = name ? <strong>{name}: </strong> : null

  if (mapping.method === 'unrecognised') {
    return (
      <div className="map-note map-warn">
        {label}No documented log format was recognised in this file. Only timestamps and IP
        addresses were extracted, so no detection rule can fire on it.
      </div>
    )
  }

  if (mapping.line_profiles) {
    return (
      <div className="map-note">
        {label}Read with documented message formats:{' '}
        {mapping.line_profiles.map((p) => `${p.name} (${p.lines.toLocaleString()} lines)`).join(', ')}
        {mapping.unrecognised_lines
          ? `. ${mapping.unrecognised_lines.toLocaleString()} other lines matched no known format and carry no findings.`
          : '.'}
        <Docs docs={mapping.line_profiles.flatMap((p) => p.docs)} />
      </div>
    )
  }

  if (mapping.method === 'documented') {
    const guessed = mapping.heuristic_fields || []
    return (
      <div className={`map-note${guessed.length ? ' map-warn' : ''}`}>
        {label}Columns mapped from vendor documentation: <strong>{mapping.name}</strong>.
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
    )
  }

  return (
    <div className="map-note map-warn">
      {label}
      <strong>Column mapping not based on vendor documentation.</strong> No known vendor format
      matched this file's header, so its columns were guessed from their names. Verify the mapping
      before relying on the findings: {fieldList(mapping.fields) || 'no column was recognised'}.
    </div>
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
